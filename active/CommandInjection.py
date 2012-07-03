
#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr
import re

#Inherit from the base ActivePlugin class
class CommandInjection(ActivePlugin):

	#Check logic based on osCommanding.py of the W3AF project - http://w3af.sourceforge.net/
	seperators = ['', '&&', '|', ';']
	
	#Override the GetInstance method of the base class to return a new instance with details
	def GetInstance(self):
		p = CommandInjection()
		p.Name = "Command Injection"
		p.Description = "Active Plugin to check for OS Command Injection vulnerabilities"
		p.Version = "0.1"
		return p
	
	#Override the Check method of the base class with custom functionlity
	def Check(self, scnr):
		self.scnr = scnr
		self.base_res = self.scnr.BaseResponse
		self.RequestTriggers = []
		self.ResponseTriggers = []
		self.TriggerRequests = []
		self.TriggerResponses = []
		self.scnr.StartTrace()
		self.scnr.SetTraceTitle("-",0)
		self.CheckForCommandInjection()
		self.AnalyzeTestResults()
		self.scnr.LogTrace()
	
	def CheckForCommandInjection(self):
		self.scnr.Trace("<i<br>><i<h>>Checking for Command Injection:<i</h>>")

		#start the checks
		self.prefixes = [""]
		if len(self.scnr.PreInjectionParameterValue) > 0:
			self.prefixes.append(self.scnr.PreInjectionParameterValue)
		self.CheckForEchoBasedCommandInjection()
		self.CheckForTimeBasedCommandInjection()
	
	def CheckForEchoBasedCommandInjection(self):
		
		self.scnr.Trace("<i<br>><i<h>>Checking for Command Injection by Printing File Contents:<i</h>>")
		for prefix in self.prefixes:
			for seperator in self.seperators:
				payload = "{0}{1} /bin/cat /etc/passwd".format(prefix, seperator)
				self.SendAndAnalyzeEchoPayload(payload, "etc/passwd")
				
				payload = "{0}{1} type %SYSTEMROOT%\\win.ini".format(prefix, seperator)
				self.SendAndAnalyzeEchoPayload(payload, "win.ini")
			
			payload = "{0} `/bin/cat /etc/passwd`".format(prefix)
			self.SendAndAnalyzeEchoPayload(payload, "etc/passwd")
			
			payload = "{0} run type %SYSTEMROOT%\\win.ini".format(prefix)
			self.SendAndAnalyzeEchoPayload(payload, "win.ini")
	
	def CheckForTimeBasedCommandInjection(self):
		self.scnr.Trace("<i<br>><i<h>>Checking for Command Injection by Inducing Time Delay:<i</h>>")
		#set the time related values for time-based command injection check
		self.time = 10
		max_delay = 0
		min_delay = -1
		
		self.scnr.Trace("<i<br>>Sending three requests to get a baseline of the response time for time based check:")
		base_line_delays = []
		for i in range(3):
			res = self.scnr.Inject()
			base_line_delays.append("  {0}) Response time is - {1} ms".format(i+1, res.RoundTrip))
			if res.RoundTrip > max_delay:
				max_delay = res.RoundTrip
			if res.RoundTrip < min_delay or min_delay == -1:
				min_delay = res.RoundTrip
		
		self.scnr.Trace("<i<br>>".join(base_line_delays))

		if min_delay > 5000:
			self.time = ((max_delay + min_delay) / 1000) + 1
		else:
			self.time = ((max_delay + 5000) / 1000) + 1

		#buffer to handle the time difference in the ping time and ping number
		self.buffer = 3
		
		self.scnr.Trace("<i<br>>Maximum Response Time - {0}ms. Minimum Response Time - {1}ms.<i<br>>Induced Time Delay will be for {2}ms<i<br>>".format(max_delay, min_delay, (self.time + self.buffer) * 1000))
		
		for prefix in self.prefixes:
			for seperator in self.seperators:
				payload = "{0}{1} ping -n {2} localhost".format(prefix, seperator, self.time + self.buffer)
				self.SendAndAnalyzeTimePayload(payload)
				
				payload = "{0}{1} ping -c {2} localhost".format(prefix, seperator, self.time + self.buffer)
				self.SendAndAnalyzeTimePayload(payload)
				
				payload = "{0}{1} /usr/sbin/ping -s localhost 1000 {2} ".format(prefix, seperator, self.time + self.buffer)
				self.SendAndAnalyzeTimePayload(payload)
				
			payload = "{0} `ping -c {1} localhost`".format(prefix, self.time + self.buffer)
			self.SendAndAnalyzeTimePayload(payload)
			
			payload = "{0} run ping -n {1} localhost".format(prefix, self.time + self.buffer)
			self.SendAndAnalyzeTimePayload(payload)
			
	def SendAndAnalyzeEchoPayload(self, payload, file_echoed):
		self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
		res = self.scnr.Inject(payload)
		echoed_file_info = self.GetDownloadedFileInfo(res, file_echoed)
		if len(echoed_file_info) > 0:
			self.scnr.ResponseTrace("	==> <i<cr>>Response contains contens of {0}<i</cr>>".format(file_echoed))
			self.AddToTriggers(payload, echoed_file_info)
		else:
			self.scnr.ResponseTrace("	==> No trace of {0}".format(file_echoed))
	
	def SendAndAnalyzeTimePayload(self, payload):
		for i in range(2):
			self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
			res = self.scnr.Inject(payload)
			#we reduce the delay by 3 seconds to make up for the the fact that the ping could complete earlier
			if res.RoundTrip >= (self.time - self.buffer) * 1000:
				if i == 0:
					self.scnr.ResponseTrace("	==> <i<b>>Observed a delay of {0}ms, induced delay was for {1}ms. Rechecking the delay by sending the same payload again<i</b>>".format(res.RoundTrip, (self.time + self.buffer) * 1000))
				else:
					self.scnr.ResponseTrace("	==> <i<cr>>Observed a delay of {0}ms, induced delay was for {1}ms. Delay observed twice, indicates Command Injection!!<i</cr>>".format(res.RoundTrip, (self.time + self.buffer) * 1000))
					self.AddToTriggers(payload, "Got a delay of {0}ms. {1}ms delayed was induced by the payload".format(res.RoundTrip, (self.time + self.buffer) * 1000))
			else:
				if i == 0:
					self.scnr.ResponseTrace("	==> Response time was {0}ms. No delay observed.".format(res.RoundTrip))
					return
				else:
					self.scnr.ResponseTrace("	==> Response time was {0}ms. Delay did not reoccur, initial delay could have been due to network issues.".format(res.RoundTrip))

	def GetDownloadedFileInfo(self, res, file):
		bs = res.BodyString.lower()
		bbs = self.base_res.BodyString.lower()
		
		if file == "etc/passwd":	
			bs_c = bs.count("root:x:0:0:")
			bbs_c = bbs.count("root:x:0:0:")
			if bs_c > bbs_c:
				return "root:x:0:0:"
			elif bs_c == bbs_c and self.scnr.PreInjectionParameterValue.count("etc/passwd") > 0:
				return "root:x:0:0:"
			
			bs_c = bs.count("root:!:x:0:0:")
			bbs_c = bbs.count("root:!:x:0:0:")
			if bs_c > bbs_c:
				return "root:!:x:0:0:"
			elif bs_c == bbs_c and self.scnr.PreInjectionParameterValue.count("etc/passwd") > 0:
				return "root:!:x:0:0:"
			
		elif file == "win.ini":
			bs_c = bs.count("[fonts]")
			bbs_c = bbs.count("[fonts]")
			if bs_c > bbs_c:
				return "[fonts]"
			elif bs_c == bbs_c and self.scnr.PreInjectionParameterValue.count("win.ini") > 0:
				return "[fonts]"
		
		return ""
	
	def AddToTriggers(self, RequestTrigger, ResponseTrigger):
		self.RequestTriggers.append(RequestTrigger)
		self.ResponseTriggers.append(ResponseTrigger)
		self.TriggerRequests.append(self.scnr.InjectedRequest.GetClone())
		self.TriggerResponses.append(self.scnr.InjectionResponse.GetClone())
	
	def AnalyzeTestResults(self):
		if len(self.RequestTriggers) > 0:
			self.ReportCommandInjection()
	
	def ReportCommandInjection(self):
		self.scnr.SetTraceTitle("Command Injection Found", 10)
		pr = PluginResult(self.scnr.InjectedRequest.Host)
		pr.Title = "Command Injection Found"
		pr.Summary = "Command Injection has been detected in the '{0}' parameter of the {1} section of the request  <i<br>><i<br>><i<hh>>Test Trace:<i</hh>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.scnr.GetTrace())
		for i in range(len(self.RequestTriggers)):
			pr.Triggers.Add(self.RequestTriggers[i], self.TriggerRequests[i], self.ResponseTriggers[i], self.TriggerResponses[i])
		pr.ResultType = PluginResultType.Vulnerability
		pr.Severity = PluginResultSeverity.High
		pr.Confidence = PluginResultConfidence.High
		self.scnr.AddResult(pr)


p = CommandInjection()
ActivePlugin.Add(p.GetInstance())
