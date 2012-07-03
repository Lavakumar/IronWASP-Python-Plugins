#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr
import re

#Inherit from the base ActivePlugin class
class CodeInjection(ActivePlugin):

	def GetInstance(self):
		p = CodeInjection()
		p.Name = "Code Injection"
		p.Description = "Active Plugin to check for CodeInjection vulnerability"
		p.Version = "0.1"
		return p
	
	#Check logic based on https://github.com/Zapotek/arachni/blob/master/modules/audit/code_injection.rb of the Arachni project
	#Override the Check method of the base class with custom functionlity
	def Check(self, scnr):
		self.scnr = scnr
		self.RequestTriggers = []
		self.ResponseTriggers = []
		self.TriggerRequests = []
		self.TriggerResponses = []
		self.scnr.StartTrace()
		self.scnr.SetTraceTitle("-",0)
		self.CheckForCodeInjection()
		self.scnr.LogTrace()
	
	def CheckForCodeInjection(self):
		self.scnr.Trace("<i<br>><i<h>>Checking for Code Injection:<i</h>>")
		self.CheckForEchoBasedCodeInjection()
		self.CheckForTimeBasedCodeInjection()
		self.AnalyzeTestResult()
	
	def CheckForEchoBasedCodeInjection(self):
		#lang_order [php, perl, pyton, asp, ruby]
		functions = ['echo <add_str>;', 'print <add_str>;', 'print <add_str>', 'Response.Write(<add_str>)', "puts <add_str>"]
		comments = ["#", "#", "#", "'", "#"]
		prefixes = ["", "';", '";']
		
		add_num_1 = 0
		add_num_2 = 0
		base_res = self.scnr.BaseResponse
		found_rand_nums = False
		while(not found_rand_nums):
			add_num_1 = Tools.GetRandomNumber(1000000, 10000000)
			add_num_2 = Tools.GetRandomNumber(1000000, 10000000)
			if base_res.BodyString.count(str(add_num_1 + add_num_2)) == 0:
				found_rand_nums = True
		
		add_str = "{0}+{1}".format(str(add_num_1), str(add_num_2))
		added_str = str(add_num_1 + add_num_2)
		
		self.scnr.Trace("<i<br>><i<h>>Checking for Echo based Code Injection:<i</h>>")
		for i in range(len(functions)):
			for p in prefixes:
				inj_comments = ["", comments[i]]
				for c in inj_comments:
					payload = "{0}{1}{2}".format(p, functions[i].replace("<add_str>", add_str), c)
					self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
					res = self.scnr.Inject(payload)
					if res.BodyString.count(added_str) > 0:
						self.scnr.ResponseTrace("	==> <i<cr>>Got {0} in the response, this is the result of executing '{1}'. Indicates Code Injection!<i</cr>>".format(added_str, add_str))
						self.scnr.SetTraceTitle("Echo based Code Injection", 5)
						self.AddToTriggers(payload, added_str)
						return
					else:
						self.scnr.ResponseTrace("	==> Did not get {0} in the response".format(added_str))
	
	def CheckForTimeBasedCodeInjection(self):
		self.scnr.Trace("<i<br>><i<h>>Checking for Time based Code Injection:<i</h>>")
		#set the time related values for time-based code injection check
		self.time = 0
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

		self.scnr.Trace("<i<br>>Maximum Response Time: {0}ms. Minimum Response Time: {1}ms<i<br>>Induced Time Delay will be for {2}ms<i<br>>".format(max_delay, min_delay, self.time * 1000))
		
		functions = ['sleep(<seconds>);', 'import time;time.sleep(<seconds>);']
		prefixes = ["", "';", '";']
		comments = ["", "#"]
		for f in functions:
			for p in prefixes:
				for c in comments:
					payload = "{0}{1}{2}".format(p, f.replace("<seconds>",str(self.time)), c)
					self.SendAndAnalyzeTimePayload(payload)
	
	def SendAndAnalyzeTimePayload(self, payload):
		for i in range(2):
			self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
			res = self.scnr.Inject(payload)
			#we reduce the delay by 3 seconds to make up for the the fact that the ping could complete earlier
			if res.RoundTrip >= self.time * 1000:
				if i == 0:
					self.scnr.ResponseTrace("	==> <i<b>>Observed a delay of {0}ms, induced delay was for {1}ms. Rechecking the delay by sending the same payload again<i</b>>".format(res.RoundTrip, self.time * 1000))
				else:
					self.scnr.ResponseTrace("	==> <i<cr>>Observed a delay of {0}ms, induced delay was for {1}ms. Delay observed twice, indicates Code Injection!!<i</cr>>".format(res.RoundTrip, self.time * 1000))
					self.AddToTriggers(payload, "Got a delay of {0}ms. {1}ms delayed was induced by the payload".format(res.RoundTrip, self.time * 1000))
			else:
				if i == 0:
					self.scnr.ResponseTrace("	==> Response time was {0}ms. No delay observed.".format(res.RoundTrip))
					return
				else:
					self.scnr.ResponseTrace("	==> Response time was {0}ms. Delay did not reoccur, initial delay could have been due to network issues.".format(res.RoundTrip))
	
	def AddToTriggers(self, RequestTrigger, ResponseTrigger):
		self.RequestTriggers.append(RequestTrigger)
		self.ResponseTriggers.append(ResponseTrigger)
		self.TriggerRequests.append(self.scnr.InjectedRequest.GetClone())
		self.TriggerResponses.append(self.scnr.InjectionResponse.GetClone())
	
	def AnalyzeTestResult(self):
		if len(self.RequestTriggers) == 1:
			self.ReportCodeInjection(PluginResultConfidence.Medium)
		elif len(self.RequestTriggers) > 1:
			self.ReportCodeInjection(PluginResultConfidence.High)
	
	def ReportCodeInjection(self, confidence):
		self.scnr.SetTraceTitle("Code Injection Found", 10)
		pr = PluginResult(self.scnr.InjectedRequest.Host)
		pr.Title = "Code Injection Found"
		pr.Summary = "Code Injection been detected in the '{0}' parameter of the {1} section of the request  <i<br>><i<br>><i<hh>>Test Trace:<i</hh>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.scnr.GetTrace())
		for i in range(len(self.RequestTriggers)):
			pr.Triggers.Add(self.RequestTriggers[i], self.TriggerRequests[i], self.ResponseTriggers[i], self.TriggerResponses[i])
		pr.ResultType = PluginResultType.Vulnerability
		pr.Severity = PluginResultSeverity.High
		pr.Confidence = confidence
		self.scnr.AddResult(pr)


p = CodeInjection()
ActivePlugin.Add(p.GetInstance())
