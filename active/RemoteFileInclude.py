#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr
import re

#Inherit from the base ActivePlugin class
class RemoteFileInclude(ActivePlugin):

	prefixes = ["", "http://", "https://"]
	suffixes = ["", "/", "/a"]
	
	def GetInstance(self):
		p = RemoteFileInclude()
		p.Name = "Remote File Include"
		p.Description = "Active Plugin to check for Remote File Include vulnerabilities"
		p.Version = "0.2"
		return p
	
	#Override the Check method of the base class with custom functionlity
	def Check(self, scnr):
		self.scnr = scnr
		self.confidence = 0
		self.RequestTriggers = []
		self.ResponseTriggers = []
		self.TriggerRequests = []
		self.TriggerResponses = []
		self.scnr.StartTrace()
		self.scnr.SetTraceTitle("-",0)
		self.CheckForRemoteFileInclude()
		self.scnr.LogTrace()
	
	def CheckForRemoteFileInclude(self):
		self.scnr.Trace("<i<br>><i<h>>Checking for Remote File Include:<i</h>>")
		self.CheckForEchoBasedRemoteFileInclude()
		self.CheckForTimeBasedRemoteFileInclude()
		self.AnalyzeTestResult()
		
	def CheckForEchoBasedRemoteFileInclude(self):
		self.scnr.Trace("<i<br>><i<h>>Checking for Remote File Include with Echo:<i</h>>")
		for p in self.prefixes:
			for s in self.suffixes:
				payload = "{0}example.org{1}".format(p, s)
				self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
				res = self.scnr.Inject(payload)
				if res.BodyString.count("we maintain a number of domains such as EXAMPLE.COM and EXAMPLE.ORG") > 0:
					self.AddToTriggers(payload, "we maintain a number of domains such as EXAMPLE.COM and EXAMPLE.ORG")
					self.scnr.ResponseTrace("	==> <i<cr>>Response includes content from http://www.iana.org/domains/example/. Indicates RFI<i</cr>>")
					self.SetConfidence(3)
				else:
					self.scnr.ResponseTrace("	==> Response does not seem to contain content from http://www.iana.org/domains/example/.")
	
	def CheckForTimeBasedRemoteFileInclude(self):
		self.scnr.Trace("<i<br>><i<h>>Checking for Remote File Include with Time Delay:<i</h>>")
		self.IsResponseTimeConsistent = True
		for p in self.prefixes:
			for s in self.suffixes:
				sd = self.GetUniqueSubdomain()
				payload = "{0}<sub_domain>.example.org{1}".format(p, s)
				if self.IsResponseTimeConsistent:
					self.CheckForRemoteFileIncludeWithSubDomainDelay(payload)
				else:
					break
	
	def CheckForRemoteFileIncludeWithSubDomainDelay(self, payload_raw):
		worked = 0
		for ii in range(4):
			if worked == 2:
				self.SetConfidence(1)
				return
			payload = payload_raw.replace("<sub_domain>", str(self.GetUniqueSubdomain()))
			first_time = 0
			last_res_time = 0
			for i in range(7):
				if i == 0:
					self.scnr.Trace("<i<br>><i<b>>Sending First Request with Payload - {0}:<i</b>>".format(payload))
				self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
				res = self.scnr.Inject(payload)
				if i==0:
					req_current = self.scnr.InjectedRequest
					res_current = res
					first_time = res.RoundTrip
					self.scnr.ResponseTrace("	==> Response time is {0}ms. This will be treated as the base time.".format(res.RoundTrip))
				else:
					if i == 2:
						last_res_time = res.RoundTrip
					else:
						if res.RoundTrip > (last_res_time + 150) or res.RoundTrip < (last_res_time - 150):
							self.IsResponseTimeConsistent = False
							self.scnr.Trace("<i<br>><i<b>>Response times are inconsistent, terminating time based RFI check.<i</b>>")
							return
					if res.RoundTrip >= first_time - 300:
						self.scnr.ResponseTrace("	==> Response time is {0}ms which is not less than base time - 300ms. Not an indication of RFI".format(res.RoundTrip))
						break
					else:
						self.scnr.ResponseTrace("	==> Response time is {0}ms which is less than base time - 300ms. If this is repeated then it could mean RFI".format(res.RoundTrip))
				if i == 6:
					worked = worked + 1
					self.scnr.SetTraceTitle("RFI Time Delay Observed Once", 5)
					if worked == 2:
						self.RequestTriggers.append(payload)
						self.ResponseTriggers.append("")
						self.TriggerRequests.append(req_current)
						self.TriggerResponses.append(res_current)
						self.scnr.Trace("<i<br>><i<cr>>Got a delay in first request with payload - {0}. The three requests after that with the same payload took 300ms less. Infering that this is due to DNS caching on the server-side this is a RFI!<i</cr>>".format(payload))
									
	def GetUniqueSubdomain(self):
		sd = "{0}r{1}".format(str(self.scnr.ID), Tools.GetRandomNumber(1, 10000))
		return sd
	
	def SetConfidence(self, conf):
		if conf > self.confidence:
			self.confidence = conf
	
	def AnalyzeTestResult(self):
		if len(self.RequestTriggers) > 0:
			self.ReportRemoteFileInclude()
	
	def AddToTriggers(self, RequestTrigger, ResponseTrigger):
		self.RequestTriggers.append(RequestTrigger)
		self.ResponseTriggers.append(ResponseTrigger)
		self.TriggerRequests.append(self.scnr.InjectedRequest.GetClone())
		self.TriggerResponses.append(self.scnr.InjectionResponse.GetClone())
	
	def ReportRemoteFileInclude(self):
		pr = PluginResult(self.scnr.InjectedRequest.Host)
		pr.Title = "Remote File Include Found"
		pr.Summary = "Remote File Include been detected in the '{0}' parameter of the {1} section of the request.<i<br>>This was tested by injecting a payload with a unique domain name, then time taken to fetch the response is noted. If subsequent requests with the same payload return quicker then it is inferred that DNS cachcing of the domain name in the payload by the server has sped up the response times.<i<br>><i<br>><i<hh>>Test Trace:<i</hh>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.scnr.GetTrace())
		for i in range(len(self.RequestTriggers)):
			pr.Triggers.Add(self.RequestTriggers[i], self.TriggerRequests[i], self.ResponseTriggers[i], self.TriggerResponses[i])
		pr.ResultType = PluginResultType.Vulnerability
		pr.Severity = PluginResultSeverity.High
		if self.confidence == 3:
			pr.Confidence = PluginResultConfidence.High
		elif self.confidence == 2:
			pr.Confidence = PluginResultConfidence.Medium
		else:
			pr.Confidence = PluginResultConfidence.Low
		self.scnr.AddResult(pr)
		self.scnr.SetTraceTitle("Remote File Include",10)

p = RemoteFileInclude()
ActivePlugin.Add(p.GetInstance())
