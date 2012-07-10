#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr
import re

#Inherit from the base ActivePlugin class
class LocalFileInclude(ActivePlugin):

	null_terminator = ["\000",""]
	files = ["etc/passwd", "boot.ini"]
	file_ext = ["txt", "html", "jpg",""]
	
	def GetInstance(self):
		p = LocalFileInclude()
		p.Name = "Local File Include"
		p.Description = "Active Plugin to check for Local File Include/Directory Traversal vulnerabilities"
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
		self.CheckForLocalFileInclude()
		self.scnr.LogTrace()
	
	def CheckForLocalFileInclude(self):
		self.CheckForLocalFileIncludeWithKnownFiles()
		self.CheckForLocalFileIncludeWithDownwardTraversal()
		self.AnalyzeTestResult()
		
	def CheckForLocalFileIncludeWithKnownFiles(self):
		file_exts = []
		self.base_res = self.scnr.BaseResponse
		parts = self.scnr.PreInjectionParameterValue.split(".")
		if len(parts) > 1:
			file_exts.append(parts[len(parts) - 1])
		file_exts.extend(self.file_ext)
		self.scnr.Trace("<i<br>><i<h>>Checking for Local File Include:<i</h>>")
		for file in self.files:
			for nt in self.null_terminator:
				for fe in file_exts:
					if len(nt) == 0 and len(fe) > 0:
						continue#no point in adding a file extension without a null terminator
					payload = "{0}{1}{2}".format("../" * 15, file, nt)
					if len(fe) > 0:
						payload = "{0}.{1}".format(payload, fe)
					self.scnr.RequestTrace("  Injected payload - {0}".format(payload.replace("\000","\\000")))
					res = self.scnr.Inject(payload)
					downloaded_file_info = self.GetDownloadedFileInfo(res, file)
					if len(downloaded_file_info) > 0:
						self.scnr.ResponseTrace("	==> <i<cr>>Response contains contens of {0}<i</cr>>".format(file))
						self.AddToTriggers(payload, downloaded_file_info)
						self.SetConfidence(3)
					else:
						self.scnr.ResponseTrace("	==> No trace of {0}".format(file))
		
	def CheckForLocalFileIncludeWithDownwardTraversal(self):
		#check downward traversal
		#indicates presence of file read function and also a insecure direct object reference in that function
		self.scnr.Trace("<i<br>><i<b>>Checking for Downward Directory Traversal:<i</b>>")
		self.scnr.Trace("<i<br>>Normal Response Code - {0}. Length -{0}".format(self.base_res.Code, self.base_res.BodyLength))
		
		payload_a = "aa/../{0}".format(self.scnr.PreInjectionParameterValue)
		self.scnr.RequestTrace("  Injected payload - {0}".format(payload_a))
		res_a = self.scnr.Inject(payload_a)
		req_a = self.scnr.InjectedRequest
		self.scnr.ResponseTrace("	==> Got Response. Code- {0}. Length- {1}".format(res_a.Code, res_a.BodyLength))
		
		payload_a1 = "aa../{0}".format(self.scnr.PreInjectionParameterValue)
		self.scnr.RequestTrace("  Injected payload - {0}".format(payload_a1))
		res_a1 = self.scnr.Inject(payload_a1)
		req_a1 = self.scnr.InjectedRequest
		self.scnr.ResponseTrace("	==> Got Response. Code- {0}. Length- {1}".format(res_a1.Code, res_a1.BodyLength))
		
		payload_b = "bb/../{0}".format(self.scnr.PreInjectionParameterValue)
		self.scnr.RequestTrace("  Injected payload - {0}".format(payload_b))
		res_b = self.scnr.Inject(payload_b)
		req_b = self.scnr.InjectedRequest
		self.scnr.ResponseTrace("	==> Got Response. Code- {0}. Length- {1}".format(res_b.Code, res_b.BodyLength))
		
		payload_b1 = "bb../{0}".format(self.scnr.PreInjectionParameterValue)
		self.scnr.RequestTrace("  Injected payload - {0}".format(payload_b1))
		res_b1 = self.scnr.Inject(payload_b1)
		req_b1 = self.scnr.InjectedRequest
		self.scnr.ResponseTrace("	==> Got Response. Code- {0}. Length- {1}".format(res_b1.Code, res_b1.BodyLength))
		
		self.scnr.Trace("<i<br>>Analysing the responses for patterns...")
		
		#Analyzing the responses for patterns
		sc = SimilarityChecker()
		sc.Add("a", res_a)
		sc.Add("a1", res_a1)
		sc.Add("b", res_b)
		sc.Add("b1", res_b1)
		sc.Check()
		
		requests = [req_a, req_a1, req_b, req_b1]
		responses = [res_a, res_a1, res_b, res_b1]
		request_triggers = [payload_a, payload_a1, payload_b, payload_b1]
		response_triggers = ["","","",""]
		
		for group in sc.StrictGroups:
			if group.Count == 2:
				if group.HasKey("a") and group.HasKey("b"):
					self.scnr.Trace("<i<br>><i<cr>>Responses for traversal based payloads are similar to each other and are different from non-traversal based responses. Indicates presence of LFI.<i</cr>>")
					self.RequestTriggers.extend(request_triggers)
					self.ResponseTriggers.extend(response_triggers)
					self.TriggerRequests.extend(requests)
					self.TriggerResponses.extend(responses)
					self.SetConfidence(2)
					return
		
		for group in sc.RelaxedGroups:
			if group.Count == 2:
				if group.HasKey("a") and group.HasKey("b"):
					self.scnr.Trace("<i<br>><i<cr>>Responses for traversal based payloads are similar to each other and are different from non-traversal based responses. Indicates presence of LFI.<i</cr>>")
					self.RequestTriggers.extend(request_triggers)
					self.ResponseTriggers.extend(response_triggers)
					self.TriggerRequests.extend(requests)
					self.TriggerResponses.extend(responses)
					self.SetConfidence(1)
					return
		
		self.scnr.Trace("<i<br>>The responses did not fall in any patterns that indicate LFI")
		
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
			
		elif file == "boot.ini":
			bs_c_1 = bs.count("[boot loader]")
			bbs_c_1 = bbs.count("[boot loader]")
			bs_c_2 = bs.count("multi(")
			bbs_c_2 = bbs.count("multi(")
			if bs_c_1 > bbs_c_1 and bs_c_2 > bbs_c_2:
				return "[boot loader]"
			elif bs_c_1 == bbs_c_1 and bs_c_2 == bbs_c_2 and self.scnr.PreInjectionParameterValue.count("boot.ini") > 0:
				return "[boot loader]"
		
		return ""
	
	def SetConfidence(self, conf):
		if conf > self.confidence:
			self.confidence = conf
	
	def AnalyzeTestResult(self):
		if len(self.RequestTriggers) > 0:
			self.ReportLocalFileInclude()
	
	def AddToTriggers(self, RequestTrigger, ResponseTrigger):
		self.RequestTriggers.append(RequestTrigger)
		self.ResponseTriggers.append(ResponseTrigger)
		self.TriggerRequests.append(self.scnr.InjectedRequest.GetClone())
		self.TriggerResponses.append(self.scnr.InjectionResponse.GetClone())
	
	def ReportLocalFileInclude(self):
		self.scnr.SetTraceTitle("Local File Include Found", 10)
		pr = PluginResult(self.scnr.InjectedRequest.Host)
		pr.Title = "Local File Include Found"
		pr.Summary = "Local File Include/Path Traversal been detected in the '{0}' parameter of the {1} section of the request  <i<br>><i<br>><i<hh>>Test Trace:<i</hh>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.scnr.GetTrace())
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

p = LocalFileInclude()
ActivePlugin.Add(p.GetInstance())
