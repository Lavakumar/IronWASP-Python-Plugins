#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr

#Inherit from the base ActivePlugin class
class XPATHInjection(ActivePlugin):

	error_strings = []
	
	def GetInstance(self):
		p = XPATHInjection()
		p.Name = "XPATH Injection"
		p.Description = "Active plugin that checks for XPATH Injection"
		p.Version = "0.1"
		return p
	
	#Override the Check method of the base class with custom functionlity
	def Check(self, scnr):
		self.scnr = scnr
		self.scnr.StartTrace()
		self.scnr.SetTraceTitle("-",0)
		self.CheckForXPATHInjection()
		self.scnr.LogTrace()

	
	def CheckForXPATHInjection(self):
		self.scnr.Trace("<i<br>><i<h>>Checking for XPATH Injection:<i</h>>")

		payload = "<!--'\"a"
		self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
		res = self.scnr.Inject(payload)
		errors_found = []
		for error in self.error_strings:
			if res.BodyString.count(error) > 0:
				errors_found.append(error)
		if len(errors_found) > 0:
			self.scnr.ResponseTrace("	==> <i<cr>>XPATH Injection Found.<i<br>>Errors:<i<br>>{0}<i</cr>>".format("<i<br>>".join(errors_found)))
			self.ReportXPATHInjection(payload, "\r\n".join(errors_found))
		else:
			self.scnr.ResponseTrace("	==> No Errors Found")
	
	def ReportXPATHInjection(self, req_trigger, res_trigger):
		self.scnr.SetTraceTitle("XPATH Injection Found", 10)
		pr = PluginResult(self.scnr.InjectedRequest.Host)
		pr.Title = "XPATH Injection Found"
		pr.Summary = "XPATH Injection has been detected in the '{0}' parameter of the {1} section of the request  <i<br>><i<br>><i<hh>>Test Trace:<i</hh>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.scnr.GetTrace())
		pr.Triggers.Add(req_trigger, self.scnr.InjectedRequest, res_trigger, self.scnr.InjectionResponse)
		pr.ResultType = PluginResultType.Vulnerability
		pr.Severity = PluginResultSeverity.High
		pr.Confidence = PluginResultConfidence.High
		self.scnr.AddResult(pr)
		
	def SetUp(self):
		err_str_file = open(Config.Path + "\\plugins\\active\\xpath_error_strings.txt")
		err_str_file.readline()#Ignore the first line containing comments
		error_strings_raw = err_str_file.readlines()
		err_str_file.close()
		for err_str in error_strings_raw:
			err_str = err_str.strip()
			if len(err_str) > 0:
				self.error_strings.append(err_str)

p = XPATHInjection()
p.SetUp()
ActivePlugin.Add(p.GetInstance())
