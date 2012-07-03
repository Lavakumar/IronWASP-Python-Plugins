#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr

#Inherit from the base ActivePlugin class
class HeaderInjection(ActivePlugin):

	crlf_inj_str = ["\r\nNeww: Headerr", "aa\r\nNeww: Headerr", "\r\nNeww: Headerr\r\n", "aa\r\nNeww: Headerr\r\n"]
	
	def GetInstance(self):
		p = HeaderInjection()
		p.Name = "Header Injection"
		p.Description = "Active plugin that checks for HTTP Header Injection by inserting CR LF characters"
		p.Version = "0.1"
		return p
	
	#Override the Check method of the base class with custom functionlity
	def Check(self, scnr):
		self.scnr = scnr
		self.scnr.StartTrace()
		self.scnr.SetTraceTitle("-",0)
		self.CheckForCRLFInjection()
		self.scnr.LogTrace()

	
	def CheckForCRLFInjection(self):
		self.scnr.Trace("<i<br>><i<h>>Checking for Header Injection:<i</h>>")
		self.scnr.Trace("<i<br>><i<b>>  Trying to inject a header named 'Neww'<i</b>>")
		crlf_inj_found = False
		prefix = ["", self.scnr.PreInjectionParameterValue]
		for cis in self.crlf_inj_str:
			if 	crlf_inj_found:
				break
			for p in prefix:
				self.scnr.RequestTrace("  Injected payload - {0}".format(p + cis.replace("\r\n", "\\r\\n")))
				res = self.scnr.Inject(p + cis)
				if(res.Headers.Has("Neww")):
					self.scnr.ResponseTrace("	==> <i<cr>>Header 'Neww' injected<i</cr>>")
					self.ReportCRLFInjection(cis.replace("\r\n", "\\r\\n"), cis.replace("\r\n", "\\r\\n"))
					crlf_inj_found = True
					break
				else:
					self.scnr.ResponseTrace("	==> Header not injected")
	
	def ReportCRLFInjection(self, req_trigger, res_trigger):
		self.scnr.SetTraceTitle("Header Injection Found", 10)
		pr = PluginResult(self.scnr.InjectedRequest.Host)
		pr.Title = "Header Injection Found"
		pr.Summary = "Header Injection has been detected in the '{0}' parameter of the {1} section of the request  <i<br>><i<br>><i<hh>>Test Trace:<i</hh>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.scnr.GetTrace())
		pr.Triggers.Add(req_trigger, self.scnr.InjectedRequest, res_trigger, self.scnr.InjectionResponse)
		pr.ResultType = PluginResultType.Vulnerability
		pr.Severity = PluginResultSeverity.High
		pr.Confidence = PluginResultConfidence.High
		self.scnr.AddResult(pr)

p = HeaderInjection()
ActivePlugin.Add(p.GetInstance())
