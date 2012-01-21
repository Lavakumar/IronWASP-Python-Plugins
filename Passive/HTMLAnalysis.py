#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *

class HTMLAnalysis(PassivePlugin):
    
	def Check(self, Sess, Results):
		
		if(Sess.Response.IsBinary):
			return
		
		if(not Sess.Response.IsHtml):
			return
	
		ThreadStore.Put("Session", Sess)
		ThreadStore.Put("Results", Results)
		
		Req = Sess.Request
		Res = Sess.Response
		
		script_srcs = Sess.Response.Html.GetValues("script","src")
		for src in script_srcs:
			try:
				src_req = Request(src)
				if(self.IsForiegnDomain(Req, src_req)):
					self.ReportScriptFromExternalDomain()
					Title = "Scripts loaded from External Domains"
					Summary = "Script has been loaded in the page from "+ src_req.Host + " which is an external domain that might not be trustworthy"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportTestLead(Title, Summary,"","",Signature)
				if(Req.SSL and not src_req.SSL):
					Title = "Insecure Scripts loaded inside Secure Page"
					Summary = "Page loaded over SSL includes script that is loaded over HTTP, this compromises the integrity of the SSL layer"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportVulnerability(Title, Summary,"",src_req.FullUrl,PluginResultConfidence.High, PluginResultSeverity.Medium, Signature)
				elif(src_req.SSL and not Req.SSL):
					Title = "Secure Script loaded inside Insecure Page"
					Summary = "Page loaded over HTTP includes script that is loaded over SSL, this compromises the integrity of the script"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportTestLead(Title, Summary,"","",Signature)
			except:
				pass
			
		css_srcs = Sess.Response.Html.GetValues("style","src")
		for src in css_srcs:
			try:
				src_req = Request(src)
				if(self.IsForiegnDomain(Req, src_req)):
					Title = "CSS loaded from External Domains"
					Summary = "CSS document has been loaded in the page from "+ src_req.Host + " which is an external domain that might not be trustworthy"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportTestLead(Title, Summary,"","",Signature)
				if(Req.SSL and not src_req.SSL):
					Title = "Insecure CSS loaded inside Secure Page"
					Summary = "Page loaded over SSL includes CSS that is loaded over HTTP, this compromises the integrity of the SSL layer"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportVulnerability(Title, Summary,"",src_req.FullUrl,PluginResultConfidence.High, PluginResultSeverity.Medium, Signature)
			except:
				pass
		
		iframe_srcs = Sess.Response.Html.GetValues("iframe","src")
		for src in iframe_srcs:
			try:
				src_req = Request(src)
				if(self.IsForiegnDomain(Req, src_req)):
					Title = "IFRAME loaded from External Domains"
					Summary = "IFRAME has been loaded in the page from "+ src_req.Host + " which is an external domain that might not be trustworthy"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportTestLead(Title, Summary,"","",Signature)
				if(Req.SSL and not src_req.SSL):
					Title = "Insecure IFRAMEs loaded inside Secure Page"
					Summary = "Page loaded over SSL includes IFRAME that is loaded over HTTP, this compromises the integrity of the SSL layer"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportVulnerability(Title, Summary,"",src_req.FullUrl,PluginResultConfidence.High, PluginResultSeverity.Medium, Signature)
				elif(src_req.SSL and not Req.SSL):
					Title = "Secure IFRAME loaded inside Insecure Page"
					Summary = "Page loaded over HTTP includes script that is loaded over SSL, this compromises the integrity of the IFRAME"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportTestLead(Title, Summary,"","",Signature)
			except:
				pass
		
		forms = Sess.Response.Html.GetForms()
		#form_actions = Sess.Response.Html.GetValues("form","src")
		for form in forms:
			src = self.GetFormAction(form)
			try:
				src_req = Request(src)
				if(self.IsForiegnDomain(Req, src_req)):
					Title = "Form contents submitted to External Domains"
					Summary = "Form contents in the page are submitted to "+ src_req.Host + " which is an external domain that might not be trustworthy"
					Signature = self.MakeSignature(Title, src_req.UrlPath)
					self.ReportTestLead(Title, Summary,"",form.OuterHtml,Signature)
				if(Req.SSL and not src_req.SSL):
					if(self.IsSensitiveForm(form)):
						Title = "Secure Page submits Sensitive Form contents to InSecure Page"
						Summary = "Form contained inside page loaded over SSL submits its contents, which includes password fields, to another page over HTTP"
						Signature = self.MakeSignature(Title, src_req.UrlPath)
						self.ReportVulnerability(Title, Summary,"",form.OuterHtml,PluginResultConfidence.High, PluginResultSeverity.Medium, Signature)
					else:
						Title = "Secure Page submits Form contents to InSecure Page"
						Summary = "Form contained inside page loaded over SSL submits its contents to another page over HTTP"
						Signature = self.MakeSignature(Title, src_req.UrlPath)
						self.ReportVulnerability(Title, Summary,"",form.OuterHtml,PluginResultConfidence.High, PluginResultSeverity.Low, Signature)
				elif(src_req.SSL and not Req.SSL):
					if(self.IsSensitiveForm(form)):
						Title = "Secure Form with Sensitive contents loaded over InSecure Page"
						Summary = "Form contained inside page loaded over HTTP submits its contents, which includes password fields, to another page over HTTPS. Loading the form over HTTP compromises the SSL security required for this form submission."
						Signature = self.MakeSignature(Title, src_req.UrlPath)
						self.ReportVulnerability(Title, Summary,"",form.OuterHtml,PluginResultConfidence.High, PluginResultSeverity.Medium, Signature)
					else:
						Title = "Secure Form loaded over InSecure Page"
						Summary = "Form contained inside page loaded over HTTP submits its contents to another page over HTTPS. Loading the form over HTTP compromises the SSL security required for this form submission."
						Signature = self.MakeSignature(Title, src_req.UrlPath)
						self.ReportVulnerability(Title, Summary,"",form.OuterHtml,PluginResultConfidence.High, PluginResultSeverity.Low, Signature)
			except:
				if(self.IsSensitiveForm(form) and not Req.SSL):
					Title = "Sensitive Form loaded and submitted Insecurely"
					Summary = "Form with sensitive contents, which includes password fields, is loaded and submitted over HTTP"
					Signature = self.MakeSignature(Title, Req.UrlPath)
					self.ReportVulnerability(Title, Summary,"",form.OuterHtml,PluginResultConfidence.High, PluginResultSeverity.Medium, Signature)
		
	def IsSensitiveForm(self, form):
		AutoComplete = True
		form_attrs = ""
		for attr in form.Attributes:
			form_attrs = form_attrs + attr.Name + "|"
			attr_name = attr.Name.lower()
			if attr_name == "id" or attr_name == "class":
				form_attrs = form_attrs + attr.Value + "|"
			if(attr_name == "autocomplete"):
				if(attr.Value.lower() == "off"):
					AutoComplete = False
		form_fields = ""
		
		for child_node in form.ChildNodes:
			if(child_node.Name.lower() == "input"):
				Sensitive = False
				
				pwd_field = False
				field_autocomplete = True
				
				for attr in child_node.Attributes:
					attr_name = attr.Name.lower()
					if attr_name == "name":
						form_fields = form_fields + attr_name + "|"
					if(attr_name == "type" and attr.Value.lower() == "password"):
						Sensitive = True
						pwd_field = True
					if attr_name == "autocomplete" and attr.Value.lower() == "off" :
						field_autocomplete = False
				if (Sensitive and AutoComplete) or (pwd_field and field_autocomplete):
					Title = "AutoComplete Enabled on Password Fields"
					Summary = "AutoComplete feature has not been disabled on the form/fields that accept Passwords from users"
					Signature = self.MakeSignature(Title, form_attrs)
					self.ReportVulnerability(Title, Summary,"","",PluginResultConfidence.High, PluginResultSeverity.Low, Signature)
					return True
		return False
	
	def GetFormAction(self, form):
		for attr in form.Attributes:
			if(attr.Name.lower() == "action"):
				return attr.Value 
		return ""
	
	def IsForiegnDomain(self, ReqOne, ReqTwo):
		reqone_host_parts = ReqOne.Host.Split(".")
		reqtwo_host_parts = ReqTwo.Host.Split(".")
		
		if((self.IsIP(ReqOne.Host) or self.IsIP(ReqTwo.Host)) or (len(reqone_host_parts) < 1 or len(reqtwo_host_parts) < 1)):
			if(ReqOne.Host == ReqTwo.Host):
				return False
			else:
				return True
		
		if((reqone_host_parts[0] == reqtwo_host_parts[0]) and (reqone_host_parts[1] == reqtwo_host_parts[1])):
			return False
		else:
			return True
	
	def IsIP(self, Input):
		vals = Input.split(".")
		if(len(vals) != 4):
			return False
		int_vals = []
		for val in vals:
			try:
				int_val = int(val)
				int_vals.append(int_val)
			except:
				return False
		if(int_vals[0] < 1 or int_vals[0] > 222):
			return False
		for i in range(1,4):
			if(int_vals[i] < 0 or int_vals[i] > 255):
				return False
		return True
		
		
	def ReportVulnerability(self, Title, Summary, RequestTrigger, ResponseTrigger, Confidence, Severity, Signature):
		Results = ThreadStore.Get("Results")
		Sess = ThreadStore.Get("Session")
		PR = PluginResult(Sess.Request.Host)
		PR.Title = Title
		PR.Summary = Summary
		PR.Triggers.Add(RequestTrigger, Sess.Request, ResponseTrigger, Sess.Response)
		PR.Signature = Signature
		PR.Confidence = Confidence
		PR.Severity = Severity
		Results.Add(PR)
		
	def ReportTestLead(self, Title, Summary, RequestTrigger, ResponseTrigger, Signature):
		Results = ThreadStore.Get("Results")
		Sess = ThreadStore.Get("Session")
		PR = PluginResult(Sess.Request.Host)
		PR.Title = Title
		PR.Summary = Summary
		PR.Triggers.Add(RequestTrigger, Sess.Request, ResponseTrigger, Sess.Response)
		PR.Signature = Signature
		PR.ResultType = PluginResultType.TestLead
		Results.Add(PR)

	def MakeSignature(self, Title, VulnSignature):
		Sess =  ThreadStore.Get("Session")
		Signature = 'HTMLAnalysis{0}|{1}|{2}|{3}|{4}:'.format(Sess.Request.Host, Sess.Request.SSL.ToString(), Sess.Request.UrlPath, Title, VulnSignature)
		return Signature


p = HTMLAnalysis()
p.Name = "HTML Analysis"
p.Description = "Passive plugin to analyze the Response HTML for potential vulnerabilities"
p.FileName = "HTMLAnalysis.py"
p.WorksOn = PluginWorksOn.Response
PassivePlugin.Add(p)
