#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr

class CrossSiteScripting(ActivePlugin):
    
	def Check(self, Req, Scnr):
		ThreadStore.Put("Scanner",Scnr)
		self.SetUpThreadVariables()
		Scnr.StartTrace()
		#Send a Random string for analysing injection nature
		#ps = self.GetProbeString()
		ps = Analyzer.GetProbeString()
		
		ThreadStore.Put("ps",ps)
		
		Scnr.Trace("<i<br>><i<h>>Checking Reflection Contexts with a Probe String:\n<i</h>>")
		Scnr.RequestTrace("  Injected Probe String - " + ps)
		
		ps_res = Scnr.Inject(ps)
		ps_req = Scnr.InjectedRequest
		#Store the ProbeString in Analyzer for Stored XSS Reflection Checking
		Analyzer.AddProbeString(ps, Scnr.InjectedRequest)
		
		ThreadStore.Put("ps_req",ps_req)
		ThreadStore.Put("ps_res",ps_res)
		res_details = "		|| Code - " + str(ps_res.Code) + " | Length - " + str(ps_res.BodyLength)
		if(ps_res.BodyString.Contains(ps)):
			ps_contexts = self.GetContext(ps, ps_res)
			ps_contexts = list(set(ps_contexts))#make the array unique
		else:
			ps_contexts = []
		ThreadStore.Put("ps_contexts",ps_contexts)
		ps_contexts_string = ""
		if(len(ps_contexts) == 0):
			ps_contexts_string = "<i<cg>>No reflection<i</cg>>"
		else:
			ps_contexts_string = "<i<cr>>" + ",".join(ps_contexts) + "<i</cr>>"
		Scnr.ResponseTrace(" ==> Reflection contexts - " + ps_contexts_string + res_details)
		
		#Inject an additional parameter in the URL once for this request and analyse it
		if(not ThreadStore.Has("url_extra_inj")):
			self.DoUrlExtraInjection()
		elif(not ThreadStore.Get("url_extra_inj")):
			self.DoUrlExtraInjection()
					
		#Do Context specific checks
		for context in ps_contexts:
			if(context == "JS"):
				self.CheckForInjectionInFullJS()
			if(context == "InLineJS" or context == "EventAttribute"):
				self.CheckForInjectionInJSInsideHTML()
			elif(context == "UrlAttribute"):
				self.CheckForInjectionInUrlAttribute()
			elif(context == "CSS" or context == "InLineCSS"):
				self.CheckForInjectionInCSS()
			elif(context == "AttributeName"):
				self.CheckForInjectionInAttributeName()
			elif(context == "AttributeValueWithSingleQuote"):
				self.CheckForInjectionInSingleQuoteAttributeValue()
			elif(context == "AttributeValueWithDoubleQuote"):
				self.CheckForInjectionInDoubleQuoteAttributeValue()
			elif(context == "Comment"):
				self.CheckForInjectionInComment()
		
		#Do a HTML Injection Check irrespective of the context
		self.CheckForInjectionInHtml()
		
		#Scan is complete, analyse the results
		self.AnalyseResults()
	
	
	def DoUrlExtraInjection(self):
		ThreadStore.Put("url_extra_inj", True)
	
	def CheckForInjectionInHtml(self):
		#Get required variables from ThreadStore
		Scnr = ThreadStore.Get("Scanner")
		
		#Start the test
		Scnr.Trace("<i<br>><i<h>>Checking HTML Injection in HTML Context:\n<i</h>>")
		Scnr.RequestTrace("  Injected <h1>hxytp</h1> - ")
		
		html_res = Scnr.Inject("<h1>hxytp</h1>")
		
		res_details = "		|| Code - " + str(html_res.Code) + " | Length - " + str(html_res.BodyLength)
		self.CheckResponseDetails(html_res)
		
		if(html_res.BodyString.Contains("<h1>hxytp</h1>")):
			html_inj_contexts = self.GetContext("<h1>hxytp</h1>", html_res)
			if(html_inj_contexts.Contains("Html")):
				Scnr.ResponseTrace("<i<cr>>Got <h1>hxytp</h1> in HTML context<i</cr>>\n" + res_details)
				self.AddToTriggers("<h1>hxytp</h1>","<h1>hxytp</h1>")
				self.SetConfidence(3)
				#self.ReportXSS("<h1>hxytp</h1>", "<h1>hxytp</h1>", PluginResultConfidence.High)
			elif(html_inj_contexts.Contains("Unknown")):
				Scnr.ResponseTrace("<i<cr>>Got <h1>hxytp</h1> in Unknown context<i</cr>>\n" + res_details)
				self.AddToTriggers("<h1>hxytp</h1>","<h1>hxytp</h1>")
				self.SetConfidence(2)
			else:
				Scnr.ResponseTrace("Got <h1>hxytp</h1> in non-HTML context\n")
				self.CheckForContextEscapeInjectionInHtml()
		elif(html_res.BodyString.Contains("<h1>hxytp")):
			html_inj_contexts = self.GetContext("<h1>hxytp", html_res)
			if(html_inj_contexts.Contains("Html")):
				Scnr.ResponseTrace("<i<cr>>Got <h1>hxytp in HTML context<i</cr>>\n" + res_details)
				self.AddToTriggers("<h1>hxytp</h1>","<h1>hxytp")
				self.SetConfidence(3)
				#self.ReportXSS("<h1>hxytp</h1>", "<h1>hxytp", PluginResultConfidence.High)
			elif(html_inj_contexts.Contains("Unknown")):
				Scnr.ResponseTrace("<i<cr>>Got <h1>hxytp in Unknown context<i</cr>>\n" + res_details)
				self.AddToTriggers("<h1>hxytp</h1>","<h1>hxytp")
				self.SetConfidence(2)
			else:
				Scnr.ResponseTrace("Got <h1>hxytp in non-HTML context\n" + res_details)
				self.CheckForContextEscapeInjectionInHtml()
		else:
			#must check for the encoding here
			Scnr.ResponseTrace("No reflection" + res_details)
			self.CheckForContextEscapeInjectionInHtml()
	
	def CheckForContextEscapeInjectionInHtml(self):
		#Get required variables from ThreadStore
		Scnr = ThreadStore.Get("Scanner")
		
		#Start the test
		Scnr.Trace("<i<br>><i<h>>Checking HTML Injection by escaping in to HTML Context:\n<i</h>>")
		Scnr.RequestTrace("  Injected \"><h1>hxywp</h1> - ")
		
		html_res = Scnr.Inject("\"><h1>hxywp</h1>")
		res_details = "		|| Code - " + str(html_res.Code) + " | Length - " + str(html_res.BodyLength)
		self.CheckResponseDetails(html_res)
		
		if(html_res.BodyString.Contains("<h1>hxywp</h1>")):
			html_inj_contexts = self.GetContext("<h1>hxywp</h1>", html_res)
			if(html_inj_contexts.Contains("Html")):
				Scnr.ResponseTrace("<i<cr>>Got <h1>hxywp</h1> in HTML context<i</cr>>\n" + res_details)
				self.AddToTriggers("\"><h1>hxywp</h1>","<h1>hxywp</h1>")
				self.SetConfidence(3)
				#self.ReportXSS("<h1>hxytp</h1>", "<h1>hxytp</h1>", PluginResultConfidence.High)
			else:
				Scnr.ResponseTrace("Got <h1>hxywp</h1> in non-HTML context, context escaping failed\n" + res_details)
		elif(html_res.BodyString.Contains("<h1>hxywp")):
			html_inj_contexts = self.GetContext("<h1>hxywp", html_res)
			if(html_inj_contexts.Contains("Html")):
				Scnr.ResponseTrace("<i<cr>>Got <h1>hxywp in HTML context<i</cr>>\n" + res_details)
				self.AddToTriggers("\"><h1>hxywp</h1>","<h1>hxywp")
				self.SetConfidence(3)
				#self.ReportXSS("<h1>hxytp</h1>", "<h1>hxytp", PluginResultConfidence.High)
			else:
				Scnr.ResponseTrace("Got <h1>hxywp in non-HTML context, context escaping failed\n" + res_details)
		else:
			#must check for the encoding here
			Scnr.ResponseTrace("No reflection" + res_details)
			
		Scnr.RequestTrace("  Injected '><h1>hxywp</h1> - ")
		html_res = Scnr.Inject("'><h1>hxywp</h1>")
		
		res_details = "		|| Code - " + str(html_res.Code) + " | Length - " + str(html_res.BodyLength)
		self.CheckResponseDetails(html_res)
		
		if(html_res.BodyString.Contains("<h1>hxywp</h1>")):
			html_inj_contexts = self.GetContext("<h1>hxywp</h1>", html_res)
			if(html_inj_contexts.Contains("Html")):
				Scnr.ResponseTrace("<i<cr>>Got <h1>hxywp</h1> in HTML context<i</cr>>\n" + res_details)
				self.AddToTriggers("'><h1>hxywp</h1>","<h1>hxywp</h1>")
				self.SetConfidence(3)
				#self.ReportXSS("<h1>hxytp</h1>", "<h1>hxytp</h1>", PluginResultConfidence.High)
			else:
				Scnr.ResponseTrace("Got <h1>hxywp</h1> in non-HTML context, context escaping failed\n" + res_details)
		elif(html_res.BodyString.Contains("<h1>hxywp")):
			html_inj_contexts = self.GetContext("<h1>hxywp", html_res)
			if(html_inj_contexts.Contains("Html")):
				Scnr.ResponseTrace("<i<cr>>Got <h1>hxywp in HTML context<i</cr>>\n" + res_details)
				self.AddToTriggers("'><h1>hxywp</h1>","<h1>hxywp")
				self.SetConfidence(3)
				#self.ReportXSS("<h1>hxytp</h1>", "<h1>hxytp", PluginResultConfidence.High)
			else:
				Scnr.ResponseTrace("Got <h1>hxywp in non-HTML context, context escaping failed\n" + res_details)
		else:
			#must check for the encoding here
			Scnr.ResponseTrace("No reflection" + res_details)		
	
	def CheckForInjectionInJSInsideHTML(self):
		self.CheckForInjectionInJS(True)
		
	def CheckForInjectionInFullJS(self):
		self.CheckForInjectionInJS(False)
			
	def CheckForInjectionInJS(self, InLine):
		#Get required variables from ThreadStore
		Scnr = ThreadStore.Get("Scanner")
		ps = ThreadStore.Get("ps")
		ps_res = ThreadStore.Get("ps_res")
		
		script_contexts = []
		contaminated_scripts = []
		if(InLine):
			contaminated_scripts = ps_res.Html.GetJavaScript(ps)
		else:
			contaminated_scripts.append(ps_res.BodyString)
		
		for script in contaminated_scripts:
			ij = IronJint.Trace(script,ps)
			script_contexts.extend(ij.KeywordContexts)
			if(len(ij.SourceToSinkLines) > 0):
				Scnr.Trace("<i<br>><i<cr>><i<b>>Injected ProbeString was assigned to a DOM XSS Sink<i</b>><i</cr>>")
				js_triggers = []
				for line_no in ij.SourceToSinkLines:
					js_triggers.append(ij.RawLines[line_no-1])
				self.AddToTriggersWithProbeStringInjection(ps,"\r\n".join(js_triggers))
				self.SetConfidence(3)
		script_contexts = list(set(script_contexts))#make the array unique
		
		if(len(script_contexts) == 0 and len(contaminated_scripts) > 0):
			Scnr.Trace("<i<br>><i<cr>><i<b>>Injected ProbeString was reflected inside JS Code Context<i</b>><i</cr>>")
			self.AddToTriggersWithProbeStringInjection(ps,ps)
			self.SetConfidence(1)
			#self.ReportJSTestLead()
		
		#Start the test
		if(len(script_contexts) > 0):
			if(InLine):
				Scnr.Trace("<i<br>><i<h>>Checking for Injection in 'JS inside HTML' Context:\n<i</h>>")
			else:
				Scnr.Trace("<i<br>><i<h>>Checking for Injection in JS Context:\n<i</h>>")
			
		for context in script_contexts:
			if(context == "SingleQuoteStringValue"):
				Scnr.RequestTrace("  Injected 'qupjwsiz - ")
				js_res = Scnr.Inject("'qupjwsiz")
				res_details = "		|| Code - " + str(js_res.Code) + " | Length - " + str(js_res.BodyLength)
				self.CheckResponseDetails(js_res)
				if(js_res.BodyString.count("qupjwsiz") > 0):
					if(InLine):
						contaminated_scripts = js_res.Html.GetJavaScript("qupjwsiz")
					else:
						contaminated_scripts.append(js_res.BodyString)
					inj_success = False
					for script in contaminated_scripts:
						if(self.DoesEscapeQuotes(script,"'qupjwsiz")):
							Scnr.ResponseTrace("<i<cr>>Got qupjwsiz inside code context by escaping the value context with '<i</cr>>" + res_details)
							self.AddToTriggers("'qupjwsiz","'qupjwsiz")
							self.SetConfidence(3)
							inj_success = True
							break
					if(not inj_success):
						Scnr.ResponseTrace("Unable to escape out of JS value context" + res_details)
				else:
					Scnr.ResponseTrace("No reflection" + res_details)
			elif(context == "DoubleQuoteStringValue"):
				Scnr.RequestTrace('  Injected "quxjwliz - ')
				js_res = Scnr.Inject('"quxjwliz')
				res_details = "		|| Code - " + str(js_res.Code) + " | Length - " + str(js_res.BodyLength)
				self.CheckResponseDetails(js_res)
				if(js_res.BodyString.count("quxjwliz") > 0):
					if(InLine):
						contaminated_scripts = js_res.Html.GetJavaScript("quxjwliz")
					else:
						contaminated_scripts.append(js_res.BodyString)
					inj_success = False
					for script in contaminated_scripts:
						if(self.DoesEscapeQuotes(script,'"quxjwliz')):
							Scnr.ResponseTrace("<i<cr>>Got quxjwliz inside code context by escaping the value context with \"<i</cr>>" + res_details)
							self.AddToTriggers('"quxjwliz','"quxjwliz')
							self.SetConfidence(3)
							inj_success = True
							break
					if(not inj_success):
						Scnr.ResponseTrace("Unable to escape out of JS value context" + res_details)
				else:
					Scnr.ResponseTrace("No reflection" + res_details)
			elif(context == "NonStringValue"):
				Scnr.Trace("<i<br>><i<cr>><i<b>>Injected ProbeString was reflected inside JS Code Context<i</b>><i</cr>>")
				self.AddToTriggersWithProbeStringInjection(ps,ps)
				self.SetConfidence(1)
			elif(context == "StringValue"):
				self.ReportJSTestLead()

	def CheckForInjectionInUrlAttribute(self):
		#Get required variables from ThreadStore
		Scnr = ThreadStore.Get("Scanner")
		
		#Start the test
		Scnr.Trace("<i<br>><i<h>>Checking JS Injection in UrlAttribute Context:\n<i</h>>")
		Scnr.RequestTrace("  Injected javascript:yhstdjbz - ")
		
		ua_res = Scnr.Inject("javascript:yhstdjbz")
		
		res_details = "		|| Code - " + str(ua_res.Code) + " | Length - " + str(ua_res.BodyLength)
		self.CheckResponseDetails(ua_res)
		
		if(ua_res.BodyString.Contains("javascript:yhstdjbz")):
			ua_inj_contexts = self.GetContext("javascript:yhstdjbz", ua_res)
			if(ua_inj_contexts.Contains("UrlAttribute")):
				Scnr.ResponseTrace("<i<cr>>Got yhstdjbz in InLineJS context<i</cr>>\n" + res_details)
				self.AddToTriggers("javascript:yhstdjbz","javascript:yhstdjbz")
				self.SetConfidence(3)
			else:
				Scnr.ResponseTrace("Got javascript:yhstdjbz in non-UrlAttribute context\n")
		else:
			#must check for the encoding here
			Scnr.ResponseTrace("No reflection" + res_details)

	def DoesEscapeQuotes(self, Code, Keyword):
		position = -1
		try:
			while(True):			
				slash_count = 0
				position = Code.index(Keyword, position + 1)
				check_position = position - 1
				while(check_position > -1):
					if(Code[check_position] == "\\"):
						slash_count += 1
					else:
						check_position = -1
					check_position -= 1
				if(slash_count % 2 == 0):
					return True
		except:
			pass
		return False
	
	def CheckForInjectionInCSS(self):
		self.ReportCSSTestLead()
	
	def CheckForInjectionInAttributeName(self):		
		Scnr = ThreadStore.Get("Scanner")
		#Start the test
		Scnr.Trace("<i<br>><i<h>>Checking for Injection in HTML AttributeName Context:\n<i</h>>")
		self.InjectAttribute(" olpqir=\"vtkir(1)\"","olpqir","vtkir(1)")
		self.InjectAttribute(" olpqir='vtkir(1)'","olpqir","vtkir(1)")
	
	
	def CheckForInjectionInSingleQuoteAttributeValue(self):
		Scnr = ThreadStore.Get("Scanner")
		Scnr.Trace("<i<br>><i<h>>Checking for Injection in HTML AttributeValue Context:\n<i</h>>")
		self.InjectAttribute(" \' olqpir=\"vtikr(1)\"","olqpir","vtikr(1)")
		self.InjectAttribute(" \' olqpir=\'vtikr(1)\'","olqpir","vtikr(1)")
	
	def CheckForInjectionInDoubleQuoteAttributeValue(self):		
		Scnr = ThreadStore.Get("Scanner")
		Scnr.Trace("<i<br>><i<h>>Checking for Injection in HTML AttributeValue Context:\n<i</h>>")
		self.InjectAttribute(" \" olqpir=\"vtikr(1)\"","olqpir","vtikr(1)")
		self.InjectAttribute(" \" olqpir=\'vtikr(1)\'","olqpir","vtikr(1)")
		#HtmlAgilityPack considers quote-less as Double-Quote
		self.InjectAttribute(" olqpir=\"vtikr(1)\"","olqpir","vtikr(1)")
		self.InjectAttribute(" olqpir=\'vtikr(1)\'","olqpir","vtikr(1)")
	
	def InjectAttribute(self, Payload, AttrName, AttrValue):
		#Get required variables from ThreadStore
		Scnr = ThreadStore.Get("Scanner")
		
		#Start the test
		Scnr.RequestTrace("  Injected " + Payload + " - ")
		
		at_res = Scnr.Inject(Payload)
		res_details = "		|| Code - " + str(at_res.Code) + " | Length - " + str(at_res.BodyLength)
		self.CheckResponseDetails(at_res)
		
		name_contexts = self.GetContext(AttrName, at_res)
		value_contexts = self.GetContext(AttrValue, at_res)
		if(name_contexts.Contains("AttributeName") and (value_contexts.Contains("AttributeValueWithSingleQuote") or value_contexts.Contains("AttributeValueWithDoubleQuote"))):
			Scnr.ResponseTrace("<i<cr>>Got " + AttrName + " as AttributeName and " + AttrValue + " as AttributeValue<i</cr>>" + res_details)
			self.AddToTriggers(Payload, Payload)
			self.SetConfidence(3)
 			#self.ReportXSS(" olpqir=\"vtkir(1)\"", " olpqir=\"vtkir(1)\"", PluginResultConfidence.High)
 		elif(at_res.BodyString.Contains(Payload)):
 			Scnr.ResponseTrace("Got " + Payload + " outside of AttributeName and AttributeValue context" + res_details)
 		else:
			Scnr.ResponseTrace("No useful reflection" + res_details)
	
	def CheckForInjectionInComment(self):
		#Get required variables from ThreadStore
		Scnr = ThreadStore.Get("Scanner")
		#Start the test
		Scnr.Trace("<i<br>><i<h>>Checking HTML Injection by escaping from HTML Comment Context:\n<i</h>>")
		Scnr.RequestTrace("  Injected --><h1>hzyqp</h1> - ")
		
		html_res = Scnr.Inject("--><h1>hzyqp</h1>")
		res_details = "		|| Code - " + str(html_res.Code) + " | Length - " + str(html_res.BodyLength)
		self.CheckResponseDetails(html_res)
		
		if(html_res.BodyString.Contains("<h1>hzyqp</h1>")):
			html_inj_contexts = self.GetContext("<h1>hzyqp</h1>", html_res)
			if(html_inj_contexts.Contains("Html")):
				Scnr.ResponseTrace("<i<cr>>Got <h1>hzyqp</h1> in HTML context<i</cr>>\n" + res_details)
				self.AddToTriggers("--><h1>hzyqp</h1>","<h1>hzyqp</h1>")
				self.SetConfidence(3)
			elif(html_inj_contexts.Contains("Comment")):
				Scnr.ResponseTrace("Got <h1>hzyqp</h1> in HTML Comment context, context escaping failed\n" + res_details)
			else:
				Scnr.ResponseTrace("Got <h1>hzyqp</h1> in " + ",".join(html_inj_contexts) + " context[s], context escaping failed\n" + res_details)
				#self.ReportCommentTestLead(self, "--><h1>hzyqp</h1>", html_inj_contexts)
		elif(html_res.BodyString.Contains("<h1>hzyqp")):
			html_inj_contexts = self.GetContext("<h1>hzyqp", html_res)
			if(html_inj_contexts.Contains("Html")):
				Scnr.ResponseTrace("<i<cr>>Got <h1>hzyqp in HTML context<i</cr>>\n" + res_details)
				self.AddToTriggers("--><h1>hzyqp</h1>","<h1>hzyqp")
				self.SetConfidence(3)
			elif(html_inj_contexts.Contains("Comment")):
				Scnr.ResponseTrace("Got <h1>hzyqp in HTML Comment context, context escaping failed\n" + res_details)
			else:
				Scnr.ResponseTrace("Got <h1>hzyqp in " + ",".join(html_inj_contexts) + " context[s], context escaping failed\n" + res_details)
				#self.ReportCommentTestLead(self, "--><h1>hzyqp</h1>", html_inj_contexts)
		else:
			#must check for the encoding here
			Scnr.ResponseTrace("No reflection" + res_details)
	
	#css,js,html,attributes,attribute,unknown
	def GetContext(self, InjectedValue, Res):
		if(Res.IsHtml):
			return Res.Html.GetContext(InjectedValue)
		elif(Res.ContentType.Contains("css")):
			return ["CSS"]
		#elif(Res.ContentType.Contains("javascript") or Res.ContentType.Contains("json")):
		#	return ["JS"]
		elif(Tools.IsJavaScript(Res.BodyString) or Tools.IsJson(Res.BodyString)):
			return ["JS"]
		else:
			return ["Unknown"]
	
		
	def ReportXSS(self, ReqTrigger, ResTrigger, Confidence):
		Scnr = ThreadStore.Get("Scanner")
		PR = PluginResult(Scnr.InjectedRequest.Host)
		PR.Title = "Cross-site Scripting Detected"
		PR.Summary = "Cross-site Scripting has been detected in the '" + Scnr.InjectedParameter + "' parameter of the " + Scnr.InjectedSection + " section of the request  <i<br>><i<br>><i<hh>>Test Trace:<i</hh>><i<br>>" + ThreadStore.Get("TestTrace")
		PR.Triggers.Add(ReqTrigger,Scanner.InjectedRequest,ResTrigger,Scanner.InjectionResponse)
		PR.ResultType = PluginResultType.Vulnerability
		PR.Severity = PluginResultSeverity.High
		PR.Confidence = Confidence
		Scnr.AddResult(PR)
	
	def ReportCSSTestLead(self):
		Scnr = ThreadStore.Get("Scanner")
		PR = PluginResult(Scnr.InjectedRequest.Host)
		PR.Title = "XSS Plugin found reflection in CSS"
		PR.Summary = "Data injected in to the '" + Scnr.InjectedParameter + "' parameter of the " + Scnr.InjectedSection + " is being reflected back as part of CSS. Manually check this for XSS."
		PR.Triggers.Add("",Scnr.InjectedRequest,"",Scnr.InjectionResponse)
		PR.ResultType = PluginResultType.TestLead
		Scnr.AddResult(PR)
	
	#def ReportCommentTestLead(self):
	#	Scnr = ThreadStore.Get("Scanner")
	#	PR = PluginResult(Scnr.InjectedRequest.Host)
	#	PR.Title = "XSS Plugin found reflection in HTML Comment"
	#	PR.Summary = "Data injected in to the '" + Scnr.InjectedParameter + "' parameter of the " + Scnr.InjectedSection + " is being reflected back as part of HTML Comment. Manually check this for XSS."
	#	PR.Triggers.Add("",Scnr.InjectedRequest,"",Scnr.InjectionResponse)
	#	PR.ResultType = PluginResultType.TestLead
	#	Scnr.AddResult(PR)
		
	def ReportJSTestLead(self):
		Scnr = ThreadStore.Get("Scanner")
		PR = PluginResult(Scnr.InjectedRequest.Host)
		PR.Title = "XSS Plugin found reflection in JavaScript"
		PR.Summary = "Data injected in to the '" + Scnr.InjectedParameter + "' parameter of the " + Scnr.InjectedSection + " is being reflected back inside JavaScript. Manually check this for XSS."
		PR.Triggers.Add("",Scnr.InjectedRequest,"",Scnr.InjectionResponse)
		PR.ResultType = PluginResultType.TestLead
		Scnr.AddResult(PR)
		
	def AddToTriggers(self, RequestTrigger, ResponseTrigger):
		Scnr = ThreadStore.Get("Scanner")
		RequestTriggers = ThreadStore.Get("RequestTriggers")
		ResponseTriggers = ThreadStore.Get("ResponseTriggers")
		TriggerRequests = ThreadStore.Get("TriggerRequests")
		TriggerResponses = ThreadStore.Get("TriggerResponses")
		RequestTriggers.append(RequestTrigger)
		ResponseTriggers.append(ResponseTrigger)
		TriggerRequests.append(Scnr.InjectedRequest.GetClone())
		TriggerResponses.append(Scnr.InjectionResponse.GetClone())
		
	def AddToTriggersWithProbeStringInjection(self, RequestTrigger, ResponseTrigger):
		Scnr = ThreadStore.Get("Scanner")
		RequestTriggers = ThreadStore.Get("RequestTriggers")
		ResponseTriggers = ThreadStore.Get("ResponseTriggers")
		TriggerRequests = ThreadStore.Get("TriggerRequests")
		TriggerResponses = ThreadStore.Get("TriggerResponses")
		ps_req = ThreadStore.Get("ps_req")
		ps_res = ThreadStore.Get("ps_res")
		RequestTriggers.append(RequestTrigger)
		ResponseTriggers.append(ResponseTrigger)
		TriggerRequests.append(ps_req.GetClone())
		TriggerResponses.append(ps_res.GetClone())
		
	def SetUpThreadVariables(self):
		TestTrace = ""
		ThreadStore.Put("TestTrace",TestTrace)
		ThreadStore.Put("TraceTitle","-")
		
		RequestTriggers = []
		ResponseTriggers = []
		TriggerRequests = []
		TriggerResponses = []
		ThreadStore.Put("RequestTriggers",RequestTriggers)
		ThreadStore.Put("ResponseTriggers",ResponseTriggers)
		ThreadStore.Put("TriggerRequests",TriggerRequests)
		ThreadStore.Put("TriggerResponses",TriggerResponses)
		
		Confidence = 0
		ThreadStore.Put("Confidence",Confidence)
		
	def SetConfidence(self, NewConfidence):
		Confidence = ThreadStore.Get("Confidence")
		if(NewConfidence > Confidence):
			ThreadStore.Put("Confidence",NewConfidence)
	
	def SetTraceTitle(self, Title):
		ThreadStore.Put("TraceTitle",Title)
	
	def CheckResponseDetails(self, res):
		ps_res = ThreadStore.Get("ps_res")
		Scnr = ThreadStore.Get("Scanner")
		if(Scnr.InjectedSection == "URL" and ps_res.Code == 404):
			return
		if(ps_res.Code != res.Code):
			self.SetTraceTitle("Injection Response Code varies from baseline")
		elif ps_res.BodyLength + res.BodyLength > 0:
			diff_percent = (res.BodyLength * 1.0)/((ps_res.BodyLength + res.BodyLength)* 1.0)
			if(diff_percent > 0.6 or  diff_percent < 0.4):
				self.SetTraceTitle("Injection Response Length varies from baseline")
	
	def AnalyseResults(self):
		Scnr = ThreadStore.Get("Scanner")
		Confidence = ThreadStore.Get("Confidence")
		RequestTriggers = ThreadStore.Get("RequestTriggers")
		ResponseTriggers = ThreadStore.Get("ResponseTriggers")
		TriggerRequests = ThreadStore.Get("TriggerRequests")
		TriggerResponses = ThreadStore.Get("TriggerResponses")
		if(len(RequestTriggers) > 0):
			PR = PluginResult(Scnr.InjectedRequest.Host)
			PR.Title = "Cross-site Scripting Detected"
			PR.Summary = "Cross-site Scripting has been detected in the '" + Scnr.InjectedParameter + "' parameter of the " + Scnr.InjectedSection + " section of the request  <i<br>><i<br>><i<hh>>Test Trace:<i</hh>>" + Scnr.GetTrace()
			for i in range(len(RequestTriggers)):
				PR.Triggers.Add(RequestTriggers[i],TriggerRequests[i],ResponseTriggers[i],TriggerResponses[i])
			PR.ResultType = PluginResultType.Vulnerability
			PR.Severity = PluginResultSeverity.High
			if(Confidence == 3):
				PR.Confidence = PluginResultConfidence.High
			elif(Confidence == 2):
				PR.Confidence = PluginResultConfidence.Medium
			else:
				PR.Confidence = PluginResultConfidence.Low
			Scnr.AddResult(PR)
			Scnr.LogTrace("XSS Found")
		else:
			#TraceMessage = "ScanID - " + str(Scanner.ID) + " ==> No findings from XSS check. Tested Parameter - '" + Scanner.InjectedParameter + "'.      Section - '" + Scanner.InjectedSection + "'      <i<br>>" + TestTrace
			#Tools.ScanTrace(Scanner.ID, self.Name, Scanner.InjectedSection, Scanner.InjectedParameter, "No findings", TestTrace)
			Scnr.LogTrace(ThreadStore.Get("TraceTitle"))

p = CrossSiteScripting()
p.Name = "XSS"
p.Description = "Active Plugin to detect Cross-site Scripting vulnerabilities"
ActivePlugin.Add(p)
