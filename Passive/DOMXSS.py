#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr
import re

#Inherit from the base PassivePlugin class
class DOMXSS(PassivePlugin):

	#From http://code.google.com/p/domxsswiki/wiki/FindingDOMXSS by Mario Heiderich
	sources = re.compile('/(location\s*[\[.])|([.\[]\s*["\']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)/')
	sinks = re.compile('/((src|href|data|location|code|value|action)\s*["\'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["\'\]]*\s*\()/')
		
	#Override the Check method of the base class with custom functionlity
	def Check(self, Sess, Results):		
		if(Sess.Request == None):
			return
		if(Sess.Response == None):
			return
		if(Sess.Response.IsBinary):
			return
		source_matches = []
		sink_matches = []
		
		JS = ""
		
		if(Sess.Response.IsHtml):
			scripts = Sess.Response.Html.GetJavaScript()
			for script in scripts:
				JS += "\r\n" + script
		elif (Tools.IsJavaScript(Sess.Response.BodyString)):
			JS = Sess.Response.BodyString
		
		for source_match in self.sources.findall(JS):
			for match in source_match:
				if(len(match) > 0):
					source_matches.append(match)
		for sink_match in self.sinks.findall(JS):
			for match in sink_match:
				if(len(match) > 0):
					sink_matches.append(match)
		
		source_matches = list(set(source_matches))
		sink_matches = list(set(sink_matches))
		
		if((len(source_matches) == 0) and (len(sink_matches) == 0)):
			return
		
		Title = ""
		Summary = ""
		
		if((len(source_matches) > 0) and (len(sink_matches) > 0)):
			Title = "DOM XSS Sources and Sinks found"
			Summary = "DOM XSS Sources and Sinks were found in the Body of the Response. Analyze the Response for presence of DOM XSS"
		elif(len(source_matches) > 0):
			Title = "DOM XSS Sources found"
			Summary = "DOM XSS Sources were found in the Body of the Response. Analyze the Response for presence of DOM XSS"
		elif(len(sink_matches) > 0):
			Title = "DOM XSS Sinks found"
			Summary = "DOM XSS Sinks were found in the Body of the Response. Analyze the Response for presence of DOM XSS"
		
		if(len(source_matches) > 0):
			Summary += "<i<br>><i<h>>Sources:<i</hh>><i<br>>"
			for m in source_matches:
				Summary += "	" + m +"<i<br>>"
		if(len(sink_matches) > 0):
			Summary += "<i<br>><i<h>>Sinks:<i</hh>><i<br>>"
			for m in sink_matches:
				Summary += "	" + m +"<i<br>>"
				
		PR = PluginResult(Sess.Request.Host)
		PR.Title = Title
		PR.Summary = Summary
		PR.Triggers.Add("", Sess.Request, "", Sess.Response);
		PR.ResultType = PluginResultType.TestLead;
		PR.Signature = 'DOMXSS|TestLead|{0}'.format(Tools.MD5(JS))
		Results.Add(PR)
			
p = DOMXSS()
p.Name = "DOMXSSChecker"
p.Description = "Passive plugin that checks the JavaScript in HTTP Response for DOM XSS Sources and Sinks."
#When should this plugin be called. Possible values - BeforeInterception, AfterInterception, Both, Offline. Offline is the default value, it is also the recommended value if you are not going to perform any changes in the Request/Response
#p.CallingState = PluginCallingState.BeforeInterception
#On what should this plugin run. Possible values - Request, Response, Both
p.WorksOn = PluginWorksOn.Response
PassivePlugin.Add(p)
