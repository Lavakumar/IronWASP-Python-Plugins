#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System.Threading import Monitor
import re

class CheckReflection(PassivePlugin):
    
	def Check(self, Sess, Results):
	
		if(Sess.Request == None):
			return
		
		if(Sess.Response == None):
			return
		
		if(Sess.Response.IsBinary):
			return
		
		#Get the probe strings injected by the XSS Plugin during XSS Scans
		probe_strings = Analyzer.GetProbeStrings()
		ReqStr = Sess.Request.ToString()
		ResStr = Sess.Response.ToString()
		
		matching_probe_strings = []
		
		for ps in probe_strings:
			if(ReqStr.count(ps) == 0):
				if(ResStr.count(ps) > 0):
					matching_probe_strings.append(ps)
		
		if(len(matching_probe_strings) > 0):
			PR = PluginResult(Sess.Request.Host)
			PR.Title = "Stored Reflection Found on {0}".format(Sess.Request.URLPath)
			PR.Summary = "Probe Strings injected during XSS Scans were found to be reflected in this page. This indicates a Stored Reflection, test this for Stored XSS."
			PR.Triggers.Add("", Sess.Request, "\r\n".join(matching_probe_strings), Sess.Response)
			for mps in matching_probe_strings:
				PR.Triggers.Add(mps, Analyzer.GetProbeStringRequest(mps))
			PR.ResultType = PluginResultType.TestLead
			PR.Signature = 'CheckReflection|TestLead|{0}|{1}|{2}'.format(Sess.Request.UrlPath, "-".join(matching_probe_strings))
			Results.Add(PR)
        

p = CheckReflection()
p.Name = "Check Reflections"
p.Description = "Passive plugin to identify stored reflections"
#p.CallingState = PluginCallingState.BeforeInterception
p.WorksOn = PluginWorksOn.Response
PassivePlugin.Add(p)
