#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr

#Inherit from the base PassivePlugin class
class HeaderAnalysis(PassivePlugin):

	#Override the Check method of the base class with custom functionlity
	def Check(self, Sess, Results):
				
		if Sess.Response.Headers.Has("Location") and Sess.Response.Code != 200:
			redirect_location = Sess.Response.Headers.Get("Location").lower()
			if Sess.Request.FullUrl.lower().count(redirect_location) > 0:
				if Sess.Request.UrlPath.lower().count(redirect_location) > 0:
					for part in Sess.Request.UrlPathParts:
						if part.lower() == redirect_location:
							self.ReportRedirect(redirect_location, "url", Sess, Results)
							return
				else:
					for name in Sess.Request.Query.GetNames():
						for val in Sess.Request.Query.GetAll(name):
							if val.lower() == redirect_location:
								self.ReportRedirect(redirect_location, "query:(0)".format(name), Sess, Results)
								return
			elif Sess.Request.BodyString.lower().count(redirect_location) > 0:
				for name in Sess.Request.Body.GetNames():
					for val in Sess.Request.Body.GetAll(name):
						if val.lower() == redirect_location:
							self.ReportRedirect(redirect_location, "body:{0}".format(name), Sess, Results)
							return
			elif Sess.Request.Headers.Has("Referer"):
				if Sess.Request.Headers.Get("Referer").lower() == redirect_location:
					self.ReportRedirect(redirect_location, "referrer", Sess, Results)
					return

	def ReportRedirect(self, redirect_location, section, Sess, Results):
		Signature = '{0}|{1}'.format(Sess.Request.SSL.ToString(), section)
		if self.IsSignatureUnique(Sess.Request.Host, PluginResultType.TestLead, Signature):
			PR = PluginResult(Sess.Request.Host)
			PR.Title = "Possible Open Redirect"
			PR.Summary = "The Location Header of the Response contains the value present in the Request. This could potentially be an Open Redirect. Manual investigation required."
			PR.Triggers.Add(redirect_location, Sess.Request, redirect_location, Sess.Response)
			PR.Signature = Signature
			PR.ResultType = PluginResultType.TestLead
			Results.Add(PR)
		
	
p = HeaderAnalysis()
p.Name = "Header Analysis"
p.Version = "0.1"
p.Description = "Analyzes the HTTP Request and Response Headers for potential security issues"
#When should this plugin be called. Possible values - BeforeInterception, AfterInterception, Both, Offline. Offline is the default value, it is also the recommended value if you are not going to perform any changes in the Request/Response
#p.CallingState = PluginCallingState.BeforeInterception
#On what should this plugin run. Possible values - Request, Response, Both
p.WorksOn = PluginWorksOn.Response
PassivePlugin.Add(p)
