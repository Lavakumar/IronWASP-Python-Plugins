#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
import re

class SessionAnalysis(PassivePlugin):
    
	#Override the GetInstance method of the base class to return a new instance with details
	def GetInstance(self):
		p = SessionAnalysis()
		p.Name = "Session Analysis"
		p.Description = "Passive plugin to analyze the Session for potential vulnerabilities"
		p.Version = "0.3"
		p.FileName = "SessionAnalysis.py"
		p.WorksOn = PluginWorksOn.Response
		return p
	
	def Check(self, Sess, Results):

		ThreadStore.Put("Session", Sess)
		ThreadStore.Put("Results", Results)
		
		#Check if this is a response for authentication
		if(self.IsLoginRequest(Sess.Request)):
			if(Sess.Response.SetCookies.Count == 0 and Sess.Request.Cookie.Count > 0):
				Summary = "The application does not set a new Session ID in the cookie after what appears to be an authentication attempt by the user. If this was a successful login and the Session IDs are stored in cookies then this application is affected by Session Fixation vulnerability."
				self.ReportSessionFixation(Summary, "", "",PluginResultConfidence.Low, PluginResultSeverity.Medium)
			elif(Sess.Response.SetCookies.Count > 0):
				name = self.GetSessionParameterName(Sess)
				if(len(name) > 0):
					if(Sess.Request.Cookie.Has(name)):
						for sc in Sess.Response.SetCookies:
							if(sc.Name == name):
								if(sc.Value == Sess.Request.Cookie.Get(name)):
									Summary = "The value of the Session ID is the same after what appears to be an authentication attempt by the user. If this was a successful login and the Session IDs are stored in cookies then this application is affected by Session Fixation vulnerability."
									RequestTrigger = "{0}= {1}".format(name, Sess.Request.Cookie.Get(name))
									ResponseTrigger = "{0}= {1}".format(name, Sess.Request.Cookie.Get(name))
									self.ReportSessionFixation(Summary, RequestTrigger, ResponseTrigger, PluginResultConfidence.Low, PluginResultSeverity.Medium)

	def IsLoginRequest(self, Req):
		login_url_keywords = ['login','auth','signin','signoff']
		login_usernames = ['uname','username','email','id','user']
		login_passwords = ['pwd','password','pass','passwd']
		
		url_check_pass = False
		username_check_pass = False
		password_check_pass = False
		
		username_in_url = False
		password_in_url = False
		
		username_parameter = ""
		password_parameter = ""
		
		for word in login_url_keywords:
			if(re.search(word, Req.Url, re.I)):
				url_check_pass = True
				break
		
		for word in login_usernames:
			for param in Req.Body.GetNames():
				if word == param.lower():
					username_check_pass = True
					username_parameter = word
					break
		
		for word in login_passwords:
			for param in Req.Body.GetNames():
				if word == param.lower():
					password_check_pass = True
					password_parameter = word
					break
				
		if(not username_check_pass):
			for word in login_usernames:
				for param in Req.Query.GetNames():
					if word == param.lower():
						username_check_pass = True
						username_parameter = word
						username_in_url = True
						break
		
		if(not password_check_pass):
			for word in login_passwords:
				for param in Req.Query.GetNames():
					if word == param.lower():
						password_check_pass = True
						password_parameter = word
						password_in_url = True
						break
		
		if((url_check_pass and username_check_pass) or password_check_pass):
			if(password_in_url):
				Summary = "The application sends the user's password in clear-text over the URL."
				if(username_in_url and (Req.Method == "GET")):
					self.ReportPasswordInUrl(Summary, password_parameter, "", PluginResultConfidence.High, PluginResultSeverity.Medium)
				elif(Req.Method == "GET"):
					self.ReportPasswordInUrl(Summary, password_parameter, "", PluginResultConfidence.Medium, PluginResultSeverity.Medium)
				else:
					self.ReportPasswordInUrl(Summary, password_parameter, "", PluginResultConfidence.Low, PluginResultSeverity.Medium)
			return True
		else:
			return False

	def GetSessionParameterName(self, Sess):
		for sc in Sess.Response.SetCookies:
			if(re.search("session", sc.Name, re.I)):
				return sc.Name
		for name in Sess.Request.Cookie.GetNames():
			if(re.search("session", name, re.I)):
				return name
		return ""
				
		     
	def ReportSessionFixation(self, Summary, RequestTrigger, ResponseTrigger, Confidence, Severity):
		Results = ThreadStore.Get("Results")
		Sess = ThreadStore.Get("Session")
		Signature = 'SessionFixation|{0}|{1}|{2}'.format(self.MakeUniqueString(Sess), RequestTrigger, ResponseTrigger)
		if self.IsSignatureUnique(Sess.Request.Host, PluginResultType.Vulnerability, Signature):
			PR = PluginResult(Sess.Request.Host)
			PR.Title = "Session Fixation Found"
			PR.Summary = Summary
			PR.Triggers.Add(RequestTrigger, Sess.Request, ResponseTrigger, Sess.Response)
			PR.Signature = Signature
			PR.Confidence = Confidence
			PR.Severity = Severity
			Results.Add(PR)
		
	def ReportPasswordInUrl(self, Summary, RequestTrigger, ResponseTrigger, Confidence, Severity):
		Results = ThreadStore.Get("Results")
		Sess = ThreadStore.Get("Session")
		Signature = 'PasswordInUrl|{0}|{1}|{2}'.format(self.MakeUniqueString(Sess), RequestTrigger, ResponseTrigger)
		if self.IsSignatureUnique(Sess.Request.Host, PluginResultType.Vulnerability, Signature):
			PR = PluginResult(Sess.Request.Host)
			PR.Title = "Password Sent in URL"
			PR.Summary = Summary
			PR.Triggers.Add(RequestTrigger, Sess.Request, ResponseTrigger, Sess.Response);
			PR.Signature = Signature
			PR.Confidence = Confidence
			PR.Severity = Severity
			Results.Add(PR)

	def MakeUniqueString(self, Sess):
		us = '{0}|{1}:'.format(Sess.Request.SSL.ToString(), Sess.Request.Method)
		return us

p = SessionAnalysis()
PassivePlugin.Add(p.GetInstance())
