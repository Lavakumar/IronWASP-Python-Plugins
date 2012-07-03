#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr
import re

#Inherit from the base ActivePlugin class
class OpenRedirect(ActivePlugin):

	basic_redirect_urls = ["http://<host>", "https://<host>", "//<host>", "<host>", "5;URL='http://<host>'"]
	#taken from http://kotowicz.net/absolute/
	full_redirect_urls = [ "http://<host>", "https://<host>", "//<host>", "http:\\\\<host>", "https:\\\\<host>", "\\\\<host>", "/\\<host>", "\\/<host>", "\r//<host>", "/ /<host>", "http:<host>", "https:<host>", "http:/<host>", "https:/<host>", "http:////<host>", "https:////<host>", "://<host>", ".:.<host>", "<host>", "5;URL='http://<host>'"]
	
	def GetInstance(self):
		p = OpenRedirect()
		p.Name = "Open Redirect"
		p.Description = "Active Plugin to check for Open Redirect vulnerability"
		p.Version = "0.1"
		return p
	
	#Override the Check method of the base class with custom functionlity
	def Check(self, scnr):
		self.scnr = scnr
		self.base_req = self.scnr.BaseRequest
		self.scnr.StartTrace()
		self.scnr.SetTraceTitle("-",0)
		self.CheckForOpenRedirection()
		self.scnr.LogTrace()
	
	def CheckForOpenRedirection(self):
		self.scnr.Trace("<i<br>><i<h>>Checking for Open Redirect:<i</h>>")
		urls = []
		uniq_str = "eziepwlivt"
		self.scnr.Trace("<i<br>><i<h>>Checking if In-Domain Redirect Happens:<i</h>>")
		self.scnr.RequestTrace("  Injected payload - {0}".format(uniq_str))
		res = self.scnr.Inject(uniq_str)
		if self.IsRedirectedTo(uniq_str, res, False):
			self.scnr.ResponseTrace("	==> <i<b>>In-domain redirect happens. Using full payload set!<i</b>>")
			self.scnr.SetTraceTitle("In-domain redirect happens", 5)
			urls.extend(self.full_redirect_urls)
		else:
			self.scnr.ResponseTrace("	==> In-domain redirect does not happen. Using only basic payload set")
			urls.extend(self.basic_redirect_urls)
		
		host = self.base_req.Host
		#remove the port number from hostname
		try:
			if host.index(":") > 0:
				host = host[:host.index(":")]
		except:
			pass

		self.scnr.Trace("<i<br>><i<h>>Checking if Out-of-Domain Redirect Happens:<i</h>>")
		for url in urls:
			for i in range(2):
				h = ""
				if i == 0:
					h = "example.org"
				else:
					h = "{0}.example.org".format(host)
				payload = url.replace("<host>", h)
				self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
				res = self.scnr.Inject(payload)
				redirected = False
				if payload.startswith("5;"):
					redirect_url = "http://{0}".format(h)
					redirected = self.IsRedirectedTo(redirect_url, res, False)
				elif payload.startswith(h):
					redirected = self.IsRedirectedTo(payload, res, True)
				else:
					redirected = self.IsRedirectedTo(payload, res, False)

				if redirected:
						self.ReportOpenRedirect(payload, payload)
						self.scnr.ResponseTrace("	==> <i<cr>>Redirects to Injected payload!<i</cr>>")
						return
				else:
					self.scnr.ResponseTrace("	==> No redirect to payload")
		
	
	def IsRedirectedTo(self, ru, res, host_only):
			if not host_only:
				#check if redirection is happening through Location
				if res.Headers.Has("Location"):
					location_url = res.Headers.Get("Location")
					if self.IsLocationRedirected(location_url, ru):
						return True
				
				lus = res.Html.GetMetaContent("http-equiv", "Location")
				if len(lus) > 0:
					if self.IsLocationRedirected(lus[0], ru):
						return True
				
				#check if redirection is happening through Refresh
				if res.Headers.Has("Refresh"):
					refresh_url = res.Headers.Get("Refresh").lower()
					if self.IsRefreshRedirected(refresh_url, ru):
						return True
				
				rus = res.Html.GetMetaContent("http-equiv", "Refresh")
				if len(rus) > 0:
					if self.IsRefreshRedirected(rus[0], ru):
						return True
						
			#check if redirection is happening through JavaScript
			#location.href="url"
			#navigate("url")
			#location="url"
			#location.replace("url")
			if res.BodyString.lower().count(ru) > 0:
				JS = res.Html.GetJavaScript()
				for script in JS:
					script = script.lower()
					if script.count(ru) > 0:
						if host_only:
							if re.search('location\.host\s*=\s*(\'|")\s*{0}'.format(re.escape(ru)), script):
								return True
						else:
							if re.search('location(\.href)*\s*=\s*(\'|")\s*{0}'.format(re.escape(ru)), script):
								return True
							elif re.search('(navigate|location\.replace)\(\s*(\'|")\s*{0}'.format(re.escape(ru)), script):
								return True
			return False
	
	def IsLocationRedirected(self, location, redirect_url):
		location = location.strip()
		redirect_url = redirect_url.strip()
		if location.lower().startswith(redirect_url.lower()):
			return True
		else:
			return False
	
	def IsRefreshRedirected(self, refresh, redirect_url):
		refresh = refresh.strip()
		redirect_url = redirect_url.strip()
		r_parts = refresh.split(";", 1)
		if len(r_parts) == 2:
			r_url = r_parts[1].lower().strip().lstrip("url=").strip().strip("'").strip('"')
			if r_url.startswith(redirect_url.lower()):
				return True
		return False
	
	def ReportOpenRedirect(self, req_trigger, res_trigger):
		self.scnr.SetTraceTitle("Open Redirect Found", 10)
		pr = PluginResult(self.scnr.InjectedRequest.Host)
		pr.Title = "Open Redirect Found"
		pr.Summary = "Open redirect been detected in the '{0}' parameter of the {1} section of the request  <i<br>><i<br>><i<hh>>Test Trace:<i</hh>>{2}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.scnr.GetTrace())
		pr.Triggers.Add(req_trigger, self.scnr.InjectedRequest, res_trigger, self.scnr.InjectionResponse)
		pr.ResultType = PluginResultType.Vulnerability
		pr.Severity = PluginResultSeverity.High
		pr.Confidence = PluginResultConfidence.High
		self.scnr.AddResult(pr)


p = OpenRedirect()
ActivePlugin.Add(p.GetInstance())
