#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr
#Inherit from the base SessionPlugin class
class DemoAppLoginUpdate(SessionPlugin):

	#Override the Update method with custom code to check the validity of the Request/Response and update the Request. Returns Request
	def Update(self, Req, Res):
		if(Req.Url == "/login" and Req.Method == "POST"):
			r = Request(Req.FullUrl)
			r.CookieString = Req.CookieString
			res = r.Send()
			Req.SetCookie(res)
			res.ProcessHtml()
			token = res.Html.GetValues("input","value")[2]
			Req.Body.Set("token",token)
		return Req

	#Override the ProcessInjection method to update the Payload before it is injected. Returns String
	def ProcessInjection(self, Scnr, Req, Payload):
		return Payload

	#Override the PrepareForInjection method to make changes to the request or perform other steps before injecting. Returns Request
	def PrepareForInjection(self, Req):
		return Req

	#Override the GetInterestingResponse method to perform customs actions after the injection is done. Returns Response
	def GetInterestingResponse(self, Req, Res):
		return Res

p = DemoAppLoginUpdate()
p.Name = "DemoAppLoginUpdate"
p.Description = "Session Plugin to update CSRF token in the Login Request"
SessionPlugin.Add(p)