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

	#Override the Login method with custom code to login and return a updated Request. Called internally by DoLogin() with syncing. Returns Request
	def Login(self, Req, Res):
		return Req

	#Override the CanInject method to provide a filter for parameters that should not be injected/tested. Returns boolean
	def CanInject(self, Scnr, Req):
		return True

	#Override the ProcessInjection method to update the Payload before it is injected. Returns String
	def ProcessInjection(self, Scnr, Req, Payload):
		return Payload

	#Override the GetBaseLine method to customize the base-line response returned to the Scanner. Returns Response
	def GetBaseLine(self, Scnr, Req):
		return Scnr.Inject()

	#Override the PrepareForInjection method to make changes to the request or perform other steps before injecting. Returns Request
	def PrepareForInjection(self, Req):
		return Req

	#Override the GetInterestingResponse method to perform customs actions after the injection is done. Returns Response
	def GetInterestingResponse(self, Req, Res):
		return Res

	#Override the ShouldReDo method to check if the Response is valid and if the Injection should be performed again. Returns boolean
	def ShouldReDo(self, Scnr, Req, Res):
		return False

p = DemoAppLoginUpdate()
p.Name = "DemoAppLoginUpdate"
p.Description = "Session Plugin to update CSRF token in the Login Request"
SessionPlugin.Add(p)