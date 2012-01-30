#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr

#Inherit from the base SessionPlugin class
class DemoAppRegisterCapctha(SessionPlugin):

	#Override the Update method with custom code to check the validity of the Request/Response and update the Request. Returns Request
	def Update(self, Req, Res):
		Req.SetCookie(Res)
		if(Req.Url == "/register" and Req.Method == "POST"):
			r = Request(Req.FullUrl)
			r.Url = "/captcha"
			r.CookieString = Req.CookieString
			res = r.Send()
			res.SaveBody("cap.png")
			cap_str = AskUser.ForString("Register Captcha","Solve the Captcha to Submit the Register form", "cap.png")
			Req.Body.Set("captcha",cap_str)
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

	#Override the ShouldReDo method to check if the Response is valid and if the Injection should be performed again. Returns boolean
	def ShouldReDo(self, Scnr, Req, Res):
		if(Req.Url == "/register" and Req.Method == "POST"):
			if(Res.BodyString.find("Incorrect Captcha value, try again") > -1):
				if(Scnr.InjectedSection == "Body" and Scnr.InjectedParameter == "captcha"):
					return False
				else:
					return True
		return False

p = DemoAppRegisterCapctha()
p.Name = "DemoAppRegisterCapctha"
p.Description = "This plugin solves the Register Form Captcha of the DemoApp from the User"
SessionPlugin.Add(p)
