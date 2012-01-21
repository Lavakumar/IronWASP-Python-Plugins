#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr

#Inherit from the base SessionPlugin class
class DemoAppPreLoginSearch(SessionPlugin):

	#Override the Update method with custom code to check the validity of the Request/Response and update the Request. Returns Request
	def Update(self, Req, Res):
		Req.SetCookie(Res)
		return Req

	#Override the Login method with custom code to login and return a updated Request. Called internally by DoLogin() with syncing. Returns Request
	def Login(self, Req, Res):
		return Req

	#Override the CanInject method to provide a filter for parameters that should not be injected/tested. Returns boolean
	def CanInject(self, Scnr, Req):
		return True

	#Override the ProcessInjection method to update the Payload before it is injected. Returns String
	def ProcessInjection(self, Scnr, Req, Payload):
		if Scnr.InjectedSection == "Query" and Scnr.InjectedParameter == "q":
			return Tools.Base64Encode(Payload)
		else:
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

p = DemoAppPreLoginSearch()
p.Name = "DemoAppPreLoginSearch"
p.Description = "This plugin Base64 encodes any values injected in to the 'q' parameter"
SessionPlugin.Add(p)
