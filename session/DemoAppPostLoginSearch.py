#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr

#Inherit from the base SessionPlugin class
class DemoAppPostLoginSearch(SessionPlugin):

	#Override the Update method with custom code to check the validity of the Request/Response and update the Request. Returns Request
	def Update(self, Req, Res):
		Req.SetCookie(Res)
		return Req

	#Override the ProcessInjection method to update the Payload before it is injected. Returns String
	def ProcessInjection(self, Scnr, Req, Payload):
		if Scnr.InjectedSection == "URL" and Scnr.InjectedUrlPathPosition == 1:
			return Tools.Base64Encode(Payload)
		else:
			return Payload

	#Override the PrepareForInjection method to make changes to the request or perform other steps before injecting. Returns Request
	def PrepareForInjection(self, Req):
		return Req

	#Override the GetInterestingResponse method to perform customs actions after the injection is done. Returns Response
	def GetInterestingResponse(self, Req, Res):
		return Res

p = DemoAppPostLoginSearch()
p.Name = "DemoAppPostLoginSearch"
p.Description = "This plugin Base64 encodes any values injected in to the URL Path parameter that holds the search query"
SessionPlugin.Add(p)
