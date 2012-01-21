#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System.Text import *
from System.IO import *

class XML(FormatPlugin):
  
    def ToXmlFromRequest(self, Request):
        return self.ToXml(Request.BodyArray)
    
    def ToXmlFromResponse(self, Response):
        return self.ToXml(Response.BodyArray)
    
    def ToXml(self, ObjectArray):
    		return Encoding.UTF8.GetString(ObjectArray)
    
    def ToRequestFromXml(self, Request, XML):
        Request.BodyString = XML
        return Request
    
    def ToResponseFromXml(self, Response, XML):
        Response.BodyString = XML
        return Response
    
    def ToObject(self, XmlString):
        return Encoding.UTF8.GetBytes(XmlString)

p = XML();
p.Name = "XML";
p.Description = "Plugin to handle XML to enable setting Injection points"
FormatPlugin.Add(p)