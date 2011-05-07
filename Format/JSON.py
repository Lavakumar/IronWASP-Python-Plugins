#License: GPLv3
#Author: Lavakumar Kuppan

from Iron import *
import clr
clr.AddReference('Newtonsoft.Json.Net20')
from Newtonsoft import *
from System.Text import *
clr.AddReference('System.Xml')
from System.Xml import *
from System.IO import *

class JSON(FormatPlugin):
  
  def ToXml(self, ObjectArray):
    JSONString = Encoding.UTF8.GetString(ObjectArray)
    XMlOut = Json.JsonConvert.DeserializeXmlNode(JSONString, "XML")
    SW = StringWriter()
    XW = XmlTextWriter(SW)
    XW.Formatting = Formatting.Indented
    XMlOut.WriteContentTo(XW)
    return SW.ToString()

  def ToObject(self, XmlString):
    XMLDoc = XmlDocument();
    XMLDoc.LoadXml(XmlString);
    JSONString = Json.JsonConvert.SerializeXmlNode(XMLDoc, Json.Formatting.Indented, True);
    return Encoding.UTF8.GetBytes(JSONString)

p = JSON();
p.Name = "JSON";
p.Description = "Plugin to Convert JSON to XML and XML to JSON. Used in the Scanner section to set Injection points"
p.FileName = "JSON.py";
FormatPlugin.Add(p)
