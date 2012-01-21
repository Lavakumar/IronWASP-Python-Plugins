#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license


from IronWASP import *
import clr
clr.AddReference('Newtonsoft.Json.Net20')
from Newtonsoft import *
from Newtonsoft import *
from System.Text import *
clr.AddReference('System.Xml')
from System.Xml import *
from System.IO import *

class JSON(FormatPlugin):
  
	def ToXmlFromRequest(self, Request):
	    return self.ToXml(Request.BodyArray)
	
	def ToXmlFromResponse(self, Response):
		return self.ToXml(Response.BodyArray)
	
	def ToXml(self, ObjectArray):
		JSONString = Encoding.UTF8.GetString(ObjectArray)
		return self.JsonToXml(JSONString)
	
	def ToRequestFromXml(self, Request, XML):
		Request.BodyArray = self.ToObject(XML)
		return Request
	
	def ToResponseFromXml(self, Response, XML):
		Response.BodyArray = self.ToObject(XML)
		return Response
	
	def ToObject(self, XmlString):
		JSONString = self.XmlToJson(XmlString)
		return Encoding.UTF8.GetBytes(JSONString)

	def JsonToXml(self, JsonIn):
		JR = StringReader(JsonIn)
		JTR = Json.JsonTextReader(JR)
		XB = StringBuilder()
		Settings = XmlWriterSettings()
		Settings.Indent = True
		XW = XmlWriter.Create(XB, Settings)
		XW.WriteStartElement("xml")
		PropertyDict = {}
		Read = True
		NextRead = False

		while (Read):
			if not NextRead:
				Read = JTR.Read()
			NextRead = False
			if JTR.TokenType == Json.JsonToken.StartConstructor:
					XW.WriteStartElement("cons")
			elif JTR.TokenType == Json.JsonToken.EndConstructor:
					XW.WriteEndElement()
			elif JTR.TokenType == Json.JsonToken.PropertyName:
				if PropertyDict.has_key(JTR.Depth):
					XW.WriteEndElement()
				PropertyDict[JTR.Depth] = JTR.Value.ToString()
				XW.WriteStartElement(JTR.Value.ToString())
			elif JTR.TokenType == Json.JsonToken.Boolean:
					XW.WriteStartElement("bool")
					if JTR.Value:
						XW.WriteValue(1)
					else:
						XW.WriteValue(0)
					XW.WriteEndElement()
			elif JTR.TokenType == Json.JsonToken.Float or JTR.TokenType == Json.JsonToken.Integer or JTR.TokenType == Json.JsonToken.Date:
					XW.WriteStartElement("num")
					XW.WriteValue(JTR.Value.ToString())
					XW.WriteEndElement()
			elif JTR.TokenType == Json.JsonToken.String:
					XW.WriteStartElement("str")
					XW.WriteValue(JTR.Value.ToString())
					XW.WriteEndElement()
			elif JTR.TokenType == Json.JsonToken.Null:
					XW.WriteStartElement("undef")
					XW.WriteValue("null")
					XW.WriteEndElement()
			elif JTR.TokenType == Json.JsonToken.StartArray:
					XW.WriteStartElement("arr")
					Read = JTR.Read()
					NextRead = True
					if JTR.TokenType == Json.JsonToken.EndArray:
						XW.WriteValue("")
			elif JTR.TokenType == Json.JsonToken.EndArray:
					XW.WriteEndElement()
			elif JTR.TokenType == Json.JsonToken.StartObject:
					XW.WriteStartElement("obj")
					Read = JTR.Read()
					NextRead = True
					if JTR.TokenType == Json.JsonToken.EndObject:
						XW.WriteValue("")
			elif JTR.TokenType == Json.JsonToken.EndObject:
				PropertyNameFound = False
				pd_keys = PropertyDict.keys()
				for k in pd_keys:
					if k > JTR.Depth:
						PropertyNameFound = True
						PropertyDict.pop(k)
				if PropertyNameFound:
					XW.WriteEndElement()
				XW.WriteEndElement()
				if JTR.Depth == 0:
					Read = False
		XW.WriteEndElement()
		XW.Close()
		return XB.ToString().split("?>")[1]

	def XmlToJson(self, Xml):
		JW = StringWriter()
		JTW = Json.JsonTextWriter(JW)
		JTW.Formatting = Json.Formatting.Indented
		XSR = StringReader(Xml.Trim())
		XR = XmlReader.Create(XSR)
		ValueType = ""
		XR.Read()
		if not (XR.NodeType == XmlNodeType.Element and XR.Name == "xml"):
			raise Exception("Invalid XML Input")
		Read = True
		NextRead = False
		while (Read):
			if not NextRead:
				Read = XR.Read()
			NextRead = False
			if XR.NodeType == XmlNodeType.Element :
				if XR.Name == "obj" :
					JTW.WriteStartObject()
				elif XR.Name == "arr" :
				    JTW.WriteStartArray()
				elif XR.Name == "cons" :
					JTW.WriteStartConstructor("")
				elif XR.Name == "num" or XR.Name == "str" or XR.Name == "bool" or XR.Name == "undef" :
					ValueType = XR.Name
					Read = XR.Read()
					NextRead = True
					if XR.NodeType == XmlNodeType.EndElement:
						JTW.WriteValue("")
				else:
					JTW.WritePropertyName(XR.Name)
			elif XR.NodeType == XmlNodeType.EndElement :
				if XR.Name == "obj" :
					JTW.WriteEndObject()
				elif XR.Name == "arr" :
					JTW.WriteEndArray()
				elif XR.Name == "cons" :
					JTW.WriteEndConstructor()
			elif XR.NodeType == XmlNodeType.Text :
				if ValueType == "num" :
					try:
						JTW.WriteValue(int(XR.Value.Trim()))
					except:
						try:
							JTW.WriteValue(float.Parse(XR.Value.Trim()))
						except:
							JTW.WriteValue(XR.Value)
				elif ValueType == "str" :
					JTW.WriteValue(XR.Value.ToString())
				elif ValueType == "bool" :
					if XR.Value.ToString().Equals("1"):
						JTW.WriteValue(True)
					elif(XR.Value.ToString().Equals("0")):
						JTW.WriteValue(False)
					else:
						JTW.WriteValue(XR.Value)
				elif ValueType == "undef" :
					if XR.Value.ToString() == "null" :
						JTW.WriteNull()
					else:
						JTW.WriteValue(XR.Value.ToString())
		JTW.Close()
		return JW.ToString()

p = JSON();
p.Name = "JSON";
p.Description = "Plugin to Convert JSON to XML and XML to JSON. Used in the Scanner section to set Injection points"
FormatPlugin.Add(p)
