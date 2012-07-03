from IronWASP import *
from System import *
from System.Xml import *
from System.Text import *
from System.IO import *
import clr

#Inherit from the base FormatPlugin class
class Demo(FormatPlugin):

	#Override the ToXmlFromRequest method of the base class with custom functionlity. Convert RequestBody in to Xml String and return it
	def ToXmlFromRequest(self, req):
		return self.ToXml(req.BodyArray)

	#Override the ToXmlFromResponse method of the base class with custom functionlity. Convert ResponseBody in to Xml String and return it
	def ToXmlFromResponse(self, res):
		return self.ToXml(res.BodyArray)

	#Override the ToXml method of the base class with custom functionlity. Convert ByteArray in to Xml String and return it
	def ToXml(self, object_array):
		body_str = Encoding.UTF8.GetString(object_array)
		values = self.GetValuesFromBody(body_str)
		
		xb = StringBuilder()
		Settings = XmlWriterSettings()
		Settings.Indent = True
		xw = XmlWriter.Create(xb, Settings)
		xw.WriteStartElement("xml")
		
		for i in range(len(values)):
			xw.WriteStartElement("val" + str(i))
			xw.WriteValue(values[i])
			xw.WriteEndElement()
		xw.WriteEndElement()
		xw.Close()
		return xb.ToString().split("?>")[1]

	#Override the ToRequestFromXml method of the base class with custom functionlity. Update Request based on Xml String input and return it
	def ToRequestFromXml(self, req, xml):
		req.BodyArray = self.ToObject(xml)
		return req

	#Override the ToResponseFromXml method of the base class with custom functionlity. Update Response based on Xml String input and return it    
	def ToResponseFromXml(self, res, xml):
		res.BodyArray = self.ToObject(xml)
		return res

	#Override the ToObject method of the base class with custom functionlity. Convert the XmlString in to an Object and return it as ByteArray
	def ToObject(self, xml_string):
		xml_string_reader = StringReader(xml_string.Trim())
		reader = XmlReader.Create(xml_string_reader)
		values = []
		while (reader.Read()):
			if reader.NodeType == XmlNodeType.Text:
				values.append(reader.Value.Trim())
		reader.Close()
		body_str = self.GetBodyFromValues(values)
		return Encoding.UTF8.GetBytes(body_str)
	
	def GetValuesFromBody(self, body_str):
		values = []
		i = 0
		i = i + 2
		while i < len(body_str):
			if body_str[i] == 'F' and body_str[i + 1] == 'F':
				i = i + 2
				length = ""
				end_of_length = False
				while not end_of_length:
					try:
						int(body_str[i])
						length = length + body_str[i]
						i = i + 1
					except:
						end_of_length = True
				i = i + 2
				len_int = int(length)
				values.append(body_str[i:i + len_int])
				i = i + len_int
			else:
				break
		return values
	
	def GetBodyFromValues(self, values):
		body_str = '00'
		for v in values:
			body_str = body_str + 'FF' + str(len(v)) + 'F0' + v
		body_str = body_str + '00'
		return body_str


p = Demo()
p.Name = "Demo"
p.Description = "Demo plugin to handle a custom body format"
FormatPlugin.Add(p)
