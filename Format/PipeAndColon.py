#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
from System.Xml import *
from System.Text import *
from System.IO import *
import clr

#This is a sample Format Plugin to handle the following body forat
#key1:value1|key2:value2|key3:value3

#Inherit from the base FormatPlugin class
class PipeAndColon(FormatPlugin):

	#Override the ToXml method of the base class with custom functionlity. Convert ByteArray in to Xml String and return it
	def ToXml(self, ObjectArray):
		format_string = Encoding.UTF8.GetString(ObjectArray)
		kv_pairs = format_string.split('|')
		xml = '<xml>'
		for kv in kv_pairs:
			kv_parts = kv.split(':')
			xml += '<' + kv_parts[0] + '>'
			xml += Tools.XmlEncode(kv_parts[1])
			xml += '</' + kv_parts[0] + '>'
		xml += '</xml>'
		return xml

	#Override the ToObject method of the base class with custom functionlity. Convert the XmlString in to an Object and return it as ByteArray
	def ToObject(self, XmlString):
		XMLStringReader = StringReader(XmlString.Trim())
		Reader = XmlReader.Create(XMLStringReader)
		result = ""
		while (Reader.Read()):
			if (Reader.IsStartElement()):
				if(Reader.Name != "xml"):
					if(len(result) > 0):
						result += "|"
					result += Reader.Name + ":"
			elif (Reader.NodeType != XmlNodeType.EndElement):
				result += Reader.Value.Trim();
		Reader.Close()
		return Encoding.UTF8.GetBytes(result)

p = PipeAndColon()
p.Name = "PipeAndColon"
p.Description = "Format Plugin to Handle the Pipe and Colon custom format - 'username:lava|pass:s3cr3t'"
FormatPlugin.Add(p)
