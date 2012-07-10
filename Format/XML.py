#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System.Text import *
from System.IO import *
from System.Xml import *

class XML(FormatPlugin):
  
	def ToXmlFromRequest(self, Req):
		original_xml = Req.BodyString
		ironwasp_xml = self.original_xml_to_ironwasp_xml(original_xml)
		return ironwasp_xml
	
	def ToXmlFromResponse(self, Res):
		original_xml = Res.BodyString
		ironwasp_xml = self.original_xml_to_ironwasp_xml(original_xml)
		return ironwasp_xml
	
	def ToXml(self, ObjectArray):
		original_xml = Encoding.UTF8.GetString(ObjectArray)
		return self.original_xml_to_ironwasp_xml(original_xml)
	
	def ToRequestFromXml(self, Req, XML):
		xml_dec = self.get_xml_declaration(Req.BodyString)
		ironwasp_xml = XML.strip()
		original_xml = self.ironwasp_xml_to_original_xml(ironwasp_xml)
		if len(xml_dec) > 0:
			original_xml = "<?xml {0}?>{1}".format(xml_dec, original_xml)
		Req.BodyString = original_xml
		return Req
	
	def ToResponseFromXml(self, Res, XML):
		xml_dec = self.get_xml_declaration(Res.BodyString)
		ironwasp_xml = XML.strip()
		original_xml = self.ironwasp_xml_to_original_xml(ironwasp_xml)
		if len(xml_dec) > 0:
			original_xml = "<?xml {0}?>{1}".format(xml_dec, original_xml)
		Res.BodyString = original_xml
		return Res
	
	def ToObject(self, XmlString):
		original_xml = self.ironwasp_xml_to_original_xml(XmlString)
		return Encoding.UTF8.GetBytes(original_xml)
	
	def original_xml_to_ironwasp_xml(self, original_xml):
		xd = XmlDocument()
		xd.LoadXml(original_xml)
		xb = StringBuilder()
		settings = XmlWriterSettings()
		settings.Indent = True
		xw = XmlWriter.Create(xb, settings)
		xw.WriteStartElement("xml")
		self.otoi_read_node(xd.ChildNodes[1], xw)
		xw.WriteEndElement()
		xw.Close()
		ironwasp_xml =	xb.ToString().split("?>")[1]
		return ironwasp_xml
	
	def otoi_read_node(self, node, xw):
		if node.NodeType == XmlNodeType.Element:
			xw.WriteStartElement("nn_" + node.Name)
			has_attrs = False
			if node.Attributes != None and node.Attributes.Count > 0:
				has_attrs = True
				xw.WriteStartElement("attrs")
				for att in node.Attributes:
					xw.WriteStartElement("an_" + att.Name)
					xw.WriteValue(att.Value)
					xw.WriteEndElement()
				xw.WriteEndElement()
			if node.HasChildNodes:
				if node.ChildNodes.Count == 1 and node.ChildNodes[0].NodeType == XmlNodeType.Text:
					xw.WriteStartElement("val")
					xw.WriteValue(node.ChildNodes[0].Value)
					xw.WriteEndElement()
				else:
					for ch in node.ChildNodes:
						self.otoi_read_node(ch, xw)
			xw.WriteEndElement()
	
	def ironwasp_xml_to_original_xml(self, ironwasp_xml):
		xd = XmlDocument()
		xd.LoadXml(ironwasp_xml)
		xb = StringBuilder()
		settings = XmlWriterSettings()
		settings.Indent = True
		xw = XmlWriter.Create(xb, settings)
		self.itoo_read_node(xd.ChildNodes[0], xw)
		xw.Close()
		original_xml =	xb.ToString().split("?>")[1]
		return original_xml
	
	def itoo_read_node(self, node, xw):
		is_attr_val = False
		is_tag_opened = False
		
		if node.NodeType == XmlNodeType.Element:
			if node.Name.startswith("nn_"):
				xw.WriteStartElement(node.Name.lstrip("nn_"))
				is_tag_opened = True
			elif node.Name.startswith("an_"):
				is_attr_val = True
				xw.WriteStartAttribute(node.Name.lstrip("an_"))
			#attrs, val and xml nodes will be ignored and will not be written
			
			if node.HasChildNodes:
				if node.ChildNodes.Count == 1 and node.ChildNodes[0].NodeType == XmlNodeType.Text:
					xw.WriteValue(node.ChildNodes[0].Value)
					if is_attr_val:
						xw.WriteEndAttribute()
				else:
					for ch in node.ChildNodes:
						self.itoo_read_node(ch, xw)
			
			if is_tag_opened:
				xw.WriteEndElement()
				
	def get_xml_declaration(self, xml):
		dec = ""
		xsr = StringReader(xml.Trim())
		xr = XmlReader.Create(xsr)
		xr.Read()
		if xr.NodeType == XmlNodeType.XmlDeclaration:
			dec = xr.Value
		xsr.Close()
		xr.Close()
		return dec


p = XML()
p.Name = "XML"
p.Version = "0.2"
p.Description = "Plugin to handle XML to enable setting Injection points"
FormatPlugin.Add(p)