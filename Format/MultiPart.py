#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

import clr
from IronWASP import *
from System import *
from System.Text import *
clr.AddReference('System.Xml')
from System.Xml import *
from System.Collections.Generic import *

#Inherit from the base FormatPlugin class
class MultiPart(FormatPlugin):

	#Override the ToXmlFromRequest method of the base class with custom functionlity. Convert RequestBody in to Xml String and return it
	def ToXmlFromRequest(self, Req):
		return self.BodyToXml(Req)

	#Override the ToXmlFromResponse method of the base class with custom functionlity. Convert ResponseBody in to Xml String and return it
	def ToXmlFromResponse(self, Res):
		pass

	#Override the ToXml method of the base class with custom functionlity. Convert ByteArray in to Xml String and return it
	def ToXml(self, ObjectArray):
		pass

	#Override the ToRequestFromXml method of the base class with custom functionlity. Update Request based on Xml String input and return it
	def ToRequestFromXml(self, Req, XML):
		return self.XmlToBody(Req, XML)

	#Override the ToResponseFromXml method of the base class with custom functionlity. Update Response based on Xml String input and return it    
	def ToResponseFromXml(self, Res, XML):
		pass

	#Override the ToObject method of the base class with custom functionlity. Convert the XmlString in to an Object and return it as ByteArray
	def ToObject(self, XmlString):
		pass
	
	
	#Compare byte_arrays
	def check_boundary(self, sign_bytes, ba, index):
		for i in range(len(sign_bytes)):
			if(sign_bytes[i] != ba[index + i]):
				return "No"
		end_ba = Array.CreateInstance(Byte,2)
		Array.Copy(ba,index+len(sign_bytes),end_ba,0,2)
		end_str = Encoding.UTF8.GetString(end_ba)
		if end_str == "--":
			return "End"
		elif end_str == "\r\n":
			return "Bound"
		else:
			return "No"
	
	#Gets the ByteArray of Boundry and End of body markers
	def get_bs(self, req):
		b_sign_str = "--" + req.Headers.Get("Content-Type").split("boundary=")[1]
		b_sign_bytes = Encoding.UTF8.GetBytes(b_sign_str)
		return b_sign_bytes
	
	
	def BodyToXml(self, req):
		b_len = len(req.Headers.Get("Content-Type").split("boundary=")[1]) + 4
		bs = self.get_bs(req)
		i = 0
		points = []
		while i < req.BodyLength:
			chk_result = self.check_boundary(bs, req.BodyArray, i)
			if chk_result == "Bound":
				points.append(i)
				#print "Boundary @ " + str(i + b_len)
				i = i + b_len
			elif chk_result == "End":
				points.append(i)
				#print "End @ " + str(i + b_len + 2)
				i = req.BodyLength
			else:
				i = i+ 1
		ba_parts = []
		start_point = 0
		for i in range(len(points)):
			if i == len(points) - 1:
				part = Array[Byte](range(end_point - start_point))
			else:
				if i == 0:
					start_point = points[i] + b_len
				end_point = points[i + 1] - 2
				part = Array.CreateInstance(Byte,end_point - start_point)
				Array.Copy(req.BodyArray, start_point, part,0, end_point - start_point)
				ba_parts.append(part)
				start_point = points[i + 1] + b_len
		#print len(ba_parts)
		XB = StringBuilder()
		Settings = XmlWriterSettings()
		Settings.Indent = True
		XW = XmlWriter.Create(XB, Settings)
		#xml_out = "<xml>"
		XW.WriteStartElement("xml")
		for ba in ba_parts:
			self.get_xml(ba, XW)
		#xml_out = xml_out + "</xml>"
		XW.WriteEndElement()
		#print xml_out
		XW.Close()
		return XB.ToString().split("?>")[1]
	
	def get_xml(self, ba, XW):
		XW.WriteStartElement("section")
		XW.WriteStartElement("meta")
		#xml = "<section><meta>"
		ba_str = Encoding.UTF8.GetString(ba)
		parts = ba_str.split("\r\n\r\n")
		first_parts = parts[0].split("\r\n")
		binary = False
		for fp in first_parts:
			#xml = xml + "<line>"
			XW.WriteStartElement("line")
			fp_parts = fp.split("; ")
			meta = fp_parts[0].split(": ")
			if meta[0] == "Content-Type" and not meta[1].lower().count("text") > 0:
				binary = True
			XW.WriteStartElement(meta[0])
			XW.WriteValue(meta[1])
			XW.WriteEndElement()
			#xml = xml + "<" + meta[0] + ">" + meta[1] + "</" + meta[0] + ">"
			for i in range(1, len(fp_parts)):
				o_meta = fp_parts[i].split("=")
				#xml = xml + "<" + o_meta[0] + ">" + o_meta[1].strip('"') + "</" + o_meta[0] + ">"
				XW.WriteStartElement(o_meta[0])
				XW.WriteValue(o_meta[1].strip('"'))
				XW.WriteEndElement()
			#xml = xml + "</line>"
			XW.WriteEndElement()
		XW.WriteEndElement()
		XW.WriteStartElement("value")
		#xml = xml + "</meta><value>"
		if binary:
			binary_data = Array.CreateInstance(Byte, len(ba) - (len(parts[0]) + 4 ))#don't use len(parts[1]) as binary values would have incorrect length in the string form
			Array.Copy(ba, len(parts[0]) + 4, binary_data,0, len(binary_data))
			#xml = xml + Tools.Base64Encode(binary_data)
			XW.WriteValue(Tools.Base64EncodeByteArray(binary_data))
		else:
			#xml = xml + parts[1]
			XW.WriteValue(parts[1])
		#xml = xml + "</value>"
		#xml = xml + "</section>"
		XW.WriteEndElement()
		XW.WriteEndElement()
		return XW
		
	def XmlToBody(self, req, xml):
		boundary = "--" + req.Headers.Get("Content-Type").split("boundary=")[1]
		body_list = List[Byte]()
		
		xd = XmlDocument()
		xd.LoadXml(xml)
		
		sections = xd.SelectNodes("/xml/section")
			
		for section in sections:
			#mp = mp + boundary + "\r\n"
			body_list.AddRange(Encoding.UTF8.GetBytes(boundary + "\r\n"))
			binary = False
			lines = section.SelectNodes("meta/line")
		
			value = ""
			value_nodes = section.SelectNodes("value")
			if value_nodes.Count > 0:
				value = value_nodes[0].InnerText
			
			for line in lines:
				nodes = line.ChildNodes
				if nodes.Count > 0:
					#mp = mp + nodes[0].Name
					body_list.AddRange(Encoding.UTF8.GetBytes(nodes[0].Name))
					#mp = mp + ": " + nodes[0].InnerText
					body_list.AddRange(Encoding.UTF8.GetBytes(": " + nodes[0].InnerText))
					if nodes[0].Name == "Content-Type" and not nodes[0].InnerText.lower().count("text") > 0:
						binary = True
					
					
					for i in range(1,nodes.Count):
						#mp = mp + "; "
						body_list.AddRange(Encoding.UTF8.GetBytes("; "))
						#mp = mp + nodes[i].Name
						body_list.AddRange(Encoding.UTF8.GetBytes(nodes[i].Name))
						#mp = mp + '="' + nodes[i].InnerText + '"'
						body_list.AddRange(Encoding.UTF8.GetBytes('="' + nodes[i].InnerText + '"'))
						if nodes[i].Name == "Content-Type" and not nodes[i].InnerText.lower().count("text") > 0:
							binary = True
				#mp = mp + "\r\n"
				body_list.AddRange(Encoding.UTF8.GetBytes("\r\n"))
			#mp = mp + "\r\n"
			body_list.AddRange(Encoding.UTF8.GetBytes("\r\n"))
			if binary:
				#mp = mp + Tools.Base64Decode(value)
				try:
					body_list.AddRange(Tools.Base64DecodeToByteArray(value))
				except:
					body_list.AddRange(Encoding.UTF8.GetBytes(value))
			else:
				#mp = mp + value
				body_list.AddRange(Encoding.UTF8.GetBytes(value))
			#mp = mp + "\r\n"
			body_list.AddRange(Encoding.UTF8.GetBytes("\r\n"))
		#mp = mp + boundary + "--"
		body_list.AddRange(Encoding.UTF8.GetBytes(boundary + "--\r\n"))
		req.BodyArray = body_list.ToArray()
		return req

p = MultiPart()
p.Name = "MultiPart"
p.Description = "Format Plugin to convert MultiPart body to XML and vice versa"
FormatPlugin.Add(p)
