#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license

from IronWASP import *
from System import *
import clr
import re

#Inherit from the base ActivePlugin class
class SQLInjection(ActivePlugin):
	
	error_regex_raw = []
	error_regex = []
	time_check = []
	
	def GetInstance(self):
		p = SQLInjection()
		p.Name = "SQL Injection"
		p.Description = "Plugin to discover SQL Injection vulnerabilities"
		p.Version = "0.3"
		return p
	
	#Override the Check method of the base class with custom functionlity
	def Check(self, Scnr):
		
		self.Scnr = Scnr
		self.RequestTriggers = []
		self.ResponseTriggers = []
		self.TriggerRequests = []
		self.TriggerResponses = []
		self.Confidence = 0
		self.base_response = self.Scnr.BaseResponse
		
		self.Scnr.StartTrace()
		self.Scnr.SetTraceTitle("-",0)
		
		self.Scnr.Trace("<i<br>><i<h>>Checking for SQL Injection:<i</h>>")

		overall_error_score = self.CheckForErrorBasedSQLi()
		overall_blind_score = self.CheckForBlindSQLi()
		
		overall_score = overall_error_score + overall_blind_score
		
		if(overall_score > 7):
			self.ReportSQLInjection(PluginResultConfidence.High)
		elif(overall_score > 4):
			self.ReportSQLInjection(PluginResultConfidence.Medium)
		elif(overall_score > 3):
			self.ReportSQLInjection(PluginResultConfidence.Low)
		else:
			self.Scnr.LogTrace()
		#overall_blind_score = self.CheckForBlindSQLi(Request, Scanner)
		#overall_score = overall_error_score + overall_blind_score
		#if(overall_score == 0):
		#	return

	def CheckForErrorBasedSQLi(self):
		self.Scnr.Trace("<i<br>><i<h>>Checking for Error based Injection:<i</h>>")
		payload_responses = []
		payloads = ["'", "\"", "\xBF'\"(", "(", ")"]
		final_error_score = 0
		for payload in payloads:
			self.Scnr.RequestTrace("  Injected {0} - ".format(payload))
			if payload == "\xBF'\"(":
				inj_res = self.Scnr.RawInject(payload)
			else:
				inj_res = self.Scnr.Inject(payload)
			score = self.AnalyseInjectionResultForError(payload, inj_res)
			if score > final_error_score:
				final_error_score = score
		return final_error_score
	
	def AnalyseInjectionResultForError(self, payload, payload_response):
		res = payload_response
		diff_error_no = False#do base response and injeted response have different number of error matches
		triggers = []
		all_error_matches = {}
		
		error_score = 0
		for i in range(len(self.error_regex)):
			error_re = self.error_regex[i]
			error_re_raw = self.error_regex_raw[i]
			matches = error_re.findall(res.BodyString)
			if len(matches) > 0:
				original_error_matches = error_re.findall(self.base_response.BodyString)
				all_error_matches[error_re_raw] = [len(matches),len(original_error_matches)]
				triggers.extend(matches)
				if(len(matches) != len(original_error_matches)):
					diff_error_no = True
		
		if(len(all_error_matches) > 0):
			for error_key,(inj_matches,base_matches) in all_error_matches.items():
				self.Scnr.Trace("	    <i<cr>>Got {0} occurance[s] of error signature. Normal Response had {1} occurance[s]<i</cr>>. <i<b>>Error Signature:<i</b>> {2}".format(str(inj_matches), str(base_matches), error_key))
				if diff_error_no:
					error_score = 7
				else:
					error_score = 4
		else:
			self.Scnr.Trace("	    No errors")
		
		if error_score > 0:
			self.RequestTriggers.append(payload)
			self.ResponseTriggers.append("\r\n".join(triggers))
			self.TriggerRequests.append(self.Scnr.InjectedRequest.GetClone())
			self.TriggerResponses.append(res)

		return error_score
	
	def CheckForBlindSQLi(self):
		self.Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection:<i</h>>")
		is_int = False
		int_value = 0
		str_value = ""
		str_value = self.Scnr.PreInjectionParameterValue.replace("'","").replace('"',"")
		try:
			int_value = int(self.Scnr.PreInjectionParameterValue)
			is_int = True
		except:
			pass

		blind_int_math_score = 0
		blind_str_conc_score = 0
		blind_bool_score = 0
		blind_time_score = 0
		
		if is_int:
			blind_int_math_score = self.InjectBlindIntMath(int_value)
		else:
			blind_int_math_score = self.InjectBlindIntMath(0)
			
		if len(str_value) > 1:
			blind_str_conc_score = self.InjectBlindStrConc(str_value)
		
		blind_bool_score = self.InjectBlindBool()
		
		blind_time_score = self.CheckBlindTime()
		
		if blind_int_math_score  + blind_str_conc_score + blind_bool_score + blind_time_score > 0:
			return 6
		else:
			return 0
		
	def InjectBlindIntMath(self, int_value):
		self.Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection with Integer Math:<i</h>>")
		
		val = int_value
		
		#Addition Algo
		#if val < 2 then val = 3
		#(val - 1) + 1
		#(val - 2) + 2
		#
		#(val) + 5
		#(val - 1) + 6
		#
		#(val) + "a"
		#(val) + "b"
		#
		if val < 2:
			val = 3#adjust the value to be suitable for addition based check
		plus_left = [ val-1, val-2, val, val-1, val, val]
		plus_right = [ 1, 2, 5, 6, "a", "b"]
		
		#Subtraction Algo
		#(val + 1) - 1
		#(val + 2) - 2
		#
		#if val < 6 then val = 11
		#
		#(val) - 5
		#(val + 1) - 6
		#
		#(val) - "a"
		#(val) - "b"
		#

		val = int_value
		if val < 6:
			sub_val = 11#adjust the value to be suitable for subtraction based check
		else:
			sub_val = val
		minus_left = [ val+1, val+2, sub_val, sub_val+1, val, val]
		minus_right = [ 1, 2, 5, 6, "a", "b"]

		symbols = [ "+", "-"]
		keys = [ "a", "aa", "b", "bb", "c", "cc"]
		
		for ii in range(2):
			sym = symbols[ii]
			left = []
			right = []
			if sym == "+":
				self.Scnr.Trace("<i<br>>  <i<b>>Checking Addition:<i</b>>")
				left.extend(plus_left)
				right.extend(plus_right)
			else:
				self.Scnr.Trace("<i<br>>  <i<b>>Checking Subtraction:<i</b>>")
				left.extend(minus_left)
				right.extend(minus_right)
			
			#variables to keep track of rechecking
			first_strict_signature = ""
			first_relaxed_signature = ""
			second_strict_signature = ""
			second_relaxed_signature = ""
			confidence = 0
			vuln = False
			first_strict_vuln = False
			first_relaxed_vuln = False
			
			for j in range(2):
				if j == 1 and not (first_strict_vuln or first_relaxed_vuln):
					break
				payloads = []
				requests = []
				responses = []
				sc = SimilarityChecker()
				self.Scnr.Trace("<i<br>>")
				for i in range(6):
					payload = "{0}{1}{2}".format(left[i], sym, right[i])
					self.Scnr.RequestTrace("  Request Key: '{0}' - Injecting {1} ".format(keys[i], payload))
					res = self.Scnr.Inject(payload)
					#store the request and responses to be added to the vulnerability data if SQLi is found
					payloads.append(payload)
					requests.append(self.Scnr.InjectedRequest.GetClone())
					responses.append(res)
					sc.Add(keys[i], res)
					self.Scnr.ResponseTrace(" ==> Code-{0} Length-{1}".format(res.Code, res.BodyLength))
				sc.Check()
				
				self.Scnr.Trace("<i<br>>  The responses are analyzed for similarity based grouping to determine if injection succeeded.")
				self.Scnr.Trace("  Analysis Results:")
				self.Scnr.Trace("  Strict Groups Signature: {0}".format(sc.StrictGroupsSignature))
				self.Scnr.Trace("  Relaxed Groups Signature: {0}".format(sc.RelaxedGroupsSignature))
				
				if j == 0:
					first_strict_signature = sc.StrictGroupsSignature
					first_relaxed_signature = sc.RelaxedGroupsSignature
					
					if self.IsBlindMathInjectableGroupingCheck(sc.StrictGroups):
						self.Scnr.Trace("  <i<b>>Strict Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
						if j == 0:
							first_strict_vuln = True
					else:
						self.Scnr.Trace("  Strict Grouping does not indicates that injection succeeded.")
					
					if self.IsBlindMathInjectableGroupingCheck(sc.RelaxedGroups):
						self.Scnr.Trace("  <i<b>>Relaxed Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
						if j == 0:
							first_relaxed_vuln = True
					else:
						self.Scnr.Trace("  Relaxed Grouping does not indicates that injection succeeded.")
				else:
					second_strict_signature = sc.StrictGroupsSignature
					second_relaxed_signature = sc.RelaxedGroupsSignature
					vuln = False
					
					if first_strict_vuln and first_strict_signature == second_strict_signature:
						vuln = True
						confidence = confidence + 1
						self.Scnr.Trace("  <i<cr>>Even the second time Strict Grouping indicates that injection succeeded.<i</cr>>")
					else:
						self.Scnr.Trace("  Strict Grouping does not indicate that injection succeeded.")
					
					if first_relaxed_vuln and first_relaxed_signature == second_relaxed_signature:
						vuln = True
						confidence = confidence + 1
						self.Scnr.Trace("  <i<cr>>Even the second time Relaxed Grouping indicates that injection succeeded.<i</cr>>")
					else:
						self.Scnr.Trace("  Relaxed Grouping does not indicate that injection succeeded.")
					
					if vuln:
						self.RequestTriggers.extend(payloads)
						self.TriggerRequests.extend(requests)
						self.TriggerResponses.extend(responses)
						for i in range(len(payloads)):
							self.ResponseTriggers.append("")
						return confidence
		return 0
	
	def IsBlindMathInjectableGroupingCheck(self, groups):
		vuln = False
		for group in groups:
			if group.Count == 2 or group.Count == 4:
				m = 0
				if group.HasKey("a") and group.HasKey("aa"):
					m = m + 1
				if group.HasKey("b") and group.HasKey("bb"):
					m = m + 1
				if group.HasKey("c") and group.HasKey("cc"):
					m = m + 1
				if (group.Count == 2 and m == 1) or (group.Count == 4 and m == 2):
					#indicates SQL Injection report it
					vuln = True
			else:
				vuln = False
				break
		return vuln
	
	def InjectBlindStrConc(self, str_value):
		BlindConcInjectionScore = 0
		self.Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection with String Concatenation:<i</h>>")
		blind_str_conc_res = []
		if len(str_value) < 2:
			str_value = "aaa"
		str_value_first_part = str_value[:1]
		str_value_second_part = str_value[1:]
		
		quotes = ["'", '"']
		joiners = [ '||', "+", " "]
		keys = [ "Oracle", "MS SQL", "MySQL"]
		requests = []
		responses = []
		
		for quote in quotes:
			if quote == "'":
				self.Scnr.Trace("<i<br>>  <i<b>>Checking with Single Quotes:<i</b>>")
			else:
				self.Scnr.Trace("<i<br>>  <i<b>>Checking with Double Quotes:<i</b>>")
			
			#variables to keep track of rechecking
			first_strict_signature = ""
			first_relaxed_signature = ""
			second_strict_signature = ""
			second_relaxed_signature = ""
			confidence = 0
			vuln = False
			first_strict_vuln = False
			first_relaxed_vuln = False
			
			for j in range(2):
				if j == 1 and not (first_strict_vuln or first_relaxed_vuln):
					break
				payloads = []
				requests = []
				responses = []
				sc = SimilarityChecker()
				self.Scnr.Trace("<i<br>>")
				for i in range(3):
					payload = "{0}{1}{2}{3}{4}".format(str_value_first_part, quote, joiners[i], quote, str_value_second_part)
					self.Scnr.RequestTrace("  Request Key: '{0}' - Injecting {1}".format(keys[i], payload))
					res = self.Scnr.Inject(payload)
					payloads.append(payload)
					requests.append(self.Scnr.InjectedRequest.GetClone())
					responses.append(res)
					sc.Add(keys[i], res)
					self.Scnr.ResponseTrace(" ==> Code-{0} Length-{1}".format(res.Code, res.BodyLength))
				
				sc.Check()
				
				self.Scnr.Trace("<i<br>>  The responses are analyzed for similarity based grouping to determine if injection succeeded.")
				self.Scnr.Trace("  Analysis Results:")
				self.Scnr.Trace("  Strict Groups Signature: {0}".format(sc.StrictGroupsSignature))
				self.Scnr.Trace("  Relaxed Groups Signature: {0}".format(sc.RelaxedGroupsSignature))

				if j == 0:
					first_strict_signature = sc.StrictGroupsSignature
					first_relaxed_signature = sc.RelaxedGroupsSignature
					
					if self.IsBlindStrConcInjectableGroupingCheck(sc.StrictGroups):
						self.Scnr.Trace("  <i<b>>Strict Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
						if j == 0:
							first_strict_vuln = True
					else:
						self.Scnr.Trace("  Strict Grouping does not indicates that injection succeeded.")
					
					if self.IsBlindStrConcInjectableGroupingCheck(sc.RelaxedGroups):
						self.Scnr.Trace("  <i<b>>Relaxed Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
						if j == 0:
							first_relaxed_vuln = True
					else:
						self.Scnr.Trace("  Relaxed Grouping does not indicates that injection succeeded.")
				else:
					second_strict_signature = sc.StrictGroupsSignature
					second_relaxed_signature = sc.RelaxedGroupsSignature
					vuln = False
					
					if first_strict_vuln and first_strict_signature == second_strict_signature:
						vuln = True
						confidence = confidence + 1
						self.Scnr.Trace("  <i<cr>>Even the second time Strict Grouping indicates that injection succeeded.<i</cr>>")
					else:
						self.Scnr.Trace("  Strict Grouping does not indicate that injection succeeded.")
					
					if first_relaxed_vuln and first_relaxed_signature == second_relaxed_signature:
						vuln = True
						confidence = confidence + 1
						self.Scnr.Trace("  <i<cr>>Even the second time Relaxed Grouping indicates that injection succeeded.<i</cr>>")
					else:
						self.Scnr.Trace("  Relaxed Grouping does not indicate that injection succeeded.")
					
					if vuln:
						self.RequestTriggers.extend(payloads)
						self.TriggerRequests.extend(requests)
						self.TriggerResponses.extend(responses)
						for i in range(len(payloads)):
							self.ResponseTriggers.append("")
						return confidence
		return 0
	
	def IsBlindStrConcInjectableGroupingCheck(self, groups):
		vuln = False
		if len(groups) == 2:
			vuln = True
		return vuln
	
	def InjectBlindBool(self):
		score = 0
		
		self.Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection with Boolean check:<i</h>>")
		
		prefix = self.Scnr.PreInjectionParameterValue
		
		int_trailers = [ "8=8--", "7=5--", "7=7--", "5=8--"]
		char_trailers = [ "<q>s<q>=<q>s", "<q>s<q>=<q>r", "<q>t<q>=<q>t", "<q>t<q>=<q>r"]

		keys = [ "true-a", "false-a", "true-b", "false-b"]
		quotes = [ "'", '"']
		
		self.Scnr.Trace("<i<br>>  <i<b>>Checking with OR Operator:<i</b>>")
		clean_prefix = prefix.replace("'","").replace('"',"")
		or_prefix = clean_prefix + "xxx"#this is to change the prefix to an invalid value to help with OR
		for quote in quotes:
			score = score + self.CheckForBlindBoolWith(or_prefix, quote, "or", int_trailers)
			score = score + self.CheckForBlindBoolWith(or_prefix, quote, "or", char_trailers)
		
		#do one check with a number as prefix without any quotes
		if clean_prefix == "21":
			or_prefix = "22"
		else:
			or_prefix = "21"
		score = score + self.CheckForBlindBoolWith(or_prefix, "", "or", int_trailers)
		
		self.Scnr.Trace("<i<br>>  <i<b>>Checking with AND Operator:<i</b>>")
		for quote in quotes:
			and_prefix = prefix.replace(quote, "")
			score = score + self.CheckForBlindBoolWith(and_prefix, quote, "and", int_trailers)
			score = score + self.CheckForBlindBoolWith(and_prefix, quote, "and", char_trailers)
		
		return score
	
	def CheckForBlindBoolWith(self, prefix, quote, operator, trailers):
		keys = [ "true-a", "false-a", "true-b", "false-b"]
		
		#variables to keep track of rechecking
		first_strict_signature = ""
		first_relaxed_signature = ""
		second_strict_signature = ""
		second_relaxed_signature = ""
		confidence = 0
		vuln = False
		first_strict_vuln = False
		first_relaxed_vuln = False
		
		for j in range(2):
			if j == 1 and not (first_strict_vuln or first_relaxed_vuln):
					break
			payloads = []
			requests = []
			responses = []
			sc = SimilarityChecker()
			self.Scnr.Trace("<i<br>>")
			for i in range(len(trailers)):
				payload = "{0}{1} {2} {3}".format(prefix, quote, operator, trailers[i].replace("<q>", quote))
				self.Scnr.RequestTrace("  Request Key: '{0}' - Injecting {1}".format(keys[i], payload))
				res = self.Scnr.Inject(payload)
				payloads.append(payload)
				requests.append(self.Scnr.InjectedRequest.GetClone())
				responses.append(res)
				sc.Add(keys[i], res)
				self.Scnr.ResponseTrace(" ==> Code-{0} Length-{1}".format(res.Code, res.BodyLength))
			
			sc.Check()
			
			self.Scnr.Trace("<i<br>>  The responses are analyzed for similarity based grouping to determine if injection succeeded.")
			self.Scnr.Trace("  Analysis Results:")
			self.Scnr.Trace("  Strict Groups Signature: {0}".format(sc.StrictGroupsSignature))
			self.Scnr.Trace("  Relaxed Groups Signature: {0}".format(sc.RelaxedGroupsSignature))
	
			if j == 0:				
				first_strict_signature = sc.StrictGroupsSignature
				first_relaxed_signature = sc.RelaxedGroupsSignature
				
				if self.IsBlindBoolInjectableGroupingCheck(sc.StrictGroups):
					self.Scnr.Trace("  <i<b>>Strict Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
					if j == 0:
						first_strict_vuln = True
				else:
					self.Scnr.Trace("  Strict Grouping does not indicates that injection succeeded.")
				
				if self.IsBlindBoolInjectableGroupingCheck(sc.RelaxedGroups):
					self.Scnr.Trace("  <i<b>>Relaxed Grouping indicates that injection succeeded. Rechecking to confirm.<i</b>>")
					if j == 0:
						first_relaxed_vuln = True
				else:
					self.Scnr.Trace("  Relaxed Grouping does not indicates that injection succeeded.")
			else:
				second_strict_signature = sc.StrictGroupsSignature
				second_relaxed_signature = sc.RelaxedGroupsSignature
				vuln = False
				
				if first_strict_vuln and first_strict_signature == second_strict_signature:
					vuln = True
					confidence = confidence + 1
					self.Scnr.Trace("  <i<cr>>Even the second time Strict Grouping indicates that injection succeeded.<i</cr>>")
				else:
					self.Scnr.Trace("  Strict Grouping does not indicate that injection succeeded.")
				
				if first_relaxed_vuln and first_relaxed_signature == second_relaxed_signature:
					vuln = True
					confidence = confidence + 1
					self.Scnr.Trace("  <i<cr>>Even the second time Relaxed Grouping indicates that injection succeeded.<i</cr>>")
				else:
					self.Scnr.Trace("  Relaxed Grouping does not indicate that injection succeeded.")
				
				if vuln:
					self.RequestTriggers.extend(payloads)
					self.TriggerRequests.extend(requests)
					self.TriggerResponses.extend(responses)
					for i in range(len(payloads)):
						self.ResponseTriggers.append("")
					return confidence
		return 0
	
	def IsBlindBoolInjectableGroupingCheck(self, groups):
		match = 0
		if len(groups) == 2:
			for group in groups:
				if group.Count == 2:
					match = 0
					if group.HasKey("true-a") and group.HasKey("true-b"):
						match = 1
					elif group.HasKey("false-a") and group.HasKey("false-b"):
						match = 1
		
		if match > 0:
			return True
		else:
			return False
	
	def CheckBlindTime(self):
		score = 0
		self.Scnr.Trace("<i<br>><i<h>>Checking for Time based Injection:<i</h>>")
		self.Scnr.Trace("<i<br>> Sending three requests to get a baseline of the response time for time based check:")
		min_delay = -1
		max_delay = 0
		time = 10000
		base_line_delays = []
		for i in range(3):
			res = self.Scnr.Inject()
			base_line_delays.append("  {0}) Response time is - {1} ms".format(i+1, res.RoundTrip))
			if res.RoundTrip > max_delay:
				max_delay = res.RoundTrip
			if res.RoundTrip < min_delay or min_delay == -1:
				min_delay = res.RoundTrip

		self.Scnr.Trace("<i<br>>".join(base_line_delays))
		
		if min_delay > 5000:
			time = ((max_delay + min_delay) / 1000) + 1
		else:
			time = ((max_delay + 5000) / 1000) + 1
		
		self.Scnr.Trace("<i<br>> Response Times: Minimum - {0}ms. Maximum - {1}ms.".format(min_delay, max_delay))

		self.Scnr.Trace("<i<br>> <i<b>>Testing with delay time of {0}ms.<i</b>>".format(time * 1000))
		for inj_str in self.time_check:
			payload = inj_str.replace("__TIME__", str(time))
			score = score + self.InjectAndCheckBlindDelay(payload, time)
		
		return score
	
	def InjectAndCheckBlindDelay(self, payload, time):
		for i in range(2):
			self.Scnr.RequestTrace("  Injecting {0}".format(payload))
			res = self.Scnr.Inject(payload)
			res_trace = "	==> Code-{0} Length-{1} Time-{2}ms.".format(res.Code, res.BodyLength, res.RoundTrip)
			if i == 0:
				if res.RoundTrip >= (time * 1000):
					self.Scnr.ResponseTrace("{0} <i<b>>Delay Observed! Rechecking the result with the same Injection string<i</b>>".format(res_trace))
				else:
					self.Scnr.ResponseTrace("{0} No Time Delay.".format(res_trace))
					break
			elif i == 1:
				if res.RoundTrip >= (time * 1000):
					self.Scnr.ResponseTrace("{0} <i<br>><i<cr>>Delay Observed Again! Indicates Presence of SQL Injection<i</cr>>".format(res_trace))
					self.RequestTriggers.append(payload)
					self.TriggerRequests.append(self.Scnr.InjectedRequest.GetClone())
					self.TriggerResponses.append(res)
					self.ResponseTriggers.append("")
					#self.ReportSQLInjection()
					return 1
				else:
					self.Scnr.ResponseTrace("{0} <i<b>>Time Delay did not occur again!<i</b>>".format(res_trace))
		
		return 0
	
	def ReportSQLInjection(self, Confidence):
		PR = PluginResult(self.Scnr.InjectedRequest.Host)
		PR.Title = "SQL Injection Detected"
		PR.Summary = "SQL Injection has been detected in the '{0}' parameter of the {1} section of the request   <i<br>><i<br>><i<hh>>Test Trace:<i</hh>>{2}".format(self.Scnr.InjectedParameter, self.Scnr.InjectedSection, self.Scnr.GetTrace())
		for i in range(len(self.RequestTriggers)):
			PR.Triggers.Add(self.RequestTriggers[i],self.TriggerRequests[i],self.ResponseTriggers[i],self.TriggerResponses[i])
		PR.ResultType = PluginResultType.Vulnerability
		PR.Severity = PluginResultSeverity.High
		PR.Confidence = Confidence
		self.Scnr.AddResult(PR)
		self.Scnr.LogTrace("SQLi Found")
	
	def SetUp(self):
		err_regex_file = open(Config.Path + "\\plugins\\active\\sql_error_regex.txt")
		err_regex_file.readline()#Ignore the first line containing comments
		error_strings = err_regex_file.readlines()
		err_regex_file.close()
		for err_str in error_strings:
			err_str = err_str.strip()
			if len(err_str) > 0:
				self.error_regex_raw.append(err_str)
				self.error_regex.append(re.compile(err_str, re.I))
		time_check_file = open(Config.Path + "\\plugins\\active\\sql_time_check.txt")
		time_check_file.readline()#Ignore the first line containing comments
		time_check_temp = time_check_file.readlines()
		time_check_file.close()
		for tct in time_check_temp:
			tct = tct.strip()
			if len(tct) > 0:
				self.time_check.append(tct)

p = SQLInjection()
p.SetUp()
ActivePlugin.Add(p.GetInstance())
