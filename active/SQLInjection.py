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
	
	#Override the Check method of the base class with custom functionlity
	def Check(self, Req, Scnr):
		self.SetUpThreadVariables()
		ThreadStore.Put("Scanner",Scnr)
		Scnr.StartTrace()
		
		Scnr.Trace("<i<br>><i<h>>Getting a baseline response:\n<i</h>>")
		base_res_random_str = Tools.GetRandomString(3,4)
		Scnr.RequestTrace("	Injected random string - " + base_res_random_str)
		base_response = Scnr.Inject(base_res_random_str)
		Scnr.ResponseTrace(" ==> Code-" + str(base_response.Code) + " Length-" + str(base_response.BodyLength))
		ThreadStore.Put("base_response",base_response)
		#Scnr.Trace("<i<br>><i<h>>Baseline Response Details:\n<i</h>>")
		#Scnr.Trace("	Code -" + str(Scnr.BaseResponse.Code) + " Length -" + str(Scnr.BaseResponse.BodyLength))
		#ThreadStore.Put("base_response", Scnr.BaseResponse)
		
		overall_error_score = self.CheckForErrorBasedSQLi(Req, Scnr)
		overall_blind_score = self.CheckForBlindSQLi(Req, Scnr)
		
		overall_score = overall_error_score + overall_blind_score
		
		if(overall_score > 7):
			self.ReportSQLInjection(PluginResultConfidence.High)
		elif(overall_score > 4):
			self.ReportSQLInjection(PluginResultConfidence.Medium)
		elif(overall_score > 3):
			self.ReportSQLInjection(PluginResultConfidence.Low)
		else:
			Scnr.LogTrace(ThreadStore.Get("TraceTitle"))
		#overall_blind_score = self.CheckForBlindSQLi(Request, Scanner)
		#overall_score = overall_error_score + overall_blind_score
		#if(overall_score == 0):
		#	return

	def CheckForErrorBasedSQLi(self, Req, Scnr):
		Scnr.Trace("<i<br>><i<h>>Checking for Error based Injection:\n<i</h>>")
		payload_responses = []
		payloads = ["'","\"","\xBF'\"(","(",")"]
		final_error_score = 0
		for payload in payloads:
			Scnr.RequestTrace("  Injected " + payload + " - ")
			inj_res = Scnr.Inject(payload)
			score = self.AnalyseInjectionResultForError(payload, inj_res)
			if score > final_error_score:
				final_error_score = score
		return final_error_score
		
	def AnalyseInjectionResultForError(self, payload, payload_response):
		Scnr = ThreadStore.Get("Scanner")
		base_response = ThreadStore.Get("base_response")
		res = payload_response
		diff_error_no = False#do base response and injeted response have different number of error matches
		triggers = []
		all_error_matches = {}
		
		res_code_score = 0
		
		if res.Code != base_response.Code :
			self.SetTraceTitle("Response Code(" + str(res.Code) + ") varies from baseline")
		
		#check if the response is a 500
		if(base_response.Code < 500):
			if(res.Code > 499):
				Scnr.ResponseTrace("<i<cr>>Injection Response Code - " + str(res.Code) + " . Normal Response Code - " + str(base_response.Code) + "<i</cr>>")
				res_code_score = 3
		
		#check if the response status is different than the baseline status, ignore 404s
		if(res_code_score == 0):
			if(res.Code != base_response.Code and (res.Code < 400 or  res.Code > 499)):
				res_code_score = 1
				Scnr.ResponseTrace("<i<cr>>Injection Response Code - " + str(res.Code) + " . Normal Response Code - " + str(base_response.Code) + "<i</cr>>")
			else:
				Scnr.ResponseTrace("Injection Response Code - " + str(res.Code) + " . Normal Response Code - " + str(base_response.Code))
				
		error_score = 0
		for i in range(len(self.error_regex)):
			error_re = self.error_regex[i]
			error_re_raw = self.error_regex_raw[i]
			matches = error_re.findall(res.BodyString)
			if(len(matches) > 0):
				original_error_matches = error_re.findall(base_response.BodyString)
				all_error_matches[error_re_raw] = [len(matches),len(original_error_matches)]
				triggers.extend(matches)
				if(len(matches) != len(original_error_matches)):
					diff_error_no = True
		
		if(len(all_error_matches) > 0):
			for error_key,(inj_matches,base_matches) in all_error_matches.items():
				Scnr.Trace("	    <i<cr>>Got " + str(inj_matches) + " occurance[s] of error signature. Normal Response Had " + str(base_matches) + " occurance[s]<i</cr>>. <i<b>>Error Signature:<i</b>> " + error_key)
				if diff_error_no:
					error_score = 7
				else:
					error_score = 4
		else:
			Scnr.Trace("	    No errors")
		
		if(error_score > 0):
			self.AddToTriggers(payload, "\r\n".join(triggers))
		elif(res_code_score > 0):
			self.AddToTriggers(payload, str(res.Code) + " " + res.Status)
		
		return (error_score + res_code_score)

		
	def CheckForBlindSQLi(self, Req, Scnr):
		Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection:\n<i</h>>")
		is_int = False
		int_value = 0
		str_value = ""
		str_value = Scnr.PreInjectionParameterValue
		try:
			int_value = int(Scnr.PreInjectionParameterValue)
			is_int = True
		except:
			pass
		Scnr.Trace("<i<br>><i<h>>Getting a baseline DiffLevel in three responses for same paramter value:\n<i</h>>")
		Scnr.RequestTrace("  Sending first request(A) ")
		first_normal_response = Scnr.Inject(Scnr.PreInjectionParameterValue)
		Scnr.ResponseTrace(" ==> Code-" + str(first_normal_response.Code) + " Length-" + str(first_normal_response.BodyLength))
		Scnr.RequestTrace("  Sending second request(B)")
		second_normal_response = Scnr.Inject(Scnr.PreInjectionParameterValue)
		Scnr.ResponseTrace(" ==> Code-" + str(first_normal_response.Code) + " Length-" + str(first_normal_response.BodyLength))
		Scnr.RequestTrace("  Sending first request(A) ")
		first_normal_response = Scnr.Inject(Scnr.PreInjectionParameterValue)
		Scnr.ResponseTrace(" ==> Code-" + str(first_normal_response.Code) + " Length-" + str(first_normal_response.BodyLength))
		Scnr.RequestTrace("  Sending third request(C)")
		third_normal_response = Scnr.Inject(Scnr.PreInjectionParameterValue)
		Scnr.ResponseTrace(" ==> Code-" + str(first_normal_response.Code) + " Length-" + str(first_normal_response.BodyLength))
		
		avg_round_trip = (first_normal_response.RoundTrip + second_normal_response.RoundTrip + third_normal_response.RoundTrip)/3
		
		ab_diff_level = Tools.DiffLevel(first_normal_response.BodyString, second_normal_response.BodyString)
		bc_diff_level = Tools.DiffLevel(second_normal_response.BodyString, third_normal_response.BodyString)
		ac_diff_level = Tools.DiffLevel(first_normal_response.BodyString, third_normal_response.BodyString)
		
		lowest_diff_level = 0
		highest_diff_level = 0
		
		if ab_diff_level <= bc_diff_level and ab_diff_level <= ac_diff_level:
			lowest_diff_level = ab_diff_level
		elif bc_diff_level <= ab_diff_level and bc_diff_level <= ac_diff_level:
			lowest_diff_level = bc_diff_level
		elif ac_diff_level <= ab_diff_level and ac_diff_level <= bc_diff_level:
			lowest_diff_level = ac_diff_level
		
		if ab_diff_level >= bc_diff_level and ab_diff_level >= ac_diff_level:
			highest_diff_level = ab_diff_level
		elif bc_diff_level >= ab_diff_level and bc_diff_level >= ac_diff_level:
			highest_diff_level = bc_diff_level
		elif ac_diff_level >= ab_diff_level and ac_diff_level >= bc_diff_level:
			highest_diff_level = ac_diff_level
		
		Scnr.Trace("<i<br>><i<b>>Diff Levels: AB- " + str(ab_diff_level) + "% BC- " + str(bc_diff_level) + "% AC- " + str(ac_diff_level) + "%<i</b>>")
		
		blind_int_math_score = 0
		blind_str_conc_score = 0
		blind_bool_score = 0
		blind_time_score = 0
		
		if is_int:
			blind_int_math_score = self.InjectBlindIntMath(Req, Scnr, int_value, first_normal_response, lowest_diff_level, highest_diff_level)
			
		if len(str_value) > 1:
			blind_str_conc_score = self.InjectBlindStrConc(Req, Scnr, str_value, first_normal_response, lowest_diff_level, highest_diff_level)
		
		blind_bool_score = self.InjectBlindBool(Req, Scnr, str_value, first_normal_response, lowest_diff_level, highest_diff_level)
		
		if self.CanDoTimeBasedCheck(Req, Scnr, str_value, first_normal_response, lowest_diff_level, highest_diff_level):
			blind_time_score = self.InjectBlindTime(Req, Scnr, str_value, avg_round_trip)
		
		if blind_int_math_score  + blind_str_conc_score + blind_bool_score + blind_time_score > 0:
			return 6
		else:
			return 0
		
		#blind_math_score = self.AnalyzeBlindMathResults(blind_int_math_res)
		#blind_conc_score = self.AnalyzeBlindConcResults(blind_str_conc_res)
		#return blind_math_score + blind_conc_score
		
	def InjectBlindIntMath(self, Req, Scnr, int_value, first_normal_response, lowest_diff_level, highest_diff_level):
		Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection with Integer Math:\n<i</h>>")
		#blind_int_math_res = []
		
		Scnr.RequestTrace("  Injecting " + str(int_value + 1) + "-1")
		minus_actual_res = Scnr.Inject(str(int_value + 1) + "-1")
		Scnr.ResponseTrace(" ==> Code-" + str(minus_actual_res.Code) + " Length-" + str(minus_actual_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, minus_actual_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response. Abandoning this check.")
			return 0
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response. Continuing this check.")
		#blind_int_math.append(minus_actual_res)
		
		Scnr.RequestTrace("  Injecting " + str(int_value) + "+2")
		plus_inj_res = Scnr.Inject(str(int_value) + "+2")
		Scnr.ResponseTrace(" ==> Code-" + str(plus_inj_res.Code) + " Length-" + str(plus_inj_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, plus_inj_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	<i<cr>>Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response. Indicates SQL Injection<i</cr>>")
			return 6
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response. Check failed")
			return 0
		#blind_int_math.append(plus_inj_res)
		
		#return blind_int_math_res
		
	def InjectBlindStrConc(self, Req, Scnr, str_value, first_normal_response, lowest_diff_level, highest_diff_level):
		BlindConcInjectionScore = 0
		Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection with String Concatenation:\n<i</h>>")
		blind_str_conc_res = []
		str_value_first_part = str_value[1:]
		str_value_second_part = str_value[:1]
		
		Scnr.RequestTrace("  Injecting " + str_value_first_part + "'||'" + str_value_second_part)
		conc_ora_res = Scnr.Inject(str_value_first_part + "'||'" + str_value_second_part)
		Scnr.ResponseTrace(" ==> Code-" + str(conc_ora_res.Code) + " Length-" + str(conc_ora_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, conc_ora_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
			BlindConcInjectionScore = BlindConcInjectionScore + 1
		
		Scnr.RequestTrace("  Injecting " + str_value_first_part + "'%2b'" + str_value_second_part)
		conc_mssql_res = Scnr.Inject(str_value_first_part + "'%2b'" + str_value_second_part)
		Scnr.ResponseTrace(" ==> Code-" + str(conc_mssql_res.Code) + " Length-" + str(conc_mssql_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, conc_mssql_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
			BlindConcInjectionScore = BlindConcInjectionScore + 1
		
		Scnr.RequestTrace("  Injecting " + str_value_first_part + "'%20'" + str_value_second_part)
		conc_mysql_res = Scnr.Inject(str_value_first_part + "'%20'" + str_value_second_part)
		Scnr.ResponseTrace(" ==> Code-" + str(conc_mysql_res.Code) + " Length-" + str(conc_mysql_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, conc_mysql_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
			BlindConcInjectionScore = BlindConcInjectionScore + 1
		
		if BlindConcInjectionScore  == 1:
			Scnr.Trace("	<i<cr>>Only one out of the three responses matches with normal response. Indicates SQL Injection.<i</cr>>")
			return 6
		
		BlindConcInjectionScore = 0
		
		Scnr.RequestTrace("  Injecting " + str_value_first_part + '"||"' + str_value_second_part)
		conc_ora_res = Scnr.Inject(str_value_first_part + '"||"' + str_value_second_part)
		Scnr.ResponseTrace(" ==> Code-" + str(conc_ora_res.Code) + " Length-" + str(conc_ora_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, conc_ora_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
			BlindConcInjectionScore = BlindConcInjectionScore + 1
		
		Scnr.RequestTrace("  Injecting " + str_value_first_part + '"%2b"' + str_value_second_part)
		conc_mssql_res = Scnr.Inject(str_value_first_part + '"%2b"' + str_value_second_part)
		Scnr.ResponseTrace(" ==> Code-" + str(conc_mssql_res.Code) + " Length-" + str(conc_mssql_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, conc_mssql_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
			BlindConcInjectionScore = BlindConcInjectionScore + 1
		
		Scnr.RequestTrace("  Injecting " + str_value_first_part + '"%20"' + str_value_second_part)
		conc_mysql_res = Scnr.Inject(str_value_first_part + '"%20"' + str_value_second_part)
		Scnr.ResponseTrace(" ==> Code-" + str(conc_mysql_res.Code) + " Length-" + str(conc_mysql_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, conc_mysql_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
			BlindConcInjectionScore = BlindConcInjectionScore + 1
		
		if BlindConcInjectionScore  == 1:
			Scnr.Trace("	<i<cr>>Only one out of the three responses matches with normal response. Indicates SQL Injection<i</cr>>")
			return 6
		else:
			Scnr.Trace("	More or less than one out of the three responses matches with normal response. Check failed.")
			return 0
		
	def InjectBlindBool(self, Req, Scnr, str_value, first_normal_response, lowest_diff_level, highest_diff_level):
		BlindBoolInjectionScore = 0
		Scnr.Trace("<i<br>><i<h>>Checking for Blind Injection with Boolean check:\n<i</h>>")

		Scnr.RequestTrace("  Injecting " + str_value + "' or 1=1--")
		f_res = Scnr.Inject(str_value + "' or 1=1--")
		Scnr.ResponseTrace(" ==> Code-" + str(f_res.Code) + " Length-" + str(f_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, f_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			Scnr.RequestTrace("  Injecting " + str_value + "' or 1=2--")
			s_res = Scnr.Inject(str_value + "' or 1=2--")
			Scnr.ResponseTrace(" ==> Code-" + str(s_res.Code) + " Length-" + str(s_res.BodyLength))
			diff_level = Tools.DiffLevel(first_normal_response.BodyString, s_res.BodyString)
			if diff_level < lowest_diff_level or diff_level > highest_diff_level:
				Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			else:
				self.AddToTriggers(str_value + "' or 1=2--", "")
				Scnr.Trace("	<i<cr>>Diff Level with A -" + str(diff_level) + "% and Matches with the normal response indicating SQL Injection<i</cr>><i<br>>")
				return 6
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
		
		Scnr.RequestTrace("  Injecting " + str_value + "' or 'a'='a")
		f_res = Scnr.Inject(str_value + "' or 'a'='a")
		Scnr.ResponseTrace(" ==> Code-" + str(f_res.Code) + " Length-" + str(f_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, f_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			Scnr.RequestTrace("  Injecting " + str_value + "' or 'a'='b")
			s_res = Scnr.Inject(str_value + "' or 'a'='b")
			Scnr.ResponseTrace(" ==> Code-" + str(s_res.Code) + " Length-" + str(s_res.BodyLength))
			diff_level = Tools.DiffLevel(first_normal_response.BodyString, s_res.BodyString)
			if diff_level < lowest_diff_level or diff_level > highest_diff_level:
				Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			else:
				self.AddToTriggers(str_value + "' or 'a'='b", "")
				Scnr.Trace("	<i<cr>>Diff Level with A -" + str(diff_level) + "% and Matches with the normal response indicating SQL Injection<i</cr>><i<br>>")
				return 6
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
		
		Scnr.RequestTrace("  Injecting " + str_value + '" or 1=1--')
		f_res = Scnr.Inject(str_value + '" or 1=1--')
		Scnr.ResponseTrace(" ==> Code-" + str(f_res.Code) + " Length-" + str(f_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, f_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			Scnr.RequestTrace("  Injecting " + str_value + '" or 1=2--')
			s_res = Scnr.Inject(str_value + '" or 1=2--')
			Scnr.ResponseTrace(" ==> Code-" + str(s_res.Code) + " Length-" + str(s_res.BodyLength))
			diff_level = Tools.DiffLevel(first_normal_response.BodyString, s_res.BodyString)
			if diff_level < lowest_diff_level or diff_level > highest_diff_level:
				Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			else:
				self.AddToTriggers(str_value + '" or 1=2--', "")
				Scnr.Trace("	<i<cr>>Diff Level with A -" + str(diff_level) + "% and Matches with the normal response indicating SQL Injection<i</cr>><i<br>>")
				return 6
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
		
		Scnr.RequestTrace("  Injecting " + str_value + '" or "a"="a')
		f_res = Scnr.Inject(str_value + '" or "a"="a')
		Scnr.ResponseTrace(" ==> Code-" + str(f_res.Code) + " Length-" + str(f_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, f_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			Scnr.RequestTrace("  Injecting " + str_value + '" or "a"="b')
			s_res = Scnr.Inject(str_value + '" or "a"="b')
			Scnr.ResponseTrace(" ==> Code-" + str(s_res.Code) + " Length-" + str(s_res.BodyLength))
			diff_level = Tools.DiffLevel(first_normal_response.BodyString, s_res.BodyString)
			if diff_level < lowest_diff_level or diff_level > highest_diff_level:
				Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			else:
				self.AddToTriggers(str_value + '" or "a"="b', "")
				Scnr.Trace("	<i<cr>>Diff Level with A -" + str(diff_level) + "% and Matches with the normal response indicating SQL Injection<i</cr>><i<br>>")
				return 6
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
		
		Scnr.RequestTrace("  Injecting " + str_value + "' and 1=2--")
		f_res = Scnr.Inject(str_value + "' or 1=2--")
		Scnr.ResponseTrace(" ==> Code-" + str(f_res.Code) + " Length-" + str(f_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, f_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			Scnr.RequestTrace("  Injecting " + str_value + "' or 1=1--")
			s_res = Scnr.Inject(str_value + "' or 1=1--")
			Scnr.ResponseTrace(" ==> Code-" + str(s_res.Code) + " Length-" + str(s_res.BodyLength))
			diff_level = Tools.DiffLevel(first_normal_response.BodyString, s_res.BodyString)
			if diff_level < lowest_diff_level or diff_level > highest_diff_level:
				Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			else:
				self.AddToTriggers(str_value + "' or 1=1--", "")
				Scnr.Trace("	<i<cr>>Diff Level with A -" + str(diff_level) + "% and Matches with the normal response indicating SQL Injection<i</cr>><i<br>>")
				return 6
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
		
		Scnr.RequestTrace("  Injecting " + str_value + "' or 'a'='b")
		f_res = Scnr.Inject(str_value + "' or 'a'='b")
		Scnr.ResponseTrace(" ==> Code-" + str(f_res.Code) + " Length-" + str(f_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, f_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			Scnr.RequestTrace("  Injecting " + str_value + "' or 'a'='a")
			s_res = Scnr.Inject(str_value + "' or 'a'='a")
			Scnr.ResponseTrace(" ==> Code-" + str(s_res.Code) + " Length-" + str(s_res.BodyLength))
			diff_level = Tools.DiffLevel(first_normal_response.BodyString, s_res.BodyString)
			if diff_level < lowest_diff_level or diff_level > highest_diff_level:
				Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			else:
				self.AddToTriggers(str_value + "' or 'a'='a", "")
				Scnr.Trace("	<i<cr>>Diff Level with A -" + str(diff_level) + "% and Matches with the normal response indicating SQL Injection<i</cr>><i<br>>")
				return 6
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
		
		Scnr.RequestTrace("  Injecting " + str_value + '" or 1=2--')
		f_res = Scnr.Inject(str_value + '" or 1=2--')
		Scnr.ResponseTrace(" ==> Code-" + str(f_res.Code) + " Length-" + str(f_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, f_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			Scnr.RequestTrace("  Injecting " + str_value + '" or 1=1--')
			s_res = Scnr.Inject(str_value + '" or 1=1--')
			Scnr.ResponseTrace(" ==> Code-" + str(s_res.Code) + " Length-" + str(s_res.BodyLength))
			diff_level = Tools.DiffLevel(first_normal_response.BodyString, s_res.BodyString)
			if diff_level < lowest_diff_level or diff_level > highest_diff_level:
				Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			else:
				self.AddToTriggers(str_value + '" or 1=1--', "")
				Scnr.Trace("	<i<cr>>Diff Level with A -" + str(diff_level) + "% and Matches with the normal response indicating SQL Injection<i</cr>><i<br>>")
				return 6
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
		
		Scnr.RequestTrace("  Injecting " + str_value + '" or "a"="b')
		f_res = Scnr.Inject(str_value + '" or "a"="b')
		Scnr.ResponseTrace(" ==> Code-" + str(f_res.Code) + " Length-" + str(f_res.BodyLength))
		diff_level = Tools.DiffLevel(first_normal_response.BodyString, f_res.BodyString)
		if diff_level < lowest_diff_level or diff_level > highest_diff_level:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			Scnr.RequestTrace("  Injecting " + str_value + '" or "a"="a')
			s_res = Scnr.Inject(str_value + '" or "a"="a')
			Scnr.ResponseTrace(" ==> Code-" + str(s_res.Code) + " Length-" + str(s_res.BodyLength))
			diff_level = Tools.DiffLevel(first_normal_response.BodyString, s_res.BodyString)
			if diff_level < lowest_diff_level or diff_level > highest_diff_level:
				Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so does not match with the normal response.")
			else:
				self.AddToTriggers(str_value + '" or "a"="a', "")
				Scnr.Trace("	<i<cr>>Diff Level with A -" + str(diff_level) + "% and Matches with the normal response indicating SQL Injection<i</cr>><i<br>>")
				return 6
		else:
			Scnr.Trace("	Diff Level with A -" + str(diff_level) + "% and so is matching with the normal response.")
		
		return 0
	
	#Based on http://lcamtuf.blogspot.com/2010/11/understanding-and-using-skipfish.html
	#Time-based check requires sending lot of requests so this a crude check to see if there are any indications of SQL Injection behaviour to decide if time-based check needs to be done
	def CanDoTimeBasedCheck(self, Req, Scnr, str_value, first_normal_response, lowest_diff_level, highest_diff_level):
		Scnr.Trace("<i<br>><i<h>>Checking for Time Based Check Eligibility:\n<i</h>>")

		Scnr.RequestTrace("  Injecting " + "'" + '"' + str_value)
		f_res = Scnr.Inject("'" + '"' + str_value)
		Scnr.ResponseTrace(" ==> Code-" + str(f_res.Code) + " Length-" + str(f_res.BodyLength))
		
		Scnr.RequestTrace("  Injecting " + "\\'" + '\\"' + str_value)
		s_res = Scnr.Inject("\\'" + '\\"' + str_value)
		Scnr.ResponseTrace(" ==> Code-" + str(s_res.Code) + " Length-" + str(s_res.BodyLength))
		
		Scnr.RequestTrace("  Injecting " + "\\\\'" + '\\\\"' + str_value)
		t_res = Scnr.Inject( "\\\\'" + '\\\\"' + str_value)
		Scnr.ResponseTrace(" ==> Code-" + str(t_res.Code) + " Length-" + str(t_res.BodyLength))
		
		ft_diff_level = Tools.DiffLevel(f_res.BodyString, t_res.BodyString)
		fs_diff_level = Tools.DiffLevel(f_res.BodyString, s_res.BodyString)
		st_diff_level = Tools.DiffLevel(s_res.BodyString, t_res.BodyString)
		
		if ft_diff_level < lowest_diff_level or ft_diff_level > highest_diff_level:
			return False
		else:
			if (fs_diff_level < lowest_diff_level or fs_diff_level > highest_diff_level) and (st_diff_level < lowest_diff_level or st_diff_level > highest_diff_level):
				return True
			else:
				return False
	
	def InjectBlindTime(self, Req, Scnr, avg_round_trip):
		time = avg_round_trip * 4
		time_str = str(time)
		Scnr.Trace("<i<br>><i<h>>Checking for Time based Injection:<i</h>>")
		Scnr.Trace("	Testing with delay time of " + str(time) + "ms. Average response time is " + str(avg_round_trip) + "ms")
		for inj_str in time_check:
			res = Scnr.Inject(inj_str.replace("__TIME__",time_str))
			if res.RoundTrip > time:
				Scnr.Trace("	Observed a time delay of " + str(res.RoundTrip) + "ms. Rechecking the result with the same Injection string...")
				Scnr.RequestTrace("  Injecting " + inj_str.replace("__TIME__",time_str))
				res = Scnr.Inject(inj_str.replace("__TIME__",time_str))
				Scnr.ResponseTrace(" ==> Code-" + str(s_res.Code) + " Length-" + str(s_res.BodyLength))
				if res.RoundTrip > time:
					self.AddToTriggers(inj_str.replace("__TIME__",time_str), "")
					Scnr.Trace("	<i<cr>>Time delay observed again. Delay of " + str(res.RoundTrip) + "ms. Indicates SQL Injection<i</cr>>")
					return 6
				else:
					Scnr.Trace("	Time delay did not reoccur. Got a response time of " + str(res.RoundTrip) + "ms")
				Scnr.Trace("	No time delays were observed and so there is no indication of SQL Injection")
		return 0
	
	def ReportSQLInjection(self, Confidence):
		Scnr = ThreadStore.Get("Scanner")
		TestTrace = ThreadStore.Get("TestTrace")
		RequestTriggers = ThreadStore.Get("RequestTriggers")
		ResponseTriggers = ThreadStore.Get("ResponseTriggers")
		TriggerRequests = ThreadStore.Get("TriggerRequests")
		TriggerResponses = ThreadStore.Get("TriggerResponses")

		PR = PluginResult(Scnr.InjectedRequest.Host)
		PR.Title = "SQL Injection Detected"
		PR.Summary = "SQL Injection has been detected in the '" + Scnr.InjectedParameter + "' parameter of the " + Scnr.InjectedSection + " section of the request   <i<br>><i<br>><i<hh>>Test Trace:<i</hh>>" + Scnr.GetTrace()
		for i in range(len(RequestTriggers)):
			PR.Triggers.Add(RequestTriggers[i],TriggerRequests[i],ResponseTriggers[i],TriggerResponses[i])
		PR.ResultType = PluginResultType.Vulnerability
		PR.Severity = PluginResultSeverity.High
		PR.Confidence = Confidence
		Scnr.AddResult(PR)
		Scnr.LogTrace("SQLi Found")
	  
	def AddTestTrace(self, TraceMessage):
		TestTrace = ThreadStore.Get("TestTrace")
		TestTrace += TraceMessage
		ThreadStore.Put("TestTrace",TestTrace)
	
	def AddToTriggers(self, RequestTrigger, ResponseTrigger):
		Scnr = ThreadStore.Get("Scanner")
		RequestTriggers = ThreadStore.Get("RequestTriggers")
		ResponseTriggers = ThreadStore.Get("ResponseTriggers")
		TriggerRequests = ThreadStore.Get("TriggerRequests")
		TriggerResponses = ThreadStore.Get("TriggerResponses")
		RequestTriggers.append(RequestTrigger)
		ResponseTriggers.append(ResponseTrigger)
		TriggerRequests.append(Scnr.InjectedRequest.GetClone())
		TriggerResponses.append(Scnr.InjectionResponse.GetClone())
	
	def SetTraceTitle(self, Title):
		ThreadStore.Put("TraceTitle",Title)
	
	def SetUpThreadVariables(self):
		RequestTriggers = []
		ResponseTriggers = []
		TriggerRequests = []
		TriggerResponses = []
		ThreadStore.Put("RequestTriggers",RequestTriggers)
		ThreadStore.Put("ResponseTriggers",ResponseTriggers)
		ThreadStore.Put("TriggerRequests",TriggerRequests)
		ThreadStore.Put("TriggerResponses",TriggerResponses)
		
		ThreadStore.Put("TraceTitle","-")
		
		Confidence = 0
		ThreadStore.Put("Confidence",Confidence)
	
	def SetUp(self):
		err_regex_file = open(Config.Path + "\\plugins\\active\\sql_error_regex.txt")
		err_regex_file.readline()#Ignore the first line containing comments
		error_strings = err_regex_file.readlines()
		err_regex_file.close()
		for err_str in error_strings:
			self.error_regex_raw.append(err_str.strip())
			self.error_regex.append(re.compile(err_str.strip(), re.I))
		time_check_file = open(Config.Path + "\\plugins\\active\\sql_time_check.txt")
		time_check_file.readline()#Ignore the first line containing comments
		time_check_temp = time_check_file.readlines()
		time_check_file.close()
		for tct in time_check_temp:
			self.time_check.append(tct.strip())

p = SQLInjection()
p.SetUp()
p.Name = "SQLi"
p.Description = "Plugin to discover SQL Injection vulnerabilities"
p.Version = "0.1"
ActivePlugin.Add(p)
