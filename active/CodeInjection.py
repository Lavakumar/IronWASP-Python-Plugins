#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
from System import *
import clr
import re


#Inherit from the base ActivePlugin class
class CodeInjection(ActivePlugin):
  def GetInstance(self):
    p = CodeInjection()
    p.Name = "Code Injection"
    p.Description = "Active Plugin to check for CodeInjection vulnerability"
    p.Version = "0.3"
    return p
  
  #Check logic based on https://github.com/Zapotek/arachni/blob/master/modules/audit/code_injection.rb of the Arachni project
  #Override the Check method of the base class with custom functionlity
  def Check(self, scnr):
    self.scnr = scnr
    self.RequestTriggers = []
    self.ResponseTriggers = []
    self.TriggerRequests = []
    self.TriggerResponses = []
    self.TriggerCount = 0
    self.reasons = []
    self.CheckForCodeInjection()
  
  def CheckForCodeInjection(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for Code Injection:<i</h>>")
    self.CheckForEchoBasedCodeInjection()
    self.CheckForTimeBasedCodeInjection()
    self.AnalyzeTestResult()
  
  def CheckForEchoBasedCodeInjection(self):
    #lang_order [php, perl, pyton, asp, ruby]
    functions = ['echo <add_str>;', 'print <add_str>;', 'print <add_str>', 'Response.Write(<add_str>)', "puts <add_str>"]
    comments = ["#", "#", "#", "'", "#"]
    prefixes = ["", ";", "';", '";']
    
    add_num_1 = 0
    add_num_2 = 0
    base_res = self.scnr.BaseResponse
    found_rand_nums = False
    while(not found_rand_nums):
      add_num_1 = Tools.GetRandomNumber(1000000, 10000000)
      add_num_2 = Tools.GetRandomNumber(1000000, 10000000)
      if base_res.BodyString.count(str(add_num_1 + add_num_2)) == 0:
        found_rand_nums = True
    
    add_str = "{0}+{1}".format(str(add_num_1), str(add_num_2))
    added_str = str(add_num_1 + add_num_2)
    
    self.scnr.Trace("<i<br>><i<h>>Checking for Echo based Code Injection:<i</h>>")
    for i in range(len(functions)):
      for p in prefixes:
        inj_comments = ["", comments[i]]
        for c in inj_comments:
          func_to_execute = functions[i].replace("<add_str>", add_str)
          payload = "{0}{1}{2}".format(p, func_to_execute, c)
          self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
          res = self.scnr.Inject(payload)
          if res.BodyString.count(added_str) > 0:
            self.scnr.ResponseTrace("	==> <i<cr>>Got {0} in the response, this is the result of executing '{1}'. Indicates Code Injection!<i</cr>>".format(added_str, add_str))
            self.scnr.SetTraceTitle("Echo based Code Injection", 5)
            self.AddToTriggers(payload, added_str)
            reason = self.GetErrorReason(payload, func_to_execute, add_num_1, add_num_2)
            reason = "<i<b>><i<cb>>Reason {0}:<i</b>><i</cb>> <i<br>>".format(len(self.reasons) + 1) + reason
            self.reasons.append(reason)
            return
          else:
            self.scnr.ResponseTrace("	==> Did not get {0} in the response".format(added_str))
  
  def CheckForTimeBasedCodeInjection(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for Time based Code Injection:<i</h>>")
    #set the time related values for time-based code injection check
    self.time = 0
    max_delay = 0
    min_delay = -1
    self.scnr.Trace("<i<br>>Sending three requests to get a baseline of the response time for time based check:")
    base_line_delays = []
    avg_delay = 0
    for i in range(3):
      res = self.scnr.Inject()
      avg_delay = avg_delay + res.RoundTrip
      base_line_delays.append("  {0}) Response time is - {1} ms".format(i+1, res.RoundTrip))
      if res.RoundTrip > max_delay:
        max_delay = res.RoundTrip
      if res.RoundTrip < min_delay or min_delay == -1:
        min_delay = res.RoundTrip
    avg_delay = avg_delay / 3
    
    self.scnr.Trace("<i<br>>".join(base_line_delays))
    if min_delay > 5000:
      self.time = ((max_delay + min_delay) / 1000) + 1
    else:
      self.time = ((max_delay + 5000) / 1000) + 1
    self.scnr.Trace("<i<br>>Maximum Response Time: {0}ms. Minimum Response Time: {1}ms<i<br>>Induced Time Delay will be for {2}ms<i<br>>".format(max_delay, min_delay, self.time * 1000))
    
    functions = ['sleep(<seconds>);', 'import time;time.sleep(<seconds>);']
    prefixes = ["", "';", '";']
    comments = ["", "#"]
    for f in functions:
      for p in prefixes:
        for c in comments:
          func_to_execute = f.replace("<seconds>", str(self.time))
          payload = "{0}{1}{2}".format(p, func_to_execute, c)
          self.SendAndAnalyzeTimePayload(payload, func_to_execute, avg_delay)
  
  def SendAndAnalyzeTimePayload(self, payload, func_to_execute, avg_time):
    for i in range(2):
      self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
      res = self.scnr.Inject(payload)
      #we reduce the delay by 3 seconds to make up for the the fact that the ping could complete earlier
      if res.RoundTrip >= self.time * 1000:
        if i == 0:
          self.scnr.ResponseTrace("	==> <i<b>>Observed a delay of {0}ms, induced delay was for {1}ms. Rechecking the delay by sending the same payload again<i</b>>".format(res.RoundTrip, self.time * 1000))
        else:
          self.scnr.ResponseTrace("	==> <i<cr>>Observed a delay of {0}ms, induced delay was for {1}ms. Delay observed twice, indicates Code Injection!!<i</cr>>".format(res.RoundTrip, self.time * 1000))
          self.AddToTriggers(payload, "Got a delay of {0}ms. {1}ms delay was induced by the payload".format(res.RoundTrip, self.time * 1000))
          reason = self.GetBlindReason(payload, func_to_execute, res.RoundTrip, avg_time)
          reason = "<i<cb>><i<b>>Reason {0}:<i</b>><i</cb>> <i<br>>".format(len(self.reasons) + 1) + reason
          self.reasons.append(reason)
      else:
        if i == 0:
          self.scnr.ResponseTrace("	==> Response time was {0}ms. No delay observed.".format(res.RoundTrip))
          return
        else:
          self.scnr.ResponseTrace("	==> Response time was {0}ms. Delay did not reoccur, initial delay could have been due to network issues.".format(res.RoundTrip))
  
  def AddToTriggers(self, RequestTrigger, ResponseTrigger):
    self.RequestTriggers.append(RequestTrigger)
    self.ResponseTriggers.append(ResponseTrigger)
    self.TriggerRequests.append(self.scnr.InjectedRequest.GetClone())
    self.TriggerResponses.append(self.scnr.InjectionResponse.GetClone())
    self.TriggerCount = self.TriggerCount + 1
  
  def AnalyzeTestResult(self):
    if len(self.RequestTriggers) == 1:
      self.ReportCodeInjection(FindingConfidence.Medium)
    elif len(self.RequestTriggers) > 1:
      self.ReportCodeInjection(FindingConfidence.High)
  
  def ReportCodeInjection(self, confidence):
    self.scnr.SetTraceTitle("Code Injection Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "Code Injection Found"
    pr.Summary = "Code Injection been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}<i<br>><i<br>>{3}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary(), self.GetTrace())
    for i in range(len(self.RequestTriggers)):
      pr.Triggers.Add(self.RequestTriggers[i], self.TriggerRequests[i], self.ResponseTriggers[i], self.TriggerResponses[i])
    pr.Type = FindingType.Vulnerability
    pr.Severity = FindingSeverity.High
    pr.Confidence = confidence
    self.scnr.AddFinding(pr)

  def GetTrace(self):
    Trace = "<i<hh>>Scan Trace:<i</hh>><i<br>><i<br>>"
    Trace = Trace + "This section contains trace information about the various tests that were performed during this particular scan, the payloads sent during these tests, the application's response to these payloads and the scanner's interpretation of these responses."
    Trace = Trace + "<i<br>>This vulnerability was identified by <i<b>>Scan ID {0}<i</b>>".format(self.scnr.ID)
    
    Trace = Trace + "<i<br>><i<br>>To view the requests and responses associated with this check please head over to the 'Scan Trace' section which is under the 'Automated Scanning' section. "
    Trace = Trace + "<i<br>>There would be a list of scan traces in this section, select the trace entry with the values:<i<br>>    <i<cb>>SCAN ID<i</cb>> - {0}<i<br>>    <i<cb>>CHECK<i</cb>> - {1}<i<br>>    <i<cb>>SECTION<i</cb>> - {2}<i<br>>    <i<cb>>PARAMETER<i</cb>> - {3}".format(self.scnr.ID, self.Name, self.scnr.InjectedSection, self.scnr.InjectedParameter)
    Trace = Trace + "<i<br>><i<br>>Selecting the entry would display the trace overview with the list of payloads sent and the corresponding response code, time etc. After this click on the 'Load this Trace in Viewer' button to view the exact requests and responses associated with this particular check."
    
    Trace = Trace + "<i<br>><i<br>>In the trace information below you would see repeated occurrences of a number followed by the pipe character, <i<b>>eg: 245| Some text here<i</b>>. This number is the log id of the request sent corresponding to that line of scan trace. You can view this request and response from the 'Scan Log' section of the 'Logs' section by using this id as reference. "
    
    Trace = Trace + "<i<br>><i<br>>    <i<b>><< Trace Information Starts From Here >><i</b>><i<br>><i<br>>{0}<i<br>><i<br>>    <i<b>><< Trace Information Ends Here >><i</b>>".format(self.scnr.GetTrace())
    return Trace

  def GetSummary(self):
    Summary = "Code Injection is an issue where it is possible to inject and execute code on the server-side. For more details on this issue refer <i<cb>>https://www.owasp.org/index.php/Code_Injection<i</cb>><i<br>><i<br>>"
    Summary = Summary + "IronWASP has reported this issue because of the following reasons:<i<br>><i<br>>"
    for reason in self.reasons:
      Summary = Summary + reason + "<i<br>><i<br>>"
    return Summary
  
  def GetErrorReason(self, payload, code, num_a, num_b):
    #payload - ';print 1234 + 7678;#
    #code - print 1234 + 7678
    #num_a - 1234
    #num_b - 7678
    #Reason = "IronWASP sent <i<hlg>>';print 1234 + 7678;#<i</hlg>> as payload to the application. This payload has a small snippet of code - <i<hlg>>print 1234 + 7678<i</hlg>>. "
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. This payload has a small snippet of code - <i<hlg>>{1}<i</hlg>>. ".format(payload, code)
    Reason = Reason + "If this code is executed then <i<hlg>>{0}<i</hlg>> and <i<hlg>>{1}<i</hlg>> will be added together and the sum of the addition will be printed back in the response. ".format(num_a, num_b)
    #Reason = Reason + "The response that came back from the application after the payload was injected had the value <i>34345</i>, which is the sum of 1234 & 7678. This indicates that the injected code snippet could have been executed on the server-side."
    Reason = Reason + "The response that came back from the application after the payload was injected had the value <i<hlg>>{0}<i</hlg>>, which is the sum of <i<hlg>>{1}<i</hlg>> & <i<hlg>>{2}<i</hlg>>. ".format(num_a + num_b, num_a, num_b)
    Reason = Reason + "This indicates that the injected code snippet could have been executed on the server-side."
    
    #Trigger
    Reason = Reason + "<i<br>><i<br>>The request and response associated with this check can be seen by clicking on Trigger {0}.".format(self.TriggerCount)
    Reason = Reason + "<i<br>>Doing a right-click on a Trigger id will show a menu with options to resend selected request or to send it after editing. Click on the 'Select this Request for Manual Testing' option in that menu for this feature."
    
    #False Positive Check
    Reason = Reason + "<i<br>><i<br>><i<cg>><i<b>>False Positive Check:<i</b>><i</cg>><i<br>>"
    Reason = Reason + "To check if this was a valid case or a false positive you can manually inject the same payload but by changing the two numbers to some other value. Then you can observe if the response contains the sum of two numbers."
    Reason = Reason + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    return Reason

  def GetBlindReason(self, payload, code, delayed_time, normal_time):
    #Reason = "IronWASP sent <i>';sleep(5);#</i> as payload to the application. This payload has a small snippet of code - <i>sleep(5)</i>. "
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. This payload has a small snippet of code - <i<hlg>>{1}<i</hlg>>. ".format(payload, code)
    Reason = Reason + "If this code is executed then the application will return the response <i<hlg>>{0}<i</hlg>> milliseconds later than usual. ".format(self.time * 1000)
    #Reason = Reason + "After the payload was injected the response from the application took <i>6783</i> milliseconds. "
    Reason = Reason + "After the payload was injected the response from the application took <i<hlg>>{0}<i</hlg>> milliseconds. ".format(delayed_time)
    #Reason = Reason + "Normally this particular request is processed at around <i>463</i> milliseconds. "
    Reason = Reason + "Normally this particular request is processed at around <i<hlg>>{0}<i</hlg>> milliseconds. ".format(normal_time)
    Reason = Reason + "This indicates that the injected code snippet could have been executed on the server-side."
    
    #Trigger
    Reason = Reason + "<i<br>><i<br>>The request and response associated with this check can be seen by clicking on Trigger {0}.".format(self.TriggerCount)
    Reason = Reason + "<i<br>>Doing a right-click on a Trigger id will show a menu with options to resend selected request or to send it after editing. Click on the 'Select this Request for Manual Testing' option in that menu for this feature."
    
    #False Positive Check
    Reason = Reason + "<i<br>><i<br>><i<cg>><i<b>>False Positive Check:<i</b>><i</cg>><i<br>>"
    Reason = Reason + "To check if this was a valid case or a false positive you can manually inject the same payload but by changing the number of seconds of delay to different values. Then you can observe if the time taken for the response to be returned is affected accordingly."
    Reason = Reason + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    return Reason


p = CodeInjection()
ActivePlugin.Add(p.GetInstance())
