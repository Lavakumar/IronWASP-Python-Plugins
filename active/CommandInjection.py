#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
from System import *
import clr
import re
#Inherit from the base ActivePlugin class
class CommandInjection(ActivePlugin):
  #Check logic based on osCommanding.py of the W3AF project - http://w3af.sourceforge.net/
  seperators = ['', '&&', '|', ';']
  
  #Override the GetInstance method of the base class to return a new instance with details
  def GetInstance(self):
    p = CommandInjection()
    p.Name = "Command Injection"
    p.Description = "Active Plugin to check for OS Command Injection vulnerabilities"
    p.Version = "0.4"
    return p
  
  #Override the Check method of the base class with custom functionlity
  def Check(self, scnr):
    self.scnr = scnr
    self.base_res = self.scnr.BaseResponse
    self.RequestTriggers = []
    self.ResponseTriggers = []
    self.TriggerRequests = []
    self.TriggerResponses = []
    self.TriggerCount = 0
    self.reasons = []
    self.CheckForCommandInjection()
    self.AnalyzeTestResults()
  
  def CheckForCommandInjection(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for Command Injection:<i</h>>")
    #start the checks
    self.prefixes = [""]
    if len(self.scnr.PreInjectionParameterValue) > 0:
      self.prefixes.append(self.scnr.PreInjectionParameterValue)
    self.CheckForEchoBasedCommandInjection()
    self.CheckForTimeBasedCommandInjection()
  
  def CheckForEchoBasedCommandInjection(self):
    
    self.scnr.Trace("<i<br>><i<h>>Checking for Command Injection by Printing File Contents:<i</h>>")
    for prefix in self.prefixes:
      for seperator in self.seperators:
        cmd = "/bin/cat /etc/passwd"
        payload = "{0}{1} {2}".format(prefix, seperator, cmd)
        self.SendAndAnalyzeEchoPayload(payload, "etc/passwd", cmd)
        
        cmd = "type %SYSTEMROOT%\\win.ini"
        payload = "{0}{1} {2}".format(prefix, seperator, cmd)
        self.SendAndAnalyzeEchoPayload(payload, "win.ini", cmd)
      
      cmd = "/bin/cat /etc/passwd"
      payload = "{0} `{1}`".format(prefix, cmd)
      self.SendAndAnalyzeEchoPayload(payload, "etc/passwd", cmd)
      
      cmd = "run type %SYSTEMROOT%\\win.ini"
      payload = "{0} {1}".format(prefix, cmd)
      self.SendAndAnalyzeEchoPayload(payload, "win.ini", cmd)
  
  def CheckForTimeBasedCommandInjection(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for Command Injection by Inducing Time Delay:<i</h>>")
    #set the time related values for time-based command injection check
    self.time = 10
    max_delay = 0
    min_delay = -1
    
    self.scnr.Trace("<i<br>>Sending three requests to get a baseline of the response time for time based check:")
    base_line_delays = []
    self.avg_delay = 0
    for i in range(3):
      res = self.scnr.Inject()
      self.avg_delay = self.avg_delay + res.RoundTrip
      base_line_delays.append("  {0}) Response time is - {1} ms".format(i+1, res.RoundTrip))
      if res.RoundTrip > max_delay:
        max_delay = res.RoundTrip
      if res.RoundTrip < min_delay or min_delay == -1:
        min_delay = res.RoundTrip
    self.avg_delay = self.avg_delay / 3
    
    self.scnr.Trace("<i<br>>".join(base_line_delays))
    if min_delay > 5000:
      self.time = ((max_delay + min_delay) / 1000) + 1
    else:
      self.time = ((max_delay + 5000) / 1000) + 1
    #buffer to handle the time difference in the ping time and ping number
    self.buffer = 3
    self.ping_count = self.time + self.buffer
    
    self.scnr.Trace("<i<br>>Maximum Response Time - {0}ms. Minimum Response Time - {1}ms.<i<br>>Induced Time Delay will be for {2}ms<i<br>>".format(max_delay, min_delay, self.time * 1000))
    
    for prefix in self.prefixes:
      for seperator in self.seperators:
        cmd = "ping -n {0} localhost".format(self.ping_count)
        payload = "{0}{1} {2}".format(prefix, seperator, cmd)
        self.SendAndAnalyzeTimePayload(payload, cmd)
        
        cmd = "ping -c {0} localhost".format(self.ping_count)
        payload = "{0}{1} {2}".format(prefix, seperator, cmd)
        self.SendAndAnalyzeTimePayload(payload, cmd)
        
        cmd = "/usr/sbin/ping -s localhost 1000 {0} ".format(self.ping_count)
        payload = "{0}{1} {2} ".format(prefix, seperator, cmd)
        self.SendAndAnalyzeTimePayload(payload, cmd)
        
      cmd = "ping -c {0} localhost".format(self.ping_count)
      payload = "{0} `{1}`".format(prefix, cmd)
      self.SendAndAnalyzeTimePayload(payload, cmd)
      
      cmd = "run ping -n {0} localhost".format(self.ping_count)
      payload = "{0} {1}".format(prefix, cmd)
      self.SendAndAnalyzeTimePayload(payload, cmd)
      
  def SendAndAnalyzeEchoPayload(self, payload, file_echoed, cmd):
    self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
    res = self.scnr.Inject(payload)
    echoed_file_info = self.GetDownloadedFileInfo(res, file_echoed)
    if len(echoed_file_info) > 0:
      self.scnr.ResponseTrace("	==> <i<cr>>Response contains contens of {0}<i</cr>>".format(file_echoed))
      self.AddToTriggers(payload, echoed_file_info)
      reason = self.GetErrorReason(payload, cmd, file_echoed, echoed_file_info)
      reason = "<i<b>><i<cb>>Reason {0}:<i</b>><i</cb>> <i<br>>".format(len(self.reasons) + 1) + reason
      self.reasons.append(reason)
    else:
      self.scnr.ResponseTrace("	==> No trace of {0}".format(file_echoed))
  
  def SendAndAnalyzeTimePayload(self, payload, cmd):
    for i in range(2):
      self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
      res = self.scnr.Inject(payload)
      if res.RoundTrip >= (self.time * 1000):
        if i == 0:
          self.scnr.ResponseTrace("	==> <i<b>>Observed a delay of {0}ms, induced delay was for {1}ms. Rechecking the delay by sending the same payload again<i</b>>".format(res.RoundTrip, self.time * 1000))
        else:
          self.scnr.ResponseTrace("	==> <i<cr>>Observed a delay of {0}ms, induced delay was for {1}ms. Delay observed twice, indicates Command Injection!!<i</cr>>".format(res.RoundTrip, self.time * 1000))
          self.AddToTriggers(payload, "Got a delay of {0}ms. {1}ms delayed was induced by the payload".format(res.RoundTrip, self.time * 1000))
          reason = self.GetBlindReason(payload, cmd, res.RoundTrip)
          reason = "<i<b>><i<cb>>Reason {0}:<i</b>><i</cb>> <i<br>>".format(len(self.reasons) + 1) + reason
          self.reasons.append(reason)
      else:
        if i == 0:
          self.scnr.ResponseTrace("	==> Response time was {0}ms. No delay observed.".format(res.RoundTrip))
          return
        else:
          self.scnr.ResponseTrace("	==> Response time was {0}ms. Delay did not reoccur, initial delay could have been due to network issues.".format(res.RoundTrip))
  
  def GetDownloadedFileInfo(self, res, file):
    bs = res.BodyString.lower()
    bbs = self.base_res.BodyString.lower()
    
    if file == "etc/passwd":	
      bs_c = bs.count("root:x:0:0:")
      bbs_c = bbs.count("root:x:0:0:")
      if bs_c > bbs_c:
        return "root:x:0:0:"
      elif bs_c == bbs_c and self.scnr.PreInjectionParameterValue.count("etc/passwd") > 0:
        return "root:x:0:0:"
      
      bs_c = bs.count("root:!:x:0:0:")
      bbs_c = bbs.count("root:!:x:0:0:")
      if bs_c > bbs_c:
        return "root:!:x:0:0:"
      elif bs_c == bbs_c and self.scnr.PreInjectionParameterValue.count("etc/passwd") > 0:
        return "root:!:x:0:0:"
      
    elif file == "win.ini":
      bs_c = bs.count("[fonts]")
      bbs_c = bbs.count("[fonts]")
      if bs_c > bbs_c:
        return "[fonts]"
      elif bs_c == bbs_c and self.scnr.PreInjectionParameterValue.count("win.ini") > 0:
        return "[fonts]"
    
    return ""
  
  def AddToTriggers(self, RequestTrigger, ResponseTrigger):
    self.RequestTriggers.append(RequestTrigger)
    self.ResponseTriggers.append(ResponseTrigger)
    self.TriggerRequests.append(self.scnr.InjectedRequest.GetClone())
    self.TriggerResponses.append(self.scnr.InjectionResponse.GetClone())
    self.TriggerCount = self.TriggerCount + 1
  
  def AnalyzeTestResults(self):
    if len(self.RequestTriggers) > 0:
      self.ReportCommandInjection()
  
  def ReportCommandInjection(self):
    self.scnr.SetTraceTitle("Command Injection Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "Command Injection Found"
    pr.Summary = "Command Injection has been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}<i<br>><i<br>>{3}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary(), self.GetTrace())
    for i in range(len(self.RequestTriggers)):
      pr.Triggers.Add(self.RequestTriggers[i], self.TriggerRequests[i], self.ResponseTriggers[i], self.TriggerResponses[i])
    pr.Type = FindingType.Vulnerability
    pr.Severity = FindingSeverity.High
    pr.Confidence = FindingConfidence.High
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
    Summary = "Command Injection is an issue where it is possible to inject and execute operating system commands on the server-side. For more details on this issue refer <i<cb>>https://www.owasp.org/index.php/Command_Injection<i</cb>><i<br>><i<br>>"
    Summary = Summary + "IronWASP has reported this issue because of the following reasons:<i<br>><i<br>>"
    for reason in self.reasons:
      Summary = Summary + reason + "<i<br>><i<br>>"
    return Summary
  
  def GetErrorReason(self, payload, cmd, echoed_file, file_content_match):
    #payload - ';print 1234 + 7678;#
    #code - print 1234 + 7678
    #num_a - 1234
    #num_b - 7678

    #Reason = "IronWASP sent <i>'; /bin/cat /etc/passwd</i> as payload to the application. This payload has a small system command - <i>/bin/cat /etc/passwd</i>. "
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. This payload has a small system command - <i<hlg>>{1}<i</hlg>>. ".format(payload, cmd)
    #Reason = Reason + "If this command is executed by the server then the contents of the <i<hlg>>/etc/passwd<i</hlg>> file will be present in the response. ".format(echoed_file)
    Reason = Reason + "If this command is executed by the server then the contents of the <i<hlg>>{0}<i</hlg>> file will be present in the response. ".format(echoed_file)
    #Reason = Reason + "The response that came back from the application after the payload was injected had the text <i<hlg>>root:x:0:0:<i</hlg>>, which is usually found in <i<hlg>>/etc/passwd<i</hlg>> files. "
    Reason = Reason + "The response that came back from the application after the payload was injected had the text <i<hlg>>{0}<i</hlg>>, which is usually found in <i<hlg>>{1}<i</hlg>> files. ".format(file_content_match, echoed_file)
    Reason = Reason + "This indicates that the injected command was executed by the server and the contents of the <i<hlg>>{0}<i</hlg>> file was printed in the response.".format(echoed_file)
    
    #Trigger
    Reason = Reason + "<i<br>><i<br>>The request and response associated with this check can be seen by clicking on Trigger {0}.".format(self.TriggerCount)
    Reason = Reason + "<i<br>>Doing a right-click on a Trigger id will show a menu with options to resend selected request or to send it after editing. Click on the 'Select this Request for Manual Testing' option in that menu for this feature."
    
    #False Positive Check
    Reason = Reason + "<i<br>><i<br>><i<cg>><i<b>>False Positive Check:<i</b>><i</cg>><i<br>>"
    Reason = Reason + "To check if this was a valid case or a false positive you can first manually look at the response sent for this payload and determine if it actually contains the contents of the <i<hlg>>{0}<i</hlg>> file. ".format(echoed_file)
    Reason = Reason + "After that you can try changing the file name to something else and see if the server prints those file contents."
    Reason = Reason + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    return Reason

  def GetBlindReason(self, payload, cmd, res_time):
    #Reason = "IronWASP sent <i>'; ping -n 8 localhost</i> as payload to the application. This payload has a small system command - <i>ping -n 8 localhost</i>. "
    Reason = "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. This payload has a small system command - <i<hlg>>{1}<i</hlg>>. ".format(payload, cmd)
    #Reason = Reason + "If this command is executed then the server will ping itself 8 times. This will cause the response to be returned around 5000 milliseconds later than usual. "
    Reason = Reason + "If this command is executed then the server will ping itself <i<hlg>>{0}<i</hlg>> times. This will cause the response to be returned around <i<hlg>>{1}<i</hlg>> milliseconds later than usual. ".format(self.ping_count, self.time * 1000)
    #Reason = Reason + "After the payload was injected the response from the application took <i>6783</i> milliseconds. Normally this particular request is processed at around <i>463</i> milliseconds. "
    Reason = Reason + "After the payload was injected the response from the application took <i<hlg>>{0}<i</hlg>> milliseconds. Normally this particular request is processed at around <i<hlg>>{1}<i</hlg>> milliseconds. ".format(res_time, self.avg_delay)
    Reason = Reason + "This indicates that the injected command could have been executed on the server-side."
    
    #Trigger
    Reason = Reason + "<i<br>><i<br>>The request and response associated with this check can be seen by clicking on Trigger {0}.".format(self.TriggerCount)
    Reason = Reason + "<i<br>>Doing a right-click on a Trigger id will show a menu with options to resend selected request or to send it after editing. Click on the 'Select this Request for Manual Testing' option in that menu for this feature."
    
    #False Positive Check
    Reason = Reason + "<i<br>><i<br>><i<cg>><i<b>>False Positive Check:<i</b>><i</cg>><i<br>>"
    Reason = Reason + "To check if this was a valid case or a false positive you can manually inject the same payload but by changing the number of ping requests sent to different values. Then you can observe if the time taken for the response to be returned is affected accordingly."
    Reason = Reason + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    return Reason


p = CommandInjection()
ActivePlugin.Add(p.GetInstance())
