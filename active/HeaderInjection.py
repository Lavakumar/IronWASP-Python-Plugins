#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
from System import *
import clr

#Inherit from the base ActivePlugin class
class HeaderInjection(ActivePlugin):
  
  crlf_inj_str = ["\r\nNeww: Headerr", "aa\r\nNeww: Headerr", "\r\nNeww: Headerr\r\n", "aa\r\nNeww: Headerr\r\n"]
  
  def GetInstance(self):
    p = HeaderInjection()
    p.Name = "Header Injection"
    p.Description = "Active plugin that checks for HTTP Header Injection by inserting CR LF characters"
    p.Version = "0.3"
    return p
  
  #Override the Check method of the base class with custom functionlity
  def Check(self, scnr):
    self.scnr = scnr
    self.reason = ""
    self.CheckForCRLFInjection()
  
  def CheckForCRLFInjection(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for Header Injection:<i</h>>")
    self.scnr.Trace("<i<br>><i<b>>  Trying to inject a header named 'Neww'<i</b>>")
    crlf_inj_found = False
    prefix = ["", self.scnr.PreInjectionParameterValue]
    for cis in self.crlf_inj_str:
      if crlf_inj_found:
        break
      for p in prefix:
        self.scnr.RequestTrace("  Injected payload - {0}".format(p + cis.replace("\r\n", "\\r\\n")))
        payload = p + cis
        res = self.scnr.Inject(payload)
        if(res.Headers.Has("Neww")):
          self.scnr.ResponseTrace("	==> <i<cr>>Header 'Neww' injected<i</cr>>")
          self.reason = self.GetReason(payload)
          self.ReportCRLFInjection(cis.replace("\r\n", "\\r\\n"), cis.replace("\r\n", "\\r\\n"))
          crlf_inj_found = True
          break
        else:
          self.scnr.ResponseTrace("	==> Header not injected")
  
  def ReportCRLFInjection(self, req_trigger, res_trigger):
    self.scnr.SetTraceTitle("Header Injection Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "Header Injection Found"
    pr.Summary = "Header Injection has been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}<i<br>><i<br>>{3}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary(), self.GetTrace())
    pr.Triggers.Add(req_trigger, self.scnr.InjectedRequest, res_trigger, self.scnr.InjectionResponse)
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
    Summary = "Header Injection is an issue where it is possible to inject a new HTTP Header in the response from the application. For more details on this issue refer <i<cb>>http://en.wikipedia.org/wiki/HTTP_header_injection<i</cb>><i<br>><i<br>>"
    Summary = Summary + "IronWASP has reported this issue because of the following reasons:<i<br>><i<br>>"
    Summary = Summary + self.reason
    return Summary

  def GetReason(self, payload):
    payload = Tools.EncodeForTrace(payload)
    Reason = "<i<b>><i<cb>>Reason 1:<i</b>><i</cb>> <i<br>>"
    #Reason = "IronWASP sent <i>'\r\nNeww: Headerr</i> as payload to the application. This payload has CRLF characters followed by the string <i>Neww: Headerr</i> which is in the format of a HTTP Header with name <i>Neww</i> and value <i>Headerr</i>. "
    Reason = Reason + "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. This payload has CRLF characters followed by the string <i<hlg>>Neww: Headerr<i</hlg>> which is in the format of a HTTP Header with name <i<hlg>>Neww<i</hlg>> and value <i<hlg>>Headerr<i</hlg>>. ".format(payload)
    Reason = Reason + "The response that came back from the application after injecting this payload has an HTTP header named <i<hlg>>Neww<i</hlg>>. "
    Reason = Reason + "This indicates that our payload caused an HTTP header to be injected in the response."
    
    #Trigger
    Reason = Reason + "<i<br>><i<br>>The request and response associated with this check can be seen by clicking on Trigger 1."
    Reason = Reason + "<i<br>>Doing a right-click on a Trigger id will show a menu with options to resend selected request or to send it after editing. Click on the 'Select this Request for Manual Testing' option in that menu for this feature."
    
    #False Positive Check
    Reason = Reason + "<i<br>><i<br>><i<cg>><i<b>>False Positive Check:<i</b>><i</cg>><i<br>>"
    Reason = Reason + "To check if this was a valid case or a false positive you can send the same payload but with different values for the header name part of the payload. If the response contains any HTTP headers with the specified names then there actually is Header Injection."
    Reason = Reason + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    return Reason


p = HeaderInjection()
ActivePlugin.Add(p.GetInstance())
