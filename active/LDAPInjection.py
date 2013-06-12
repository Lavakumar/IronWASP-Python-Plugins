#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
from System import *
import clr

#Inherit from the base ActivePlugin class
class LDAPInjection(ActivePlugin):

  error_strings = []
  
  def GetInstance(self):
    p = LDAPInjection()
    p.Name = "LDAP Injection"
    p.Description = "Active plugin that checks for LDAP Injection"
    p.Version = "0.3"
    return p
  
  #Override the Check method of the base class with custom functionlity
  def Check(self, scnr):
    self.scnr = scnr
    self.reason = ""
    self.CheckForLDAPInjection()
  
  def CheckForLDAPInjection(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for LDAP Injection:<i</h>>")
    payload = "#^($!@$)(()))******"
    self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
    res = self.scnr.Inject(payload)
    errors_found = []
    for error in self.error_strings:
      if res.BodyString.count(error) > 0:
        errors_found.append(error)
    if len(errors_found) > 0:
      self.scnr.ResponseTrace("	==> <i<cr>>LDAP Injection Found.<i<br>>Errors:<i<br>>{0}<i</cr>>".format("<i<br>>".join(errors_found)))
      self.reason = self.GetReason(payload, errors_found)
      self.ReportLDAPInjection(payload, "\r\n".join(errors_found))
    else:
      self.scnr.ResponseTrace("	==> No Errors Found")
  
  def ReportLDAPInjection(self, req_trigger, res_trigger):
    self.scnr.SetTraceTitle("LDAP Injection Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "LDAP Injection Found"
    pr.Summary = "LDAP Injection has been detected in the '{0}' parameter of the {1} section of the request.<i<br>><i<br>>{2}<i<br>><i<br>>{3}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary(), self.GetTrace())
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
    Summary = "LDAP Injection is an issue where it is possible execute LDAP queries on the LDAP directory being referenced on the server-side. For more details on this issue refer <i<cb>>https://www.owasp.org/index.php/LDAP_injection<i</cb>><i<br>><i<br>>"
    Summary = Summary + "IronWASP has reported this issue because of the following reasons:<i<br>><i<br>>"
    Summary = Summary + self.reason
    return Summary

  def GetReason(self, payload, errors):
    payload = Tools.EncodeForTrace(payload)
    Reason = "<i<b>><i<cb>>Reason 1:<i</b>><i</cb>> <i<br>>"
    #Reason = Reason + "IronWASP sent <i>#^($!@$)(()))******<i> as payload to the application, this payload would cause an exception to happen in insecure LDAP queries. "
    Reason = Reason + "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application, this payload would cause an exception to happen in insecure LDAP queries. ".format(payload)
    if len(errors) > 1:
      Reason = Reason + "The response from the application for this payload had the error messages:"
      for error in errors:
        Reason = Reason + "<i<br>><i<hlg>>{0}<i</hlg>>".format(error)
      Reason = Reason + "<i<br>>These error messages are usually found in LDAP query related exceptions. Therefore this issue has been reported."
    else:
      #Reason = Reason + "The response from the application for this payload had the error message: <i>An inappropriate matching occurred</i>. ".format(error)
      Reason = Reason + "The response from the application for this payload had the error message: <i<hlg>>{0}<i</hlg>>. ".format(errors[0])
      Reason = Reason + "This error message is usually found in LDAP query related exceptions. Therefore this issue has been reported."
    
    #Trigger
    Reason = Reason + "<i<br>><i<br>>The request and response associated with this check can be seen by clicking on Trigger 1."
    Reason = Reason + "<i<br>>Doing a right-click on a Trigger id will show a menu with options to resend selected request or to send it after editing. Click on the 'Select this Request for Manual Testing' option in that menu for this feature."
    
    #False Positive Check
    Reason = Reason + "<i<br>><i<br>><i<cg>><i<b>>False Positive Check:<i</b>><i</cg>><i<br>>"
    Reason = Reason + "Manually analyze the response recived for the payload and confirm if the error message is actually because of some exception on the server-side."
    Reason = Reason + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    return Reason
    
  def SetUp(self):
    err_str_file = open(Config.Path + "\\plugins\\active\\ldap_error_strings.txt")
    err_str_file.readline()#Ignore the first line containing comments
    error_strings_raw = err_str_file.readlines()
    err_str_file.close()
    for err_str in error_strings_raw:
      err_str = err_str.strip()
      if len(err_str) > 0:
        self.error_strings.append(err_str)

p = LDAPInjection()
p.SetUp()
ActivePlugin.Add(p.GetInstance())
