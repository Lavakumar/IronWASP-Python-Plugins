#Author: Lavakumar Kuppan
#License: MIT License - http://www.opensource.org/licenses/mit-license
from IronWASP import *
from System import *
import clr
import re

#Inherit from the base ActivePlugin class
class OpenRedirect(ActivePlugin):

  basic_redirect_urls = ["http://<host>", "https://<host>", "//<host>", "<host>", "5;URL='http://<host>'"]
  #taken from http://kotowicz.net/absolute/
  full_redirect_urls = [ "http://<host>", "https://<host>", "//<host>", "http:\\\\<host>", "https:\\\\<host>", "\\\\<host>", "/\\<host>", "\\/<host>", "\r//<host>", "/ /<host>", "http:<host>", "https:<host>", "http:/<host>", "https:/<host>", "http:////<host>", "https:////<host>", "://<host>", ".:.<host>", "<host>", "5;URL='http://<host>'"]
  
  def GetInstance(self):
    p = OpenRedirect()
    p.Name = "Open Redirect"
    p.Description = "Active Plugin to check for Open Redirect vulnerability"
    p.Version = "0.3"
    return p
  
  #Override the Check method of the base class with custom functionlity
  def Check(self, scnr):
    self.scnr = scnr
    self.base_req = self.scnr.BaseRequest
    self.reason = ""
    self.CheckForOpenRedirection()
  
  def CheckForOpenRedirection(self):
    self.scnr.Trace("<i<br>><i<h>>Checking for Open Redirect:<i</h>>")
    urls = []
    uniq_str = "eziepwlivt"
    self.scnr.Trace("<i<br>><i<h>>Checking if In-Domain Redirect Happens:<i</h>>")
    self.scnr.RequestTrace("  Injected payload - {0}".format(uniq_str))
    res = self.scnr.Inject(uniq_str)
    if self.IsRedirectedTo(uniq_str, res, False):
      self.scnr.ResponseTrace("	==> <i<b>>In-domain redirect happens. Using full payload set!<i</b>>")
      self.scnr.SetTraceTitle("In-domain redirect happens", 5)
      urls.extend(self.full_redirect_urls)
    else:
      self.scnr.ResponseTrace("	==> In-domain redirect does not happen. Using only basic payload set")
      urls.extend(self.basic_redirect_urls)
    
    host = self.base_req.Host
    #remove the port number from hostname
    try:
      if host.index(":") > 0:
        host = host[:host.index(":")]
    except:
      pass
    self.scnr.Trace("<i<br>><i<h>>Checking if Out-of-Domain Redirect Happens:<i</h>>")
    for url in urls:
      for i in range(2):
        h = ""
        if i == 0:
          h = "example.org"
        else:
          h = "{0}.example.org".format(host)
        payload = url.replace("<host>", h)
        self.scnr.RequestTrace("  Injected payload - {0}".format(payload))
        res = self.scnr.Inject(payload)
        redirected = ""
        if payload.startswith("5;"):
          redirect_url = "http://{0}".format(h)
          redirected = self.IsRedirectedTo(redirect_url, res, False)
        elif payload.startswith(h):
          redirected = self.IsRedirectedTo(payload, res, True)
        else:
          redirected = self.IsRedirectedTo(payload, res, False)
        if len(redirected) > 0:
            self.reason = self.GetReason(payload, redirected)
            self.scnr.ResponseTrace("	==> <i<cr>>Redirects to Injected payload!<i</cr>>")
            self.ReportOpenRedirect(payload, payload)
            return
        else:
          self.scnr.ResponseTrace("	==> No redirect to payload")
    
  
  def IsRedirectedTo(self, ru, res, host_only):
      if not host_only:
        #check if redirection is happening through Location
        if res.Headers.Has("Location"):
          location_url = res.Headers.Get("Location")
          if self.IsLocationRedirected(location_url, ru):
            return "Location-Header"
        
        lus = res.Html.GetMetaContent("http-equiv", "Location")
        if len(lus) > 0:
          if self.IsLocationRedirected(lus[0], ru):
            return "Location-Meta"
        
        #check if redirection is happening through Refresh
        if res.Headers.Has("Refresh"):
          refresh_url = res.Headers.Get("Refresh").lower()
          if self.IsRefreshRedirected(refresh_url, ru):
            return "Refresh-Header"
        
        rus = res.Html.GetMetaContent("http-equiv", "Refresh")
        if len(rus) > 0:
          if self.IsRefreshRedirected(rus[0], ru):
            return "Refresh-Meta"
            
      #check if redirection is happening through JavaScript
      #location.href="url"
      #navigate("url")
      #location="url"
      #location.replace("url")
      if res.BodyString.lower().count(ru) > 0:
        JS = res.Html.GetJavaScript()
        for script in JS:
          script = script.lower()
          if script.count(ru) > 0:
            if host_only:
              if re.search('location\.host\s*=\s*(\'|")\s*{0}'.format(re.escape(ru)), script):
                return "JS-location.host"
            else:
              if re.search('location(\.href)*\s*=\s*(\'|")\s*{0}'.format(re.escape(ru)), script):
                return "JS-location.href"
              elif re.search('(navigate|location\.replace)\(\s*(\'|")\s*{0}'.format(re.escape(ru)), script):
                return "JS-*"
      return ""
  
  def IsLocationRedirected(self, location, redirect_url):
    location = location.strip()
    redirect_url = redirect_url.strip()
    if location.lower().startswith(redirect_url.lower()):
      return True
    else:
      return False
  
  def IsRefreshRedirected(self, refresh, redirect_url):
    refresh = refresh.strip()
    redirect_url = redirect_url.strip()
    r_parts = refresh.split(";", 1)
    if len(r_parts) == 2:
      r_url = r_parts[1].lower().strip().lstrip("url=").strip().strip("'").strip('"')
      if r_url.startswith(redirect_url.lower()):
        return True
    return False
  
  def ReportOpenRedirect(self, req_trigger, res_trigger):
    self.scnr.SetTraceTitle("Open Redirect Found", 10)
    pr = Finding(self.scnr.InjectedRequest.BaseUrl)
    pr.Title = "Open Redirect Found"
    pr.Summary = "Open redirect been detected in the '{0}' parameter of the {1} section of the request. {2}  <i<br>><i<br>>{3}".format(self.scnr.InjectedParameter, self.scnr.InjectedSection, self.GetSummary(), self.GetTrace())
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
    Summary = "Open Redirect is an issue where it is possible to redirect the user to any arbitrary website from the vulnerable site. For more details on this issue refer <i<cb>>http://cwe.mitre.org/data/definitions/601.html<i</cb>><i<br>><i<br>>"
    Summary = Summary + "IronWASP has reported this issue because of the following reasons:<i<br>><i<br>>"
    Summary = Summary + self.reason
    return Summary

  def GetReason(self, payload, redir_type):
    payload = Tools.EncodeForTrace(payload)
    Reason = "<i<b>><i<cb>>Reason 1:<i</b>><i</cb>> <i<br>>"
    #Reason = Reason + "IronWASP sent <i>http://vulnsite.example.com</i> as payload to the application. The response that came back from the application to this payload had"
    Reason = Reason + "IronWASP sent <i<hlg>>{0}<i</hlg>> as payload to the application. The response that came back from the application to this payload had ".format(payload)
    
    if redir_type == "Location-Header":
      Reason = Reason + "the value <i<hlg>>{0}<i</hlg>> in its 'Location' header.".format(payload)
    elif redir_type == "Location-Meta":
      Reason = Reason + "the value <i<hlg>>{0}<i</hlg>> in its meta http-equiv tag for 'Location'. This is equivalent to having this value in the 'Location' header.".format(payload)
    elif redir_type == "Refresh-Header":
      Reason = Reason + "the value <i<hlg>>{0}<i</hlg>> in its 'Refresh' header.".format(payload)
    elif redir_type == "Refresh-Meta":
      Reason = Reason + "the value <i<hlg>>{0}<i</hlg>> in its meta http-equiv tag for 'Refresh'. This is equivalent to having this value in the 'Refresh' header.".format(payload)
    elif redir_type.startswith("JS"):
      Reason = Reason + "the value <i<hlg>>{0}<i</hlg>> inside JavaScript of the page in such a way that it would cause a redirection to this value.".format(payload)
     
    #Trigger
    Reason = Reason + "<i<br>><i<br>>The request and response associated with this check can be seen by clicking on Trigger 1."
    Reason = Reason + "<i<br>>Doing a right-click on a Trigger id will show a menu with options to resend selected request or to send it after editing. Click on the 'Select this Request for Manual Testing' option in that menu for this feature."
    
    #False Positive Check
    Reason = Reason + "<i<br>><i<br>><i<cg>><i<b>>False Positive Check:<i</b>><i</cg>><i<br>>"
    Reason = Reason + "To check if this was a valid case or a false positive you can manually send this payload from the browser and observe is the page is actually being redirect outside. If the browser does not perform a redirect then observe the HTML source of the page and try to identify why the page does not redirect inspite of the payload URL occurring in a section of the page that would trigger a redirect."
    Reason = Reason + "<i<br>>If you discover that this issue was a false positive then please consider reporting this to <i<cb>>lava@ironwasp.org<i</cb>>. Your feedback will help improve the accuracy of the scanner."
    return Reason


p = OpenRedirect()
ActivePlugin.Add(p.GetInstance())
