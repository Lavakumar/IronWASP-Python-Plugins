#License GPLv3
#Author: Lavakumar Kuppan

from Iron import *
from System.Threading import Monitor
import re

class CheckReflection(PassivePlugin):
    
    UniqueStrings = [];
    
    def Check(self, Session, Results):
    
        if(Session.Response.IsBinary):
            return
        UniqueString = self.MakeUniqueString(Session)
        Monitor.Enter(self.UniqueStrings)
        try:
            if(self.UniqueStrings.Contains(UniqueString)):
                Monitor.Exit(self.UniqueStrings)
                return
            else:
                self.UniqueStrings.append(UniqueString)
        except:
            a = "0"
        Monitor.Exit(self.UniqueStrings)
        
        #check if the URL is being reflected
        if(len(Session.Request.URL) > 1):
            if(self.HasReflection(Session.Request.URL, Session)):
                Summary = "The URL of the Request is being reflected back in the response body"
                self.ReportReflection(Results, Summary, Session, Session.Request.URL, Session.Request.URL, Session.Request.URL, UniqueString)
        
        #check if any URL path parts are being reflected. To be checked only when Querystring and File extension are absent (to handle URL rewriting)
        if((len(Session.Request.Query.GetAll()) == 0) and (len(Session.Request.File) == 0)):
            for PathPart in Session.Request.URLPathParts:
                if(self.HasReflection(PathPart, Session)):
                    Summary = "The value of the URL Path parameter '{0}' is being reflected back in the response body".format(PathPart)
                    self.ReportReflection(Results, Summary, Session, PathPart, PathPart, PathPart, UniqueString)
        
        #check if any Query parameters are being reflected
        for Parameter in Session.Request.Query.GetAll():
            SubParametervalues = Session.Request.Query.GetAll(Parameter)
            for i in range(len(SubParametervalues)):
                if(len(SubParametervalues[i]) > 0):
                    if(self.HasReflection(SubParametervalues[i], Session)):
                        Summary = "The value of Query parameter '{0}' is being reflected back in the response body".format(Parameter)
                        self.ReportReflection(Results, Summary, Session, '{0}={1}'.format(Parameter, SubParametervalues[i]), SubParametervalues[i], Parameter, '{0}:{1}'.format(UniqueString,i.ToString()))

        #check if any Body parameters are being reflected
        for Parameter in Session.Request.Body.GetAll():
            SubParametervalues = Session.Request.Body.GetAll(Parameter)
            for i in range(len(SubParametervalues)):
                if(len(SubParametervalues[i]) > 0):
                    if(self.HasReflection(SubParametervalues[i], Session)):
                        Summary = "The value of Body parameter '{0}' is being reflected back in the response body".format(Parameter)
                        self.ReportReflection(Results, Summary, Session, '{0}={1}'.format(Parameter, SubParametervalues[i]), SubParametervalues[i], Parameter, '{0}:{1}'.format(UniqueString,i.ToString()))
                    
        #check if any Cookie parameters are being reflected
        for Parameter in Session.Request.Cookie.GetAll():
            SubParametervalues = Session.Request.Cookie.GetAll(Parameter)
            for i in range(len(SubParametervalues)):
                if(len(SubParametervalues[i]) > 0):
                    if(self.HasReflection(SubParametervalues[i], Session)):
                        Summary = "The value of Cookie parameter '{0}' is being reflected back in the response body".format(Parameter)
                        self.ReportReflection(Results, Summary, Session, '{0}={1}'.format(Parameter, SubParametervalues[i]), SubParametervalues[i], Parameter, '{0}:{1}'.format(UniqueString,i.ToString()))

    def HasReflection(self, Parameter, Session):
        if(len(Parameter) > 0):
            re_string = '\W{0}\W'.format(Parameter.replace('\\','\\\\').replace('.','\.').replace('$','\$').replace('^','\^')).replace('*','\*').replace('|','\|').replace('+','\+').replace('?','\?').replace('{','\{').replace('}','\}').replace('[','\[').replace(']','\]').replace('(','\(').replace(')','\)')
            if(re.search(re_string, Session.Response.BodyString, re.I|re.M)):
                return True
            else:
                return False
    
    def ReportReflection(self, Results, Summary, Session, RequestTrigger, ResponseTrigger, Parameter, UniqueString):
          PR = PluginResult(Session.Request.Host);
          PR.Title = "Reflection Found on {0}".format(Session.Request.URLPath);
          PR.Summary = Summary
          PR.Triggers.Add(RequestTrigger, Session.Request.ToString(), ResponseTrigger, Session.Response.ToString());
          PR.ResultType = PluginResultType.TestLead;
          PR.UniquenessString = 'CheckReflection|TestLead|{0}|{1}'.format(UniqueString, Parameter)
          Results.Add(PR)

    def MakeUniqueString(self, Session):
        us = '{0}|{1}|{2}|{3}:'.format(Session.Request.Host, Session.Request.SSL.ToString(), Session.Request.Method, Session.Request.URLPath);
        for p in Session.Request.Query.GetAll():
            us += '{0}:'.format(p)
        for p in Session.Request.Body.GetAll():
            us += '{0}:'.format(p)
        for p in Session.Request.Cookie.GetAll():
            us += '{0}={1}:'.format(p, Session.Request.Cookie.Get(p))
        return us

p = CheckReflection()
p.Name = "Check Reflections"
p.Description = "Passive plugin to identify parameters whose value is returned in the response. These could be potential candidates for XSS"
p.FileName = "CheckReflection.py"
p.CallingState = PluginCallingState.BeforeInterception
p.WorksOn = PluginWorksOn.Response
PassivePlugin.Add(p)
