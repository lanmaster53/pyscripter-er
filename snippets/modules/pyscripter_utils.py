from burp import IScanIssue
from hashlib import md5
import re


class CustomIssue(IScanIssue):

    def __init__(self, callbacks, BasePair, IssueName='Python Scripter generated issue', IssueDetail=None, IssueBackground=None, RemediationDetail=None, RemediationBackground=None, Severity='High', Confidence='Certain'):

        self.callbacks = callbacks
        self.HttpMessages=[BasePair] # list of HTTP Messages
        self.HttpService=BasePair.getHttpService() # HTTP Service
        self.Url=BasePair.getUrl() # Java URL
        self.IssueType = 134217728 # always "extension generated"
        self.IssueName = IssueName # String
        self.IssueDetail = IssueDetail # String or None
        self.IssueBackground = IssueBackground # String or None
        self.RemediationDetail = RemediationDetail # String or None
        self.RemediationBackground = RemediationBackground # String or None
        self.Severity = Severity # "High", "Medium", "Low", "Information" or "False positive"
        self.Confidence = Confidence # "Certain", "Firm" or "Tentative"
        self.Signature = self._signIssue()

    def _signIssue(self):

        sig = md5(self.IssueName
            +self.IssueDetail
            +self.Severity
            +self.Confidence
        ).hexdigest()
        block = '<p>[sig:{}]</p>'.format(sig)
        self.IssueDetail += block
        return sig

    def _isDuplicate(self, issue):

        m = re.search(r'\[sig:([^\]]+)\]', issue.issueDetail or '')
        if m and m.group(1) == self.Signature:
            return True
        return False

    def addCustomIssue(self):
        rawUrl = self.HttpMessages[0].url
        url = rawUrl.getProtocol()+"://"+rawUrl.getHost()+rawUrl.getPath()
        for issue in self.callbacks.getScanIssues(url):
            if self._isDuplicate(issue):
                return
        self.callbacks.addScanIssue(self)

    def getHttpMessages(self):

        return self.HttpMessages

    def getHttpService(self):

        return self.HttpService

    def getUrl(self):

        return self.Url

    def getConfidence(self):

        return self.Confidence

    def getIssueBackground(self):

        return self.IssueBackground

    def getIssueDetail(self):

        return self.IssueDetail

    def getIssueName(self):

        return self.IssueName

    def getIssueType(self):

        return self.IssueType

    def getRemediationBackground(self):

        return self.RemediationBackground

    def getRemediationDetail(self):

        return self.RemediationDetail

    def getSeverity(self):

        return self.Severity
