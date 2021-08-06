from burp import IScanIssue


class CustomIssue(IScanIssue):

    def __init__(self, BasePair, Confidence='Certain', IssueBackground=None, IssueDetail=None, IssueName='Python Scripter generated issue', RemediationBackground=None, RemediationDetail=None, Severity='High'):

        self.HttpMessages=[BasePair] # list of HTTP Messages
        self.HttpService=BasePair.getHttpService() # HTTP Service
        self.Url=BasePair.getUrl() # Java URL
        self.Confidence = Confidence # "Certain", "Firm" or "Tentative"
        self.IssueBackground = IssueBackground # String or None
        self.IssueDetail = IssueDetail # String or None
        self.IssueName = IssueName # String
        self.IssueType = 134217728 # always "extension generated"
        self.RemediationBackground = RemediationBackground # String or None
        self.RemediationDetail = RemediationDetail # String or None
        self.Severity = Severity # "High", "Medium", "Low", "Information" or "False positive"

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
