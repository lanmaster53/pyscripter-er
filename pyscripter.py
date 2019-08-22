class BaseScript(object):

    def __init__(self, extender, callbacks, helpers, toolFlag, messageIsRequest, messageInfo):

        self.extender = extender
        self.callbacks = callbacks
        self.helpers = helpers
        self.toolFlag = toolFlag
        self.messageIsRequest = messageIsRequest
        self.messageInfo = messageInfo
        self.verbose = False
        self.in_scope = self.callbacks.isInScope(self.messageInfo.getUrl())

    def debug(self, message):
        """Provides an interface for verbose output."""

        if self.verbose:
            print(message)

    def help(self):
        """Displays this help interface."""

        if self.messageIsRequest:
            print(help(self))

    def introspect(self):
        """Provides introspection into the Python Scripter API."""

        import sys

        apis = ('extender', 'callbacks', 'helpers', 'toolFlag', 'messageIsRequest', 'messageInfo')
        funcs = (type, dir)

        if self.messageIsRequest:
            for api in apis:
                print('\n{}:\n{}'.format(api, '='*len(api)))
                for func in funcs:
                    print('\n{}:\n'.format(func.__name__))
                    print(func(getattr(self, api)))
        self.debug('Introspection complete.')

    def remove_header(self, headers, header_name):
        """Removes a specific header from a list of headers."""

        for header in headers:
            if header.startswith(header_name):
                headers.remove(header)
                self.debug('Header removed: {}'.format(header_name))
                break
        return headers

    def remove_headers(self, header_names):
        """Removes a list of headers from the current request."""

        if self.messageIsRequest:
            request = self.helpers.analyzeRequest(self.messageInfo)
            headers = request.getHeaders()
            for header_name in header_names:
                headers = self.remove_header(headers, header_name)
            body = self.messageInfo.getRequest()[request.getBodyOffset():]
            new_request = self.helpers.buildHttpMessage(headers, body)
            self.messageInfo.setRequest(new_request)
            self.debug('Headers removed: {}'.format(', '.join(header_names)))

    def replace_bearer_token(self, new_token):
        """Replaces a Bearer token in the current request."""

        if self.messageIsRequest:
            request = self.helpers.analyzeRequest(self.messageInfo)
            headers = request.getHeaders()
            headers = self.remove_header(headers, 'Authorization')
            headers.add('Authorization: Bearer {}'.format(new_token))
            body = self.messageInfo.getRequest()[request.getBodyOffset():]
            new_request = self.helpers.buildHttpMessage(headers, body)
            self.messageInfo.setRequest(new_request)
            self.debug('Token replaced.')

    def enable_passive_audit_checks(self):
        """Runs passive check methods against in-scope proxy traffic.

        Additional checks are added by creating new methods and prefixing the 
        name with `_passive_request_` or `_passive_response_`. The second 
        chunk of the method name determines what is analyzed by the method, 
        and the method must receive it as an argument.
        """

        if self.toolFlag == self.callbacks.TOOL_PROXY and self.in_scope:
            self.debug('Passive checks enabled.')
            methods =[x for x in dir(self.__class__) if x.startswith('_passive_')]
            for method in methods:
                mode = method.split('_')[1]
                if mode == 'request' and self.messageIsRequest:
                    request = self.messageInfo.getRequest()
                    getattr(self, method)(request)
                elif mode == 'response' and not self.messageIsRequest:
                    response = self.messageInfo.getResponse()
                    getattr(self, method)(response)

    def _passive_response_autocomplete_enabled(self, response):
        """Checks for autocomplete on text form fields in a response."""

        import re

        results = re.findall(r'(<input [^>]*>)', response)
        for result in results:
            if re.search(r'''type=['"]text['"]''', result) and not re.search(r'autocomplete', result):
                issue = CustomIssue(
                    BasePair=self.messageInfo,
                    IssueName='Text field with autocomplete enabled',
                    IssueDetail='The following text field has autocomplete enabled:\n\n<ul><li>' + result.replace('<', '&lt;').replace('>', '&gt;') + '</li></ul>',
                    Severity='Low',
                )
                self.callbacks.addScanIssue(issue)
        self.debug('Passive check applied: Autocomplete Enabled')

    def _passive_response_verbose_headers(self, response):
        """Checks for verbose headers in a response."""

        bad_headers = ('server', 'x-powered-by', 'x-aspnet-version')
        headers = self.helpers.analyzeResponse(response).getHeaders()
        for header in headers:
            name = header.split(':')[0]
            # known bad headers
            if name.lower() in bad_headers:
                issue = CustomIssue(
                    BasePair=self.messageInfo,
                    IssueName='Verbose header',
                    IssueDetail='The following HTTP response header may disclose sensitive information:\n\n<ul><li>' + header + '</li></ul>',
                    Severity='Low',
                )
                self.callbacks.addScanIssue(issue)
            # custom headers
            elif name.lower().startswith('x-'):
                issue = CustomIssue(
                    BasePair=self.messageInfo,
                    IssueName='Interesting header',
                    IssueDetail='The following HTTP response header may disclose sensitive information:\n\n<ul><li>' + header + '</li></ul>',
                    Severity='Low',
                    Confidence='Tentative',
                )
                self.callbacks.addScanIssue(issue)
        self.debug('Passive check applied: Verbose Headers')

    def extract_all_from_response(self, pattern):
        """Extracts multiple instances of a REGEX capture group from the 
        current response."""

        import re

        if not self.messageIsRequest:
            response = self.messageInfo.getResponse()
            matches = re.findall(pattern, response)
            for match in matches:
                print(match)

    def replace_response_body(self, url_pattern, body):
        """Replaces the body of a response from a matched URL.

        Great for swapping SPA UI build definitions between user roles.
        """

        import re

        if not self.messageIsRequest:
            url = self.messageInfo.url.toString()
            if re.search(url_pattern, url):
                response = self.messageInfo.getResponse()
                headers = self.helpers.analyzeResponse(response).getHeaders()
                new_response = self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(body))
                self.messageInfo.setResponse(new_response)
                self.debug('Response replaced from: {}'.format(url))


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
