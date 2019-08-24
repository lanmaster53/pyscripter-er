class BaseScript(object):

    def __init__(self, extender, callbacks, helpers, toolFlag, messageIsRequest, messageInfo, macroItems):

        self.extender = extender
        self.callbacks = callbacks
        self.helpers = helpers
        self.toolFlag = toolFlag
        self.messageIsRequest = messageIsRequest
        self.messageInfo = messageInfo
        self.macroItems = macroItems
        self.debug = False

    def _context(context=None, tools=[], scope=False):
        """Currently unused decorator because it hides the method's signature
        from introspection, which is needed. See `_in_context` hack below.
        """

        def wrapper(func):
            @wraps(func)
            def wrapped(self, *args, **kwargs):
                if (context and
                    context == 'request' and not self.messageIsRequest or
                    context == 'response' and self.messageIsRequest):
                    return
                toolFlags = [getattr(self.callbacks, 'TOOL_{}'.format(t.upper)) for t in tools]
                if tools and self.toolFlag not in toolFlags:
                    return
                if scope and not self._in_scope():
                    return
                return func(self, *args, **kwargs)
            return wrapped
        return wrapper

    def _in_context(self, context=None, tools=[], scope=False):
        """Checks the provided parameters against the current context."""

        if (context and
            context == 'request' and not self.messageIsRequest or
            context == 'response' and self.messageIsRequest):
            return False
        if (tools and self.toolFlag not in tools):
            return False
        if (scope and not self._in_scope()):
            return False
        return True

    def _in_scope(self):
        """Determines if the current request is in scope."""

        in_scope = self.callbacks.isInScope(self.messageInfo.getUrl())
        mode = 'Response' if self.messageIsRequest else 'Request'
        scope = 'in scope' if in_scope else 'not in scope'
        url = self.messageInfo.url.toString()
        self._debug('{} {}: {}'.format(mode, scope, url))
        return in_scope

    def _debug(self, message):
        """Provides an interface for verbose output."""

        if self.debug:
            print('[DEBUG] {}'.format(message))

    def help(self):
        """Displays this help interface."""

        if not self._in_context(context='request'): return

        print(help(self))

    def introspect(self):
        """Provides introspection into the Python Scripter API."""

        if not self._in_context(context='request'): return

        import sys

        apis = ('extender', 'callbacks', 'helpers', 'toolFlag', 'messageIsRequest', 'messageInfo')
        funcs = (type, dir)

        for api in apis:
            print('\n{}:\n{}'.format(api, '='*len(api)))
            for func in funcs:
                print('\n{}:\n'.format(func.__name__))
                print(func(getattr(self, api)))
        self._debug('Introspection complete.')

    def _remove_header(self, headers, header_name):
        """Removes a specific header from a list of headers."""

        for header in headers:
            if header.startswith(header_name):
                headers.remove(header)
                self._debug('Header removed: {}'.format(header_name))
                break
        return headers

    def remove_headers(self, header_names):
        """Removes a list of headers from the current request."""

        if not self._in_context(context='request'): return

        request = self.helpers.analyzeRequest(self.messageInfo)
        headers = request.getHeaders()
        for header_name in header_names:
            headers = self._remove_header(headers, header_name)
        body = self.messageInfo.getRequest()[request.getBodyOffset():]
        new_request = self.helpers.buildHttpMessage(headers, body)
        self.messageInfo.setRequest(new_request)
        self._debug('Headers removed: {}'.format(', '.join(header_names)))

    def _replace_bearer_token(self, new_token):
        """Replaces the Bearer token in the current request."""

        request = self.helpers.analyzeRequest(self.messageInfo)
        headers = request.getHeaders()
        headers = self._remove_header(headers, 'Authorization')
        headers.add('Authorization: Bearer {}'.format(new_token))
        body = self.messageInfo.getRequest()[request.getBodyOffset():]
        new_request = self.helpers.buildHttpMessage(headers, body)
        self.messageInfo.setRequest(new_request)
        self._debug('Token replaced.')

    def replace_bearer_token(self, new_token):
        """Replaces the Bearer token in the current request with the provided
        token."""

        if not self._in_context(context='request'): return

        self._replace_bearer_token(new_token)

    def macro_replace_bearer_token(self, pattern):
        """Replaces the Bearer token in the current request with a token 
        extracted from a macro response.

        Requires a session handling rule to pass the result of a macro to the 
        extension.

        Tip: Create and copy the REGEX pattern from the macro editor.
        """

        if not self._in_context(context='request', tools=[self.callbacks.TOOL_MACRO]): return

        import re

        response = self.macroItems[0].getResponse()
        match = re.search(pattern, response)
        self._replace_bearer_token(match.group(1))

    def passive_autocomplete_text(self):
        """Checks for autocomplete on text fields in the current response."""

        if not self._in_context(context='response',
                                tools=[self.callbacks.TOOL_PROXY],
                                scope=True): return

        import re

        response = self.messageInfo.getResponse()
        results = re.findall(r'(<input [^>]*>)', response)
        for result in results:
            if re.search(r'''type=['"]text['"]''', result) and not re.search(r'autocomplete', result):
                self._create_issue(
                    issue_name='Text field with autocomplete enabled',
                    issue_detail='The following text field has autocomplete enabled:\n\n<ul><li>' + result.replace('<', '&lt;').replace('>', '&gt;') + '</li></ul>',
                    severity='Low',
                )
        self._debug('Passive check applied: Autocomplete Enabled')

    def passive_verbose_headers(self):
        """Checks for verbose headers in the current response."""

        if not self._in_context(context='response',
                                tools=[self.callbacks.TOOL_PROXY],
                                scope=True): return

        bad_headers = ('server', 'x-powered-by', 'x-aspnet-version')
        response = self.messageInfo.getResponse()
        headers = self.helpers.analyzeResponse(response).getHeaders()
        for header in headers:
            name = header.split(':')[0]
            # known bad headers
            if name.lower() in bad_headers:
                self._create_issue(
                    issue_name='Verbose header',
                    issue_detail='The following HTTP response header may disclose sensitive information:\n\n<ul><li>' + header + '</li></ul>',
                    severity='Low',
                )
            # custom headers
            elif name.lower().startswith('x-'):
                self._create_issue(
                    issue_name='Interesting header',
                    issue_detail='The following HTTP response header may disclose sensitive information:\n\n<ul><li>' + header + '</li></ul>',
                    severity='Low',
                    confidence='Tentative',
                )
        self._debug('Passive check applied: Verbose Headers')

    def passive_link_finder(self, exclusions=[]):
        """Finds links within JavaScript files."""

        if not self._in_context(context='response',
                                tools=[self.callbacks.TOOL_PROXY],
                                scope=True): return

        import re

        regex_str = r"""

            (?:"|')                                 # Start newline delimiter

            (

                ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
                [^"'/]{1,}\.                        # Match a domainname (any character + dot)
                [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path

                |

                ((?:/|\.\./|\./)                    # Start with /,../,./
                [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
                [^"'><,;|()]{1,})                   # Rest of the characters can't be

                |

                ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
                [a-zA-Z0-9_\-/]{1,}                 # Resource name
                \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
                (?:[\?|/][^"|']{0,}|))              # ? mark with parameters

                |

                ([a-zA-Z0-9_\-]{1,}                 # filename
                \.(?:php|asp|aspx|jsp|json|
                     action|html|js|txt|xml)        # . + extension
                (?:\?[^"|']{0,}|))                  # ? mark with parameters

            )

            (?:"|')                                 # End newline delimiter

        """

        response = self.messageInfo.getResponse()
        url = self.messageInfo.url.toString()
        # check if js file
        if url.endswith('.js'):
            # exclude specified js files
            if any(re.search(x, url) for x in exclusions):
                self._debug('URL excluded: {}'.format(url))
                return
            self._debug('URL found: {}'.format(url))
            print('{} ::'.format(url))
            mime_type = self.helpers.analyzeResponse(response).getStatedMimeType()
            links = []
            if mime_type.lower() == 'script':
                regex = re.compile(regex_str, re.VERBOSE)
                links += list(set([m.group(1) for m in re.finditer(regex, response)]))
            if links:
                for counter, link in enumerate(links):
                    self._debug('\t{} - {}'.format(counter, link))
                    print('{} :: {}'.format(url, link))
                self._create_issue(
                    issue_name='Links found in JavaScript file',
                    issue_detail='The following links were found in {}:\n\n<ul><li>{}</li></ul>'.format(url, '</li><li>'.join(links)),
                    severity='Information',
                )

    def _create_issue(self, issue_name, issue_detail, issue_background=None, remediation_detail=None, remediation_background=None, severity='High', confidence='Certain'):
        """Creates a Burp Suite issue.

        Severity: High, Medium, Low, Information, False positive
        Confidence: Certain, Firm, Tentative
        """

        issue = CustomIssue(
            BasePair=self.messageInfo,
            IssueName=issue_name,
            IssueDetail=issue_detail,
            IssueBackground=issue_background,
            RemediationDetail=remediation_detail,
            RemediationBackground=remediation_background,
            Severity=severity,
            Confidence=confidence,
        )
        self.callbacks.addScanIssue(issue)

    def extract_all_from_response(self, pattern):
        """Extracts multiple instances of a REGEX capture group from the 
        current response."""

        if not self._in_context(context='response'): return

        import re

        response = self.messageInfo.getResponse()
        matches = re.findall(pattern, response)
        for match in matches:
            print(match)

    def replace_response_body(self, url_pattern, body):
        """Replaces the body of a response from a matched URL.

        Great for swapping SPA UI build definitions between user roles.
        """

        if not self._in_context(context='response'): return

        import re

        url = self.messageInfo.url.toString()
        if re.search(url_pattern, url):
            response = self.messageInfo.getResponse()
            headers = self.helpers.analyzeResponse(response).getHeaders()
            new_response = self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(body))
            self.messageInfo.setResponse(new_response)
            self._debug('Response replaced from: {}'.format(url))


from burp import IScanIssue


class CustomIssue(IScanIssue):

    def __init__(self, BasePair, IssueName='Python Scripter generated issue', IssueDetail=None, IssueBackground=None, RemediationDetail=None, RemediationBackground=None, Severity='High', Confidence='Certain'):

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
