class BaseScript(object):

    def __init__(self, extender, callbacks, helpers, toolFlag, messageIsRequest, messageInfo, macroItems=[]):

        self.extender = extender
        self.callbacks = callbacks
        self.helpers = helpers
        self.toolFlag = toolFlag
        self.messageIsRequest = messageIsRequest
        self.messageInfo = messageInfo
        self.macroItems = macroItems
        self.debug = False

    def _debug(self, message):
        """Provides an interface for verbose output."""

        if self.debug:
            print('[DEBUG] {}'.format(message))

    #################
    # Context Methods
    #################

    def is_in_context(self, context=None, tools=[], scope=False):
        """Checks the provided parameters against the current context.

        :param str context: Target message type for action, `request` or `response`
        :param list tools:  List of tool flags for tools to act upon
        :param bool scope:  Restrict action to scope?
        :return:            Whether or not the current context matches
        :rtype:             bool
        """

        if (context and
            context.lower() == 'request' and not self.messageIsRequest or
            context.lower() == 'response' and self.messageIsRequest):
            return False
        if (tools and self.toolFlag not in tools):
            return False
        if (scope and not self.is_in_scope()):
            return False
        return True

    def is_in_scope(self):
        """Determines if the current message is in scope."""

        in_scope = self.callbacks.isInScope(self.messageInfo.getUrl())
        mode = 'Response' if self.messageIsRequest else 'Request'
        scope = 'in scope' if in_scope else 'not in scope'
        url = self.messageInfo.url.toString()
        self._debug('{} {}: {}'.format(mode, scope, url))
        return in_scope

    ###############
    # Usage Methods
    ###############

    def help(self):
        """Displays this help interface."""

        if not self.is_in_context(context='request'): return

        print(help(self))

    def introspect(self):
        """Provides introspection into the Python Scripter API."""

        if not self.is_in_context(context='request'): return

        import sys

        apis = ('extender', 'callbacks', 'helpers', 'toolFlag', 'messageIsRequest', 'messageInfo')
        funcs = (type, dir)

        for api in apis:
            print('\n{}:\n{}'.format(api, '='*len(api)))
            for func in funcs:
                print('\n{}:\n'.format(func.__name__))
                print(func(getattr(self, api)))
        self._debug('Introspection complete.')

    #################
    # Utility Methods
    #################

    def remove_header(self, header_name, headers):
        """Removes a specific header from a list of headers."""

        for header in headers:
            if header.startswith(header_name):
                headers.remove(header)
                self._debug('Header removed: {}'.format(header_name))
                break
        return headers

    def get_header_value(self, header_name, headers):
        """Gets the value of a header from a list of headers."""

        for header in headers:
            if header.lower().startswith(header_name.lower()):
                self._debug(header)
                return header.split(":")[1]
        return None

    def get_jwt_payload(self, token):
        """Parses the payload from a JWT."""

        import json
        import base64

        encoded_payload = token.split('.')[1]
        payload = json.loads(base64.b64decode(encoded_payload + "==="))
        return payload

    def is_jwt_expired(self, token):
        """Checks the expiry of a JWT."""

        payload = self.get_jwt_payload(token)
        return payload['exp'] < payload['iat']

    def get_bearer_token(self, headers):
        """Gets the Bearer token from a list of headers."""

        authz = self.get_header_value('Authorization', headers)
        if authz:
            segments = authz.split()
            if len(segments) == 2 and segments[0] == 'Bearer':
                return segments[1]
        return None

    ##############################
    # Message Modification Methods
    ##############################

    def remove_request_headers(self, header_names):
        """Removes a list of headers from the current request."""

        if not self.is_in_context(context='request'): return

        request = self.helpers.analyzeRequest(self.messageInfo.getRequest())
        headers = request.getHeaders()
        for header_name in header_names:
            headers = self.remove_header(header_name, headers)
        body = self.messageInfo.getRequest()[request.getBodyOffset():]
        new_request = self.helpers.buildHttpMessage(headers, body)
        self.messageInfo.setRequest(new_request)
        self._debug('Headers removed: {}'.format(', '.join(header_names)))

    def _replace_bearer_token(self, new_token):
        """Replaces the Bearer token in the current request."""

        request = self.helpers.analyzeRequest(self.messageInfo.getRequest())
        headers = request.getHeaders()
        headers = self.remove_header('Authorization', headers)
        headers.add('Authorization: Bearer {}'.format(new_token))
        body = self.messageInfo.getRequest()[request.getBodyOffset():]
        new_request = self.helpers.buildHttpMessage(headers, body)
        self.messageInfo.setRequest(new_request)
        self._debug('Token replaced.')

    def replace_bearer_token(self, new_token):
        """Replaces the Bearer token in the current request with the provided
        token."""

        if not self.is_in_context(context='request'): return

        self._replace_bearer_token(new_token)

    def replace_bearer_token_macro(self, pattern):
        """Replaces the Bearer token in the current request with a token 
        extracted from a macro response.

        Requires a session handling rule to pass the result of a macro to the 
        extension.

        Tip: Create and copy the REGEX pattern from the macro editor.
        """

        if not self.is_in_context(context='request', tools=[self.callbacks.TOOL_MACRO]): return

        import re

        response_bytes = self.macroItems[0].getResponse()
        match = re.search(pattern, response_bytes)
        if not match:
            self._debug('Macro token not found.')
            return
        self._replace_bearer_token(match.group(1))

    def extract_all_from_response(self, pattern):
        """Extracts multiple instances of a REGEX capture group from the 
        current response."""

        if not self.is_in_context(context='response'): return

        import re

        response_bytes = self.messageInfo.getResponse()
        matches = re.findall(pattern, response_bytes)
        for match in matches:
            print(match)

    def replace_response_body(self, url_pattern, body):
        """Replaces the body of a response from a matched URL."""

        if not self.is_in_context(context='response'): return

        import re

        url = self.messageInfo.url.toString()
        if re.search(url_pattern, url):
            response_bytes = self.messageInfo.getResponse()
            headers = self.helpers.analyzeResponse(response_bytes).getHeaders()
            new_response = self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(body))
            self.messageInfo.setResponse(new_response)
            self._debug('Response replaced from: {}'.format(url))

    ##########################
    # Passive Analysis Methods
    ##########################

    def passive_autocomplete_text(self):
        """Checks for autocomplete on text fields in the current response."""

        if not self.is_in_context(context='response',
                                tools=[self.callbacks.TOOL_PROXY],
                                scope=True): return

        import re

        response_bytes = self.messageInfo.getResponse()
        results = []
        for result in re.findall(r'(<input [^>]*>)', response_bytes):
            if re.search(r'''type=['"]text['"]''', result) and not re.search(r'autocomplete', result):
                results.append(result.replace('<', '&lt;').replace('>', '&gt;'))
        if results:
            self.create_issue(
                issue_name='Text field with autocomplete enabled',
                issue_detail='The following text fields have autocomplete enabled:\n\n<ul><li>{}</li></ul>'.format('</li><li>'.join(results)),
                severity='Low',
            )
        self._debug('Passive check applied: Autocomplete Enabled')

    def passive_verbose_headers(self):
        """Checks for verbose headers in the current response."""

        if not self.is_in_context(context='response',
                                tools=[self.callbacks.TOOL_PROXY],
                                scope=True): return

        bad_headers = ('server', 'x-powered-by', 'x-aspnet-version')
        response_bytes = self.messageInfo.getResponse()
        headers = self.helpers.analyzeResponse(response_bytes).getHeaders()
        verbose_headers = []
        interesting_headers = []
        for header in headers:
            name = header.split(':')[0]
            # known bad headers
            if name.lower() in bad_headers:
                verbose_headers.append(header)
            # custom headers
            elif name.lower().startswith('x-'):
                interesting_headers.append(header)
        if verbose_headers:
            self.create_issue(
                issue_name='Verbose header',
                issue_detail='The following HTTP response headers may disclose sensitive information:\n\n<ul><li>{}</li></ul>'.format('</li><li>'.join(verbose_headers)),
                severity='Low',
            )
        if interesting_headers:
            self.create_issue(
                issue_name='Interesting header',
                issue_detail='The following HTTP response headers may disclose sensitive information:\n\n<ul><li>{}</li></ul>'.format('</li><li>'.join(interesting_headers)),
                severity='Low',
                confidence='Tentative',
            )
        self._debug('Passive check applied: Verbose Headers')

    def passive_link_finder(self, exclusions=[]):
        """Finds links within JavaScript files."""

        if not self.is_in_context(context='response',
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

        response_bytes = self.messageInfo.getResponse()
        url = self.messageInfo.url.toString()
        # check if js file
        if url.endswith('.js'):
            # exclude specified js files
            if any(re.search(x, url) for x in exclusions):
                self._debug('URL excluded: {}'.format(url))
                return
            self._debug('URL found: {}'.format(url))
            print('{} ::'.format(url))
            mime_type = self.helpers.analyzeResponse(response_bytes).getStatedMimeType()
            links = []
            if mime_type.lower() == 'script':
                regex = re.compile(regex_str, re.VERBOSE)
                links += list(set([m.group(1) for m in re.finditer(regex, response_bytes)]))
            if links:
                links.sort(key=lambda x:x[1])
                for counter, link in enumerate(links):
                    self._debug('\t{} - {}'.format(counter, link))
                    print('{} :: {}'.format(url, link))
                self.create_issue(
                    issue_name='Links found in JavaScript file',
                    issue_detail='The following links were found:\n\n<ul><li>{}</li></ul>'.format('</li><li>'.join(links)),
                    severity='Information',
                )

    def _extract_dict_keys(self, var):
        """Recursively extracts all keys from a JSON object."""

        if isinstance(var, dict):
            for k, v in var.items():
                yield k
                if isinstance(v, (dict, list)):
                    for result in self._extract_dict_keys(v):
                        yield result
        elif isinstance(var, list):
            for i in var:
                for result in self._extract_dict_keys(i):
                    yield result

    def passive_json_params(self):
        """Finds JSON parameters within JSON responses."""

        if not self.is_in_context(context='response',
                                tools=[self.callbacks.TOOL_PROXY],
                                scope=True): return

        import json

        supported_content_types = [
            "application/json",
            "text/json",
            "text/x-json",
        ]

        response_bytes = self.messageInfo.getResponse()
        response = self.helpers.analyzeResponse(response_bytes)
        content_type = self.get_header_value('content-type', response.getHeaders()) or ''
        for allowed in supported_content_types:
            if content_type.find(allowed) > 0:
                msg = response_bytes[response.getBodyOffset():].tostring()
                self._debug('Body: {}'.format(msg))
                json_obj = json.loads(msg)
                params = list(set(self._extract_dict_keys(json_obj)))
                self._debug('Params: {}'.format(params))
                self.create_issue(
                    issue_name='JSON parameters',
                    issue_detail='The following JSON parameters were found:\n\n<ul><li>{}</li></ul>'.format('</li><li>'.join(params)),
                    severity='Information',
                )
                break

    ######################
    # Custom Issue Methods
    ######################

    def create_issue(self, issue_name, issue_detail, issue_background=None, remediation_detail=None, remediation_background=None, severity='High', confidence='Certain'):
        """Creates a Burp Suite issue.

        :param str severity:   `High`, `Medium`, `Low`, `Information`, `False positive`
        :param str confidence: `Certain`, `Firm`, `Tentative`
        """

        custom_issue = CustomIssue(
            BasePair=self.messageInfo,
            IssueName=issue_name,
            IssueDetail=issue_detail,
            IssueBackground=issue_background,
            RemediationDetail=remediation_detail,
            RemediationBackground=remediation_background,
            Severity=severity,
            Confidence=confidence,
        )

        rawUrl = self.messageInfo.url
        url = rawUrl.getProtocol()+"://"+rawUrl.getHost()+rawUrl.getPath()
        for issue in self.callbacks.getScanIssues(url):
            if custom_issue.isDuplicate(issue):
                self._debug('Duplicate issue: {}'.format(custom_issue.IssueName))
                return
        self.callbacks.addScanIssue(custom_issue)


from burp import IScanIssue
from hashlib import md5
import re


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

    def isDuplicate(self, issue):

        m = re.search(r'\[sig:([^\]]+)\]', issue.issueDetail or '')
        if m and m.group(1) == self.Signature:
            return True
        return False

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
