from pyscripter_utils import CustomIssue
import re
import sys

# Adds custom passive audit checks.
# Requires pyscripter_utils.py to be loaded with Burp.

if not messageIsRequest:
    if toolFlag in (callbacks.TOOL_PROXY,):
        if callbacks.isInScope(messageInfo.getUrl()):
            response = messageInfo.getResponse()

            # Checks for autocomplete on text form fields.
            results = re.findall(r'(<input [^>]*>)', response)
            for result in results:
                if re.search(r'''type=['"]text['"]''', result) and not re.search(r'autocomplete=[\'"]off[\'"]', result):
                    issue = CustomIssue(
                        callbacks=callbacks,
                        BasePair=messageInfo,
                        IssueName='Text field with autocomplete enabled',
                        IssueDetail='The following text field has autocomplete enabled:\n\n<ul><li>' + result.replace('<', '&lt;').replace('>', '&gt;') + '</li></ul>',
                        Severity='Low',
                    )
                    issue.addCustomIssue()

            # Checks for verbose headers.
            bad_headers = ('server', 'x-powered-by', 'x-aspnet-version')
            headers = helpers.analyzeResponse(messageInfo.getResponse()).getHeaders()
            for header in headers:
                name = header.split(':')[0]
                if name.lower() in bad_headers:
                    issue = CustomIssue(
                        callbacks=callbacks,
                        BasePair=messageInfo,
                        IssueName='Verbose header',
                        IssueDetail='The following HTTP response header may disclose sensitive information:\n\n<ul><li>' + header + '</li></ul>',
                        Severity='Low',
                    )
                    issue.addCustomIssue()
