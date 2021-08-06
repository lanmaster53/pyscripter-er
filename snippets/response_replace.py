import re

# Replaces the body of a response from a matched URL.
# Great for swapping SPA UI build definitions between user roles.

url_pattern = r'<regex for response URL>'
body = r'''<new body>'''

if not messageIsRequest:
    url = messageInfo.url.toString()
    if re.search(url_pattern, url):
        response = messageInfo.getResponse()
        headers = helpers.analyzeResponse(response).getHeaders()
        new_response = helpers.buildHttpMessage(headers, helpers.stringToBytes(body))
        messageInfo.setResponse(new_response)
        print('Response replaced from: {}'.format(url))
