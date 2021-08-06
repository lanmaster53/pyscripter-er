# Fetches and replaces a Bearer token in the current request.

def get_new_token():

    url = '<url>'
    username = '<username>'
    password = '<password>'

    import urllib2
    import json

    data = {
        'username': username,
        'password': password,
    }
    req = urllib2.Request(url)
    req.add_header('Content-Type', 'application/json')
    response = urllib2.urlopen(req, json.dumps(data))
    data = json.load(response)
    token = data.get('token', '')
    print('New token obtained.')
    return token

# only apply to repeater
if toolFlag == callbacks.TOOL_REPEATER:
    # only apply to requests
    if messageIsRequest:
        # obtain a new token
        new_token = get_new_token()
        # remove any existing Authorization header
        request = helpers.analyzeRequest(messageInfo)
        headers = request.getHeaders()
        for header in headers:
            if header.startswith('Authorization'):
                headers.remove(header)
                break
        # add a new Authorization header with the new token
        headers.add('Authorization: Bearer {}'.format(new_token))
        body = messageInfo.getRequest()[request.getBodyOffset():]
        new_request = helpers.buildHttpMessage(headers, body)
        messageInfo.setRequest(new_request)
        print('Token replaced.')
