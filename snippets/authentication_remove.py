# Removes authentication information from the current request.

header_names = ['Cookie', 'Authorization']

# only apply to target
if toolFlag == callbacks.TOOL_TARGET:
    # only apply to requests
    if messageIsRequest:
        request = helpers.analyzeRequest(messageInfo)
        headers = request.getHeaders()
        for header_name in header_names:
            for header in headers:
                if header.startswith(header_name):
                    headers.remove(header)
                    print('Header removed: {}'.format(header_name))
                    break
        body = messageInfo.getRequest()[request.getBodyOffset():]
        new_request = helpers.buildHttpMessage(headers, body)
        messageInfo.setRequest(new_request)
