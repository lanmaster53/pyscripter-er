import re
import sys

# Extracts multiple instances of a REGEX capture group from responses.

pattern = r'<regex>'

if not messageIsRequest:
    response = messageInfo.getResponse()
    matches = re.findall(pattern, response)
    for match in matches:
        print(match)
