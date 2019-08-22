# Burp PyScripter

Burp PyScripter is a framework built on top of the Python Scripter Burp Suite extension.

Burp PyScripter is designed to make wielding the power of Python Scripter easier by providing interfaces to common functionality not already provided within the Burp Suite set of tools.

## Usage

1. Place `pyscripter.py` in the path configured for Burp Extender's Python Environment.
2. Install the "Python Scripter" BApp.
3. Paste the following script into the "Script" tab.

```
from pyscripter import BaseScript as Script

args = [extender, callbacks, helpers, toolFlag, messageIsRequest, messageInfo]

script = Script(*args)
script.help()
```

4. Send a request from anywhere in Burp Suite.
5. View the output in the Extender tab.
