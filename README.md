# PyScripter-er

PyScripter-er (you can thank @kevcody for the name :-P) is a framework built on top of the Python Scripter Burp Suite extension.

PyScripter-er is designed to make wielding the power of Python Scripter easier by providing interfaces to common functionality not already provided within the Burp Suite set of tools.

## Usage

1. Configure Burp Extender's Python Environment to use Jython 2.7.1.
2. Place `pyscripterer.py` in the path configured for Burp Extender's Python Environment.
3. Manually install the modified Python Scripter extension (included in this repo).
    * The custom extension provides access to macros from within the script. Everything but the methods that require macros will work using the original Python Scripter extension.
4. Paste the following script into the "Script" tab.

```
from pyscripterer import BaseScript as Script

args = [extender, callbacks, helpers, toolFlag, messageIsRequest, messageInfo, macroItems]

script = Script(*args)
script.help()
```

5. Send a request from anywhere in Burp Suite.
6. View the output in the Extender tab.
7. Use methods independently, dependently, or with custom code to achieve a desired result.

## Development Notes

A message object is an Extender object that consists of both a request and a response. It represents a full request/response cycle.

A message's context is defined by where it came from and what stage of the request/response cycle it is in. For instance, a request coming from Repeater, or a response headed back through the Proxy. Enforcing context is essential to preventing scripts from acting on unintended parts of the message.

Scripts are evaluated on every request, response, and when a macro message is passed to the script from a session handling rule. Requests and responses from macros themselves are also evaluated, but are flagged as coming from the originating tool. The macro tool flag is only set when a message is sent from a macro to the Python Scripter extension using the "Run a macro" session handling rule.

For example, when using a macro that interacts with the Python Scripter extension, the script is evaluated five times:

| Step | Action | Tool Flag|
| :---: | --- | :---: |
| 1 | Macro request | any |
| 2 | Macro response | any |
| 3 | Session handling rule | macro |
| 4 | Final request | any |
| 5 | Final response | any |

The macro message object from step 2 is evaluated by the script via the session handling rule in step 3 along with the original message object and the macro tool flag. Here, scripts can make modifications to the original message based on information from the macro message before sending the message in step 4. You would obviously want to restrict that logic to a very specific context so that the script doesn't try to make the same change the other 4 times the script is evaluated.

When not using a macro, the flow is much simpler.

| Step | Action | Tool Flag|
| :---: | --- | :---: |
| 1 | request | any |
| 2 | response | any |

If you log things with Logger++ like me, then the below message flow diagram may be useful for debugging. BLUF, Logger++ always sees the modified message.

```
Burp -> Scripter (request) -> Logger++ -> application -> Scripter (response) -> Logger++ -> Burp
```

## Help

```
Help on BaseScript in module pyscripterer object:

class BaseScript(__builtin__.object)
 |  Methods defined here:
 |  
 |  __init__(self, extender, callbacks, helpers, toolFlag, messageIsRequest, messageInfo, macroItems)
 |  
 |  create_issue(self, issue_name, issue_detail, issue_background=None, remediation_detail=None, remediation_background=None, severity='High', confidence='Certain')
 |      Creates a Burp Suite issue.
 |      
 |      :param str severity:   `High`, `Medium`, `Low`, `Information`, `False positive`
 |      :param str confidence: `Certain`, `Firm`, `Tentative`
 |  
 |  extract_all_from_response(self, pattern)
 |      Extracts multiple instances of a REGEX capture group from the 
 |      current response.
 |  
 |  get_bearer_token(self, headers)
 |      Gets the Bearer token from a list of headers.
 |  
 |  get_header_value(self, header_name, headers)
 |      Gets the value of a header from a list of headers.
 |  
 |  get_jwt_payload(self, token)
 |      Parses the payload from a JWT.
 |  
 |  help(self)
 |      Displays this help interface.
 |  
 |  introspect(self)
 |      Provides introspection into the Python Scripter API.
 |  
 |  is_in_context(self, context=None, tools=[], scope=False)
 |      Checks the provided parameters against the current context.
 |      
 |      :param str context: Target message type for action, `request` or `response`
 |      :param list tools:  List of tool flags for tools to act upon
 |      :param bool scope:  Restrict action to scope?
 |      :return:            Whether or not the current context matches
 |      :rtype:             bool
 |  
 |  is_in_scope(self)
 |      Determines if the current message is in scope.
 |  
 |  is_jwt_expired(self, token)
 |      Checks the expiry of a JWT.
 |  
 |  passive_autocomplete_text(self)
 |      Checks for autocomplete on text fields in the current response.
 |  
 |  passive_json_params(self)
 |      Finds JSON parameters within JSON responses.
 |  
 |  passive_link_finder(self, exclusions=[])
 |      Finds links within JavaScript files.
 |  
 |  passive_verbose_headers(self)
 |      Checks for verbose headers in the current response.
 |  
 |  remove_header(self, header_name, headers)
 |      Removes a specific header from a list of headers.
 |  
 |  remove_request_headers(self, header_names)
 |      Removes a list of headers from the current request.
 |  
 |  replace_bearer_token(self, new_token)
 |      Replaces the Bearer token in the current request with the provided
 |      token.
 |  
 |  replace_bearer_token_macro(self, pattern)
 |      Replaces the Bearer token in the current request with a token 
 |      extracted from a macro response.
 |      
 |      Requires a session handling rule to pass the result of a macro to the 
 |      extension.
 |      
 |      Tip: Create and copy the REGEX pattern from the macro editor.
 |  
 |  replace_response_body(self, url_pattern, body)
 |      Replaces the body of a response from a matched URL.
 |  
```
