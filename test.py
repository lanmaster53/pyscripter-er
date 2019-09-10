from pyscripterer import BaseScript as Script

args = [extender, callbacks, helpers, toolFlag, messageIsRequest, messageInfo, macroItems]

script = Script(*args)
script.debug = True

#script.help()

# utility tests
if messageIsRequest:
    #request = helpers.analyzeRequest(messageInfo.getRequest())
    #headers = request.getHeaders()
    #bearer = script.get_bearer_token(headers)
    #print(bearer)
    #payload = script.get_jwt_payload(bearer)
    #print(payload)
    #script.introspect()
    #print(script.is_in_scope())
    #expired = script.is_jwt_expired(bearer)
    #print(expired)
    #print(headers)
    #headers = script.remove_header('Authorization', headers)
    #print(headers)
    pass

# passive analysis tests
#script.passive_autocomplete_text()
#script.passive_json_params()
#script.passive_link_finder()
#script.passive_verbose_headers()

# message modification tests
#script.extract_all_from_response(r'(<input [^>]*>)')
#script.remove_request_headers(['Authorization'])
#script.replace_bearer_token('csdcdscdscds')
#script.replace_bearer_token_macro('_token=(.*?); HttpOnly')
#script.replace_response_body('/messages', 'cdscdscdscs')
