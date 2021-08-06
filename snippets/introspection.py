import sys

# Provides introspection into the Python Scripter API.

apis = ('extender', 'callbacks', 'helpers', 'toolFlag', 'messageIsRequest', 'messageInfo')
funcs = (type, dir)

if messageIsRequest:
    for api in apis:
        print('\n{}:\n{}'.format(api, '='*len(api)))
        for func in funcs:
            print('\n{}:\n'.format(func.__name__))
            try:
                print(func(locals()[api]))
            except Exception as e:
                print(func(globals()[api]))
