from ChopBinary import ChopBinary

moduleName='noop'
moduleVersion = '0.1'
minimumChopLib = '5.0'

def module_info():
    return 'NOOP module'

def init(module_data):
    # Currently returns nothing
    # This could return registered types, e.g., this module only handles 'pdf' type, if useful?
    return {}

# data is a ChopBinary type
# contains module_data which is the module-specific data
def handleData(data):
    chop.prnt("NOOP module called")

    # Default return of None won't call children
    # Return an instance of ChopBinary to send downstream
    # e.g.,:
    # cb = ChopBinary()
    # cb.data = "foo bar foo, my not so binary data"
    # cb.metadata['filename'] = 'foobarfoo'
    # return cb

def shutdown(module_data):
    pass
