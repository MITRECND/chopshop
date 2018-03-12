
import os
import imp
import traceback

def loadModule(name, path):
    cwd = os.path.dirname(os.path.abspath(__file__))
    path.append(cwd)
    try:
        (file, pathname, description) = imp.find_module(name, path)
        loaded_mod = imp.load_module(name, file, pathname, description)
    except Exception, e:
        tb = traceback.format_exc()
        raise Exception(tb)

    return loaded_mod
