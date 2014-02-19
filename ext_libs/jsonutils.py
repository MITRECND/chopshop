# Copyright (c) 2014 The MITRE Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

"""
JSON utilities including encoders, decoders, other parsers or handlers
"""

from types import NoneType 
from json import JSONEncoder


#JSON Encoder that attempts to take the represenational string or string 
#value of an object if it is not one of the default types recognized by 
#JSONEncoder. All default types are directly passed to the parent class
class jsonOrReprEncoder(JSONEncoder):
    def default(self,obj):
        #Check if it's a default type
        if not(
            isinstance(obj, dict)       or 
            isinstance(obj, list)       or 
            isinstance(obj, tuple)      or
            isinstance(obj, str)        or
            isinstance(obj, unicode)    or 
            isinstance(obj, int)        or 
            isinstance(obj, long)       or 
            isinstance(obj, float)      or 
            isinstance(obj, bool)       or
            isinstance(obj, NoneType)
           ) :
            try:
                return obj.__repr__()
            except:
                try:
                    return obj.__str__()
                except:
                    pass

        #If all else fails let the parent class throw an exception
        return JSONEncoder(self, obj) 

#JSON Encoder that attempts to take the string or representational value
#of an object if it not one of the default types recognized by
#JSONEncoder. All direct types are directly passed to parent class
class jsonOrStrEncoder(JSONEncoder):
    def default(self,obj):
        #Check if it's a default type
        if not(
            isinstance(obj, dict)       or 
            isinstance(obj, list)       or 
            isinstance(obj, tuple)      or
            isinstance(obj, str)        or
            isinstance(obj, unicode)    or 
            isinstance(obj, int)        or 
            isinstance(obj, long)       or 
            isinstance(obj, float)      or 
            isinstance(obj, bool)       or
            isinstance(obj, NoneType)
           ) :
            #Technically, this is probably the same as str(obj)
            try:
                return obj.__str__()
            except:
                try:
                    return obj.__repr__()
                except:
                    pass

        #If all else fails let the parent class throw an exception
        return JSONEncoder(self, obj) 

