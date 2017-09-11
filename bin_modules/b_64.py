# ChopShop specific code falls under the following license:
#
# Copyright (c) 2017 The MITRE Corporation. All rights reserved.
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

# The purpose of this binshop module is to b64decode data that is provided.

from __future__ import division


from ChopBinary import ChopBinary
from b64 import b64decode
from optparse import OptionParser

moduleName='b_64'
moduleVersion = '0.1'
minimumChopLib = '5.0'

def module_info():
    return 'Process a blob using b64decode from ext_libs.'

def init(module_data):
    parser = OptionParser()
    alpha='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    parser.add_option("-a", "--alpha", action="store", dest="alpha",
        default=alpha, help="Custom alphabet to use.")
    parser.add_option("-p", "--pad-byte", action="store", dest="padbyte",
        default='=', help="Custom padbyte to use.")
    parser.add_option("-s", "--no-strict", action="store", dest="strict",
        default=True, help="Disable strict.")

    (options,lo) = parser.parse_args(module_data['args'])
    module_data['alpha'] = options.alpha
    module_data['padbyte'] = options.padbyte
    module_data['strict'] = options.strict

    return {}

# data is a ChopBinary type
# contains module_data which is the module-specific data
def handleData(data):
    # Default return of None won't call children
    # Return an instance of ChopBinary to send downstream
    # e.g.,:
    cb = ChopBinary()
    cb.data = data.data

    cb.metadata['decode'] = b64decode(
        cb.data,
        alpha=data.module_data['alpha'],
        padbyte=data.module_data['padbyte'],
        strict=data.module_data['strict'],
    )

    chop.prnt(cb.metadata)

    return cb

def shutdown(module_data):
    pass
