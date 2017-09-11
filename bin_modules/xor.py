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
#
# Some code taken from CRITs (https://github.com/crits/crits_services)
# peinfo service which falls under the following license:
# The MIT License (MIT)
#
# Copyright (c) 2017, The MITRE Corporation. All rights reserved.
#
# Approved for Public Release; Distribution Unlimited 14-1511
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# The purpose of this binshop module is to XOR data that is passed into it. It
# also has the ability to search for one-byte XOR keys using a set of
# pre-defined strings or a list of strings you provide it.

from __future__ import division


from ChopBinary import ChopBinary
from c2utils import one_byte_xor, multibyte_xor
from optparse import OptionParser

moduleName='xor'
moduleVersion = '0.1'
minimumChopLib = '5.0'

def module_info():
    return 'Process a blob using xor functionality from ext_libs.'

def init(module_data):
    parser = OptionParser()

    parser.add_option("-k", "--key", action="store", dest="key",
        default=None, help="XOR key to use.")
    parser.add_option("-m", "--multi-byte", action="store_true", dest="multi_byte",
        default=False, help="Perform multi-byte XOR.")
    parser.add_option("-o", "--one-byte", action="store_true", dest="one_byte",
        default=False, help="Perform one-byte XOR.")
    parser.add_option("-s", "--search", action="store_true", dest="search",
        default=False, help="Search for a one-byte XOR.")
    parser.add_option("-S", "--string-file", action="store", dest="string_file",
        default=None, help="List of string to use for XOR search.")

    (options,lo) = parser.parse_args(module_data['args'])
    module_data['key'] = options.key
    module_data['multi_byte'] = options.multi_byte
    module_data['one_byte'] = options.one_byte
    module_data['search'] = options.search
    module_data['string_file'] = options.string_file

    return {}

# data is a ChopBinary type
# contains module_data which is the module-specific data
def handleData(data):
    # Default return of None won't call children
    # Return an instance of ChopBinary to send downstream
    # e.g.,:
    cb = ChopBinary()
    cb.data = data.data
    key = data.module_data['key']
    search = data.module_data['search']
    string_file = data.module_data['string_file']

    if not key and not search:
        chop.prnt("No XOR key provided when not searching.")
        return
    if (not data.module_data['one_byte'] and
        not data.module_data['multi_byte'] and
        not search):
        chop.prnt("Must choose between one or multi byte or search")

    if data.module_data['one_byte']:
        #foo
        cb.metadata['one-byte'] = one_byte_xor(
            cb.data,
            int(key)
        )

    if data.module_data['multi_byte']:
        #foo
        cb.metadata['multi_byte'] = multibyte_xor(
            cb.data,
            key
        )

    if search:
        strings = [
            'This program',
            'kernel32',
            'KERNEL32',
            'http',
            'svchost',
            'Microsoft',
            'PE for WIN32',
            'startxref',
            '!This program cannot be run in DOS mode',
        ]
        if string_file:
            with open(string_file) as f:
                strings = f.read().splitlines()
        results = {}
        for s in strings:
            for i in range(0, 255):
                xord_string = one_byte_xor(s,i)
                if xord_string in cb.data:
                    results[i] = one_byte_xor(cb.data, i)
        cb.metadata['xor_search'] = results

    chop.prnt(cb.metadata)

    return cb

def shutdown(module_data):
    pass
