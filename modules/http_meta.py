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

from optparse import OptionParser
from base64 import b64encode
from ChopProtocol import ChopProtocol

moduleName="http_meta"
moduleVersion="1.0"
minimumChopLib="4.0"

def module_info():
    return ("Convenience module to collate HTTP metadata. Requires 'http'"
            " parent module.\nGenerates'http_meta' type for downstream modules")

def init(module_data):
    module_options = { 'proto': [{'http':'http_meta'}]}
    parser = OptionParser()

    parser.add_option("-b", "--base64-encode", action="store_true",
        dest="base64_encode", default=False, help="Base64 Encode bodies")
    (options,lo) = parser.parse_args(module_data['args'])

    module_data['base64_encode'] = options.base64_encode

    return module_options

def handleProtocol(protocol):
    if protocol.type != 'http':
        chop.prnt("Error")
        return

    module_data = protocol.module_data
    data = {'request': protocol.clientData, 'response': protocol.serverData}

    # Convert the body to base64 encoded data, if it exists.
    if module_data['base64_encode']:
        if ('body' in data['request']
                and data['request']['body'] is not None):
            data['request']['body'] = b64encode(data['request']['body'])
            data['request']['body_encoding'] = 'base64'
        if ('body' in data['response']
                and data['response']['body'] is not None):
            data['response']['body'] = b64encode(data['response']['body'])
            data['response']['body_encoding'] = 'base64'

    chopp = ChopProtocol('http_meta')
    chopp.data = data
    chopp.flowStart = protocol.flowStart
    chopp.setTimeStamp(protocol.timestamp)
    chopp.setAddr(protocol.addr)
    
    return chopp

def teardownProtocol(protocol):
    if protocol.type != 'http':
        chop.prnt("Error")
        return

    module_data = protocol.module_data
    data = {'request': protocol.clientData, 'response': protocol.serverData}

    if module_data['base64_encode']:
        if (data['request'] is not None
                and 'body' in data['request']
                and data['request']['body'] is not None):
                data['request']['body'] = b64encode(data['request']['body'])
                data['request']['body_encoding'] = 'base64'

        if (data['response'] is not None
                and 'body' in data['response']
                and data['response']['body'] is not None):
                data['response']['body'] = b64encode(data['response']['body'])
                data['response']['body_encoding'] = 'base64'

    chopp = ChopProtocol('http_meta')
    chopp.data = data
    chopp.flowStart = protocol.flowStart
    chopp.setTimeStamp(protocol.timestamp)
    chopp.setAddr(protocol.addr)

    return chopp

def shutdown(module_data):
    return
