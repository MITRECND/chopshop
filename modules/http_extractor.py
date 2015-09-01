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

from c2utils import packet_timedate, sanitize_filename, parse_addr
from optparse import OptionParser
from base64 import b64encode

moduleName="http_extractor"
moduleVersion="2.0"
minimumChopLib="4.0"

def module_info():
    return "Extract HTTP information. Requires 'http' parent module. Print or generate JSON"

def init(module_data):
    module_options = { 'proto': [{'http':''}]}
    parser = OptionParser()

    parser.add_option("-s", "--carve_response_body", action="store_true",
        dest="carve_response", default=False, help="Save response body")
    parser.add_option("-S", "--carve_request_body", action="store_true",
        dest="carve_request", default=False, help="Save request body")
    parser.add_option("-f", "--fields", action="store", dest="fields",
        default=[], help="Comma separated list of fields to extract")
    parser.add_option("-m", "--hash_body", action="store_true", dest="hash_body",
        default=False, help="Save hash of body and throw contents away")


    (options,lo) = parser.parse_args(module_data['args'])

    module_data['counter'] = 0
    module_data['carve_request'] = options.carve_request
    module_data['carve_response'] = options.carve_response
    module_data['hash_body'] = options.hash_body
    module_data['fields'] = []

    if options.fields:
        fields = options.fields.split(',')
        for field in fields:
            chop.prnt("Extracting field: %s" % field)
        module_data['fields'] = fields

    return module_options

def handleProtocol(protocol):
    if protocol.type != 'http':
        chop.prnt("Error")
        return

    module_data = protocol.module_data
    data = {'request': protocol.clientData, 'response': protocol.serverData}

    if data['request']['body'] is None:
        del data['request']['body']
        del data['request']['body_hash']
    elif module_data['hash_body']:
        del data['request']['body']

    if data['response']['body'] is None:
        del data['response']['body']
        del data['response']['body_hash']
    elif module_data['hash_body']:
        del data['response']['body']

    del data['request']['truncated']
    del data['request']['body_len']
    del data['request']['hash_fn']

    del data['response']['truncated']
    del data['response']['body_len']
    del data['response']['hash_fn']

    fields = module_data['fields']
    if fields:
        req_fields = fields + ['uri', 'method']
        new_headers = {}
        for header in data['request']['headers']:
            if header in req_fields:
               new_headers[header] = data['request']['headers'][header] 

        for element in data['request'].keys():
            if element not in req_fields:
                del data['request'][element]

        #Set the new headers dictionary
        data['request']['headers'] = new_headers

        res_fields = fields + ['status']
        new_headers = {}
        for header in data['response']['headers']:
            if header in res_fields:
                new_headers[header] = data['response']['headers'][header]

        for element in data['response'].keys():
            if element not in res_fields:
                del data['response'][element]

        data['response']['headers'] = new_headers
            
    if module_data['carve_request'] and 'body' in data['request']:
        fname = sanitize_filename(data['request']['uri']['path'][1:]) + '.request.' + str(module_data['counter'])
        chop.prnt("DUMPING REQUEST: %s (%i)" % (fname, len(data['request']['body'])))
        chop.savefile(fname, data['request']['body'])
        module_data['counter'] += 1

    if module_data['carve_response'] and 'body' in data['response']:
        fname = sanitize_filename(data['request']['uri']['path'][1:]) + '.response.' + str(module_data['counter'])
        chop.prnt("DUMPING RESPONSE: %s (%i)" % (fname, len(data['response']['body'])))
        chop.savefile(fname, data['response']['body'])
        module_data['counter'] += 1

    # Convert the body to base64 encoded data, if it exists.
    if 'body' in data['request']:
        data['request']['body'] = b64encode(data['request']['body'])
        data['request']['body_encoding'] = 'base64'
    if 'body' in data['response']:
        data['response']['body'] = b64encode(data['response']['body'])
        data['response']['body_encoding'] = 'base64'

    chop.prnt(data)
    chop.json(data)
    
    return

def teardownProtocol(protocol):
    if protocol.type != 'http':
        chop.prnt("Error")
        return

    module_data = protocol.module_data
    data = {'request': protocol.clientData, 'response': protocol.serverData}

    if data['request'] is not None:

        if data['request']['body'] is None:
            del data['request']['body']
            del data['request']['body_hash']
        elif module_data['hash_body']:
            del data['request']['body']

        del data['request']['truncated']
        del data['request']['body_len']
        del data['request']['hash_fn']

    if data['response'] is not None:
        if data['response']['body'] is None:
            del data['response']['body']
            del data['response']['body_hash']
        elif module_data['hash_body']:
            del data['response']['body']

        del data['response']['truncated']
        del data['response']['body_len']
        del data['response']['hash_fn']


    fields = module_data['fields']
    if fields:
        if data['request'] is not None:
            req_fields = fields + ['uri', 'method']
            new_headers = {}
            for header in data['request']['headers']:
                if header in req_fields:
                   new_headers[header] = data['request']['headers'][header]

            for element in data['request'].keys():
                if element not in req_fields:
                    del data['request'][element]

            #Set the new headers dictionary
            data['request']['headers'] = new_headers

        if data['response'] is not None:
            res_fields = fields + ['status']
            new_headers = {}
            for header in data['response']['headers']:
                if header in res_fields:
                    new_headers[header] = data['response']['headers'][header]

            for element in data['response'].keys():
                if element not in res_fields:
                    del data['response'][element]

            data['response']['headers'] = new_headers

    if data['request'] is not None:
        if module_data['carve_request'] and 'body' in data['request']:
            fname = sanitize_filename(data['request']['uri']['path'][1:]) + '.request.' + str(module_data['counter'])
            chop.prnt("DUMPING REQUEST: %s (%i)" % (fname, len(data['request']['body'])))
            chop.savefile(fname, data['request']['body'])
            module_data['counter'] += 1

        if 'body' in data['request']:
            data['request']['body'] = b64encode(data['request']['body'])
            data['request']['body_encoding'] = 'base64'

    if data['response'] is not None:
        if module_data['carve_response'] and 'body' in data['response']:
            fname = sanitize_filename(data['request']['uri']['path'][1:]) + '.response.' + str(module_data['counter'])
            chop.prnt("DUMPING RESPONSE: %s (%i)" % (fname, len(data['response']['body'])))
            chop.savefile(fname, data['response']['body'])
            module_data['counter'] += 1

        if 'body' in data['response']:
            data['response']['body'] = b64encode(data['response']['body'])
            data['response']['body_encoding'] = 'base64'


    chop.prnt(data)
    chop.json(data)

    return

def shutdown(module_data):
    return
