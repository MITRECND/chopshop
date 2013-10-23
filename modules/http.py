# Copyright (c) 2013 The MITRE Corporation. All rights reserved.
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
import json
import htpy
import hashlib

import sys
import os
import Queue

from ChopProtocol import ChopProtocol


#TODO Add more error checking
# See if any useful information is missing
# Check body lenght limits

moduleName ="http"
moduleVersion ='0.1'
minimumChopLib ='4.0'

def log(cp, msg, level, obj):
    if level == htpy.HTP_LOG_ERROR:
        elog = cp.get_last_error()
        if elog == None:
            return htpy.HTP_ERROR
        chop.prnt("%s:%i - %s (%i)" % (elog['file'], elog['line'], elog['msg'], elog['level']))
    else:
        chop.prnt("%i - %s" % (level, msg))
    return htpy.HTP_OK

# The request and response body callbacks are treated identical with one
# exception: the location in the output dictionary where the data is stored.
# Because they are otherwise identical each body callback is a thin wrapper
# around the real callback.
def request_body(data, length, obj):
    return body(data, length, obj, 'request')

def response_body(data, length, obj):
    return body(data, length, obj, 'response')

def body(data, length, obj, direction):
    trans = obj['temp']

    if length == 0:
        if 'body' not in trans[direction]:
            return htpy.HTP_OK

        #if obj['module_data']['md5_body']:
        #    d[direction]['body_md5'] = hashlib.md5(d[direction]['body']).hexdigest()
        #    del d[direction]['body']

        # Only dump if direction is 'response', otherwise POST causes
        # one dump for request and another for response.
        #if direction == 'response':
        #    dump(obj['module_data'], d)
        return htpy.HTP_OK

    if 'body' in trans[direction]:
        trans[direction]['body'] += data
    else:
        trans[direction]['body'] = data

    #if obj['module_data']['blen'] != 0 and len(d[direction]['body']) >= obj['module_data']['blen']:
    #    d[direction]['body'] = d[direction]['body'][:obj['module_data']['blen']]
    return htpy.HTP_OK

def request_headers(cp, obj):
    trans = obj['temp']
    trans['start'] = obj['timestamp']
    trans['request'] = {}
    trans['request']['headers'] = cp.get_all_request_headers()
    trans['request']['uri'] = cp.get_uri()
    trans['request']['method'] = cp.get_method()

    protocol = cp.get_request_protocol_number()
    proto = "HTTP/"

    if protocol == htpy.HTP_PROTOCOL_UNKNOWN:
        proto = "UNKNOWN"
    elif protocol == htpy.HTP_PROTOCOL_0_9:
        proto += "0.9"
    elif protocol == htpy.HTP_PROTOCOL_1_0:
        proto += "1.0"
    elif protocol == htpy.HTP_PROTOCOL_1_1:
        proto += "1.1"
    else:
        proto = "Error"

    trans['request']['protocol'] = proto

    return htpy.HTP_OK

def request_complete(cp, obj):
    #Move request data to the lines queue
    obj['lines'].put(obj['temp']['request'])
    obj['temp']['request'] = {}

    return htpy.HTP_OK

def response_headers(cp, obj):
    trans = obj['temp']
    trans['response'] = {}
    trans['response']['headers'] = cp.get_all_response_headers()
    trans['response']['status'] = cp.get_response_status()

    return htpy.HTP_OK

def response_complete(cp, obj):
    trans = obj['temp']
    try:
        req = obj['lines'].get(False) #Do not block
    except Queue.Empty:
        pass
        #TODO error

    obj['transaction'] = {
                'request': req,
                'response' : trans['response'],
                'timestamp' : trans['start'],
                }

    obj['ready'] = True

    return htpy.HTP_OK

def module_info():
    return "Takes in TCP traffic and outpus parsed HTTP traffic for use by secondary modules. Refer to the docs for output format"

def init(module_data):
    module_options = { 'proto': [ {'tcp': 'http'}]}
    parser = OptionParser()

    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
        default=False, help="Be verbose about incoming packets")
    parser.add_option("-b", "--no-body", action="store_true", dest="nobody",
        default=False, help="Do not process http bodies")

    (options,lo) = parser.parse_args(module_data['args'])

    module_data['counter'] = 0
    module_data['options'] = { 
                                'verbose' : options.verbose, 
                                'no-body' : options.nobody
                             }

    return module_options

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    if sport != 80 and dport != 80:
        return False

    if tcp.module_data['options']['verbose']:
        chop.tsprnt("New session: %s:%s->%s:%s" % (src, sport, dst, dport))


    tcp.stream_data['htpy_obj'] = {
                                    'options': tcp.module_data['options'],
                                    'timestamp': None, 
                                    'temp': {},
                                    'transaction': {},
                                    'lines': Queue.Queue(),
                                    'ready': False,
                                    'flowStart': tcp.timestamp
                                   }

    tcp.stream_data['connparser'] = htpy.init()
    tcp.stream_data['connparser'].set_obj(tcp.stream_data['htpy_obj'])
    tcp.stream_data['connparser'].register_log(log)
    tcp.stream_data['connparser'].register_request_headers(request_headers)
    tcp.stream_data['connparser'].register_response_headers(response_headers)
    tcp.stream_data['connparser'].register_request_body_data(request_body)
    tcp.stream_data['connparser'].register_response_body_data(response_body)
    tcp.stream_data['connparser'].register_request_complete(request_complete)
    tcp.stream_data['connparser'].register_response_complete(response_complete)
    return True

def handleStream(tcp):
    chopp = ChopProtocol('http')
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    tcp.stream_data['htpy_obj']['timestamp'] = tcp.timestamp
    if tcp.server.count_new > 0:
        if tcp.module_data['options']['verbose']:
            chop.tsprnt("%s:%s->%s:%s (%i)" % (src, sport, dst, dport, tcp.server.count_new))
        try:
            tcp.stream_data['connparser'].req_data(tcp.server.data[:tcp.server.count_new])
        except htpy.stop:
            tcp.stop()
        except htpy.error:
            chop.prnt("Stream error in htpy.")
            tcp.stop()
        tcp.discard(tcp.server.count_new)
    elif tcp.client.count_new > 0:
        if tcp.module_data['options']['verbose']:
            chop.tsprnt("%s:%s->%s:%s (%i)" % (src, sport, dst, dport, tcp.client.count_new))
        try:
            tcp.stream_data['connparser'].res_data(tcp.client.data[:tcp.client.count_new])
        except htpy.stop:
            tcp.stop()
        except htpy.error:
            chop.prnt("Stream error in htpy.")
            tcp.stop()
        tcp.discard(tcp.client.count_new)

    if tcp.stream_data['htpy_obj']['ready']:
        trans = tcp.stream_data['htpy_obj']['transaction']
        chopp.setClientData(trans['request'])
        chopp.setServerData(trans['response']) 
        chopp.setTimeStamp(trans['timestamp'])
        chopp.setAddr(tcp.addr)
        chopp.flowStart = tcp.stream_data['htpy_obj']['flowStart']
        tcp.stream_data['htpy_obj']['ready'] = False
        return chopp

    return None

def teardown(tcp):
    return

def shutdown(module_data):
    return
