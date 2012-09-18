# Copyright (c) 2012 The MITRE Corporation. All rights reserved.
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

from c2utils import packet_timedate
from optparse import OptionParser
import json
import htpy

moduleName="http_extractor"

class dns_to_dict(json.JSONEncoder):
    def default(self, d):
        return json.JSONEncoder().encode(d)

def log(cp, msg, level, obj):
    if level == htpy.HTP_LOG_ERROR:
        elog = cp.get_last_error()
        if elog == None:
            return htpy.HOOK_ERROR
        chop.prnt("%s:%i - %s (%i)" % (elog['file'], elog['line'], elog['msg'], elog['level']))
    else:
        chop.prnt("%i - %s" % (level, msg))
    return htpy.HOOK_STOP

def request_headers(cp, obj):
    obj['stream_data']['d']['request'] = { 'headers': cp.get_all_request_headers(),
                                           'uri': cp.get_uri()
                                         }
    return htpy.HOOK_OK

def response_headers(cp, obj):
    obj['stream_data']['d']['response'] = {
                                            'headers': cp.get_all_response_headers(),
                                            'status': cp.get_response_status()
                                          }

    # We dump the object after each response. This ensures that we
    # get data even if the session does not enter teardown.
    if obj['module_data']['prnt']:
        chop.prnt(obj['stream_data']['d'])
    if obj['module_data']['mongo']:
        obj['module_data']['db'].insert(obj['stream_data']['d'])
    if obj['module_data']['json']:
        chop.json(obj['stream_data']['d'])

    # In case pipelining is going on remove these.
    del obj['stream_data']['d']['request']
    del obj['stream_data']['d']['response']
    return htpy.HOOK_OK

def module_info():
    print "Parse HTTP and generate JSON or send to mongo"

def init(module_data):
    module_options = { 'proto': 'tcp' }
    parser = OptionParser()

    parser.add_option("-p", "--print", action="store_true", dest="prnt",
        default=False, help="Send output to stdout")
    parser.add_option("-M", "--mongo", action="store_true", dest="mongo",
        default=False, help="Send output to mongodb")
    parser.add_option("-J", "--json", action="store_true", dest="json",
        default=False, help="Send output to json file (use -J to chosphop)")
    parser.add_option("-H", "--host", action="store", dest="host",
        default="localhost", help="Host to connect to")
    parser.add_option("-P", "--port", action="store", dest="port",
        default=27017, help="Port to connect to")
    parser.add_option("-D", "--db", action="store", dest="db",
        default='pcaps', help="Database to use")
    parser.add_option("-C", "--collection", action="store", dest="col",
        default='http', help="Collection to use")

    (options,lo) = parser.parse_args(module_data['args'])

    module_data['prnt'] = options.prnt
    module_data['mongo'] = options.mongo
    module_data['json'] = options.json

    if not options.prnt and not options.mongo and not options.json:
        module_options['error'] = "Select one output method."
        return module_options
    if module_data['mongo']:
        try:
            from dbtools import mongo_connector
        except ImportException, e:
            module_options['error'] = str(e)
            return module_options

        module_data['db'] = mongo_connector(options.host, options.port, options.db, options.col)

    if module_data['json']:
        chop.set_custom_json_encoder(dns_to_dict)

    return module_options

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    if sport != 80 and dport != 80:
        return False

    tcp.stream_data['cp'] = htpy.init()
    tcp.stream_data['cp'].set_obj({'stream_data': tcp.stream_data, 'module_data': tcp.module_data})
    tcp.stream_data['cp'].register_log(log)
    tcp.stream_data['cp'].register_request_headers(request_headers)
    tcp.stream_data['cp'].register_response_headers(response_headers)
    tcp.stream_data['d'] = {
                             'timestamp': packet_timedate(tcp.timestamp),
                             'src': src,
                             'sport': sport,
                             'dst': dst,
                             'dport': dport,
                           }
    return True

def handleStream(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    try:
        if tcp.server.count_new > 0:
            tcp.stream_data['cp'].req_data(tcp.server.data[:tcp.server.count_new])
            tcp.discard(tcp.server.count_new)
        elif tcp.client.count_new > 0:
            tcp.stream_data['cp'].res_data(tcp.client.data[:tcp.client.count_new])
            tcp.discard(tcp.client.count_new)
    except:
        tcp.stop()
    return

def shutdown(module_data):
    return

def teardown(tcp):
    return
