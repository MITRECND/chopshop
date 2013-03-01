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
import json
import htpy
import hashlib

moduleName="http_extractor"

class dns_to_dict(json.JSONEncoder):
    def default(self, d):
        return json.JSONEncoder().encode(d)

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
    d = obj['d']

    if length == 0:
        if 'body' not in d[direction]:
            return htpy.HTP_OK

        if obj['module_data']['md5_body']:
            d[direction]['body_md5'] = hashlib.md5(d[direction]['body']).hexdigest()
            del d[direction]['body']

        dump(obj['module_data'], d)
        return htpy.HTP_OK

    if 'body' in d[direction]:
        d[direction]['body'] += data
    else:
        d[direction]['body'] = data

    if obj['module_data']['blen'] != 0 and len(d[direction]['body']) >= obj['module_data']['blen']:
        d[direction]['body'] = d[direction]['body'][:obj['module_data']['blen']]
    return htpy.HTP_OK

def dump(module_data, d):
    if module_data['prnt']:
        chop.prnt(d)
    if module_data['mongo']:
        module_data['db'].insert(d)
    if module_data['json']:
        chop.json(d)

    if module_data['carve_request'] and 'body' in d['request']:
        chop.prnt("DUMPING REQUEST: %s (%i)" % (sanitize_filename(d['request']['uri']['path'][1:] + '.request.' + str(module_data['counter'])), len(d['request']['body'])))
        chop.savefile(sanitize_filename(d['request']['uri']['path'][1:] + '.request.' + str(module_data['counter'])), d['request']['body'])
        module_data['counter'] += 1

    if module_data['carve_response'] and 'body' in d['response']:
        chop.prnt("DUMPING RESPONSE: %s (%i)" % (sanitize_filename(d['request']['uri']['path'][1:] + '.response.' + str(module_data['counter'])), len(d['response']['body'])))
        chop.savefile(sanitize_filename(d['request']['uri']['path'][1:] + '.response.' + str(module_data['counter'])), d['response']['body'])
        module_data['counter'] += 1

    # In case pipelining is going on remove these.
    d['request'] = { 'headers': {} }
    d['response'] = { 'headers': {} }

def request_headers(cp, obj):
    d = obj['d']
    d['request'] = { 'headers': {} }
    if not obj['module_data']['fields']:
        d['request']['headers'] = cp.get_all_request_headers()
        d['request']['uri'] = cp.get_uri()
    else:
        for field in obj['module_data']['fields']:
            if field == 'uri':
                d['request']['uri'] = cp.get_uri()
            else:
                value = cp.get_request_header(field)
                if value != None:
                    d['request']['headers'][field] = value

    if not d['request']['headers']:
        del d['request']['headers']

    return htpy.HTP_OK

def response_headers(cp, obj):
    d = obj['d']
    d['response'] = { 'headers': {} }
    if not obj['module_data']['fields']:
        d['response']['headers'] = cp.get_all_response_headers()
        d['response']['status'] = cp.get_response_status()
    else:
        for field in obj['module_data']['fields']:
            if field == 'status':
                d['response']['status'] = cp.get_response_status()
            else:
                value = cp.get_response_header(field)
                if value != None:
                    d['response']['headers'][field] = value

    if not d['response']['headers']:
        del d['response']['headers']

    # If bodies are not wanted, dump the object after each response.
    # This ensures that we get data even if the session does not
    # enter teardown.
    if 'blen' not in obj['module_data']:
        dump(obj['module_data'], d)
    return htpy.HTP_OK

def module_info():
    print "Parse HTTP. Print, generate JSON or send to mongo"

def init(module_data):
    module_options = { 'proto': 'tcp' }
    parser = OptionParser()

    parser.add_option("-s", "--carve_response_body", action="store_true",
        dest="carve_response", default=False, help="Save response body")
    parser.add_option("-S", "--carve_request_body", action="store_true",
        dest="carve_request", default=False, help="Save request body")
    parser.add_option("-f", "--fields", action="store", dest="fields",
        default=[], help="Comma separated list of fields to extract")
    parser.add_option("-m", "--md5_body", action="store_true", dest="md5_body",
        default=False, help="Generate MD5 of body, and throw contents away")
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
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
        default=False, help="Be verbose about incoming packets")

    (options,lo) = parser.parse_args(module_data['args'])

    module_data['counter'] = 0
    module_data['prnt'] = options.prnt
    module_data['mongo'] = options.mongo
    module_data['json'] = options.json
    module_data['carve_request'] = options.carve_request
    module_data['carve_response'] = options.carve_response
    module_data['verbose'] = options.verbose
    module_data['md5_body'] = options.md5_body

    if not options.prnt and not options.mongo and not options.json:
        chop.prnt("WARNING: No output method selected.")

    if module_data['mongo']:
        try:
            from dbtools import mongo_connector
        except ImportException, e:
            module_options['error'] = str(e)
            return module_options
        module_data['db'] = mongo_connector(options.host, options.port, options.db, options.col)

    if module_data['json']:
        chop.set_custom_json_encoder(dns_to_dict)

    module_data['fields'] = options.fields
    if options.fields:
        fields = options.fields.split(',')
        for field in fields:
            if field.startswith('body:'):
                module_data['blen'] = int(field.split(':')[1])
                if module_data['blen'] == 0:
                    chop.prnt("Extracting all body bytes")
                else:
                    chop.prnt("Extracting %i body bytes" % module_data['blen'])
            else:
                chop.prnt("Extracting field: %s" % field)
        module_data['fields'] = fields

    if module_data['carve_request'] or module_data['carve_response']:
        chop.prnt("Adding URI to fields for carving.")
        module_data['fields'].append('uri')
        if 'blen' not in module_data:
            chop.prnt("Defaulting to carving entire body.")
            module_data['blen'] = 0
        else:
            chop.prnt("Carving %i bytes of bodies." % module_data['blen'])

    if module_data['md5_body']:
        if 'blen' not in module_data:
            chop.prnt("Defaulting to MD5 entire body.")
            module_data['blen'] = 0

    return module_options

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    if sport != 80 and dport != 80:
        return False

    if tcp.module_data['verbose']:
        chop.tsprnt("New session: %s:%s->%s:%s" % (src, sport, dst, dport))

    d = {
          'timestamp': packet_timedate(tcp.timestamp),
          'src': src,
          'sport': sport,
          'dst': dst,
          'dport': dport,
        }
    tcp.stream_data['cp'] = htpy.init()
    tcp.stream_data['cp'].set_obj({'module_data': tcp.module_data, 'd': d})
    tcp.stream_data['cp'].register_log(log)
    tcp.stream_data['cp'].register_request_headers(request_headers)
    tcp.stream_data['cp'].register_response_headers(response_headers)
    if 'blen' in tcp.module_data:
        tcp.stream_data['cp'].register_request_body_data(request_body)
        tcp.stream_data['cp'].register_response_body_data(response_body)
    return True

def handleStream(tcp):
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    if tcp.server.count_new > 0:
        if tcp.module_data['verbose']:
            chop.tsprnt("%s:%s->%s:%s (%i)" % (src, sport, dst, dport, tcp.server.count_new))
        try:
            tcp.stream_data['cp'].req_data(tcp.server.data[:tcp.server.count_new])
        except htpy.stop:
            tcp.stop()
        tcp.discard(tcp.server.count_new)
    elif tcp.client.count_new > 0:
        if tcp.module_data['verbose']:
            chop.tsprnt("%s:%s->%s:%s (%i)" % (src, sport, dst, dport, tcp.client.count_new))
        try:
            tcp.stream_data['cp'].res_data(tcp.client.data[:tcp.client.count_new])
        except htpy.stop:
            tcp.stop()
        tcp.discard(tcp.client.count_new)
    return

def shutdown(module_data):
    return

def teardown(tcp):
    return
