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

from dnslib import DNSRecord, QR, OPCODE, RCODE, QTYPE, CLASS
from c2utils import packet_timedate
from optparse import OptionParser
import json

moduleName="dns_extractor"

class dns_to_dict(json.JSONEncoder):
    def default(self, d):
        return json.JSONEncoder().encode(d)

def module_info():
    print "Parse DNS and generate JSON or send to mongo"

def init(module_data):
    module_options = { 'proto': 'udp' }
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
        default='dns', help="Collection to use")

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
        except ImportError, e:
            module_options['error'] = str(e)
            return module_options

        module_data['db'] = mongo_connector(options.host, options.port, options.db, options.col)

    if module_data['json']:
        chop.set_custom_json_encoder(dns_to_dict)

    return module_options

def handleDatagram(udp):
    ((src, sport), (dst, dport)) = udp.addr
    if sport != 53 and dport != 53:
        #chop.tsprnt("STOP: %s:%s->%s:%s (%i:%i)" % (src, sport, dst, dport, len(udp.data), len(udp.ip)))
        udp.stop()
        return

    try:
        o = DNSRecord.parse(udp.data)
    except KeyError, e:
        chop.prnt("Key error: %s" % str(e))
        return

    # Create the dictionary...
    f = [ o.header.aa and 'AA',
          o.header.tc and 'TC',
          o.header.rd and 'RD',
          o.header.ra and 'RA' ]
    d = { 'header': {
                      'id': o.header.id,
                      'type': QR[o.header.qr],
                      'opcode': OPCODE[o.header.opcode],
                      'flags': ",".join(filter(None, f)),
                      'rcode': RCODE[o.header.rcode],
                    },
          'questions': o.questions
        }
    if OPCODE[o.header.opcode] == 'UPDATE':
        f1 = 'zo'
        f2 = 'pr'
        f3 = 'up'
        f4 = 'ad'
    else:
        f1 = 'q'
        f2 = 'a'
        f3 = 'ns'
        f4 = 'ar'
    dhdr = d['header']
    dhdr[f1] = o.header.q
    dhdr[f2] = o.header.a
    dhdr[f3] = o.header.ns
    dhdr[f4]= o.header.ar
    d['questions'] = []
    for q in o.questions:
        dq = {
              'qname': str(q.qname),
              'qtype': QTYPE[q.qtype],
              'qclass': QTYPE[q.qclass]
            }
        d['questions'].append(dq)
    d['rr'] = []
    for r in o.rr:
        dr = {
              'rname': str(r.rname),
              'rtype': QTYPE.lookup(r.rtype,r.rtype),
              'rclass': CLASS[r.rclass],
              'ttl': r.ttl,
              'rdata': str(r.rdata)
            }
        d['rr'].append(dr)
   
    d['timestamp'] = packet_timedate(udp.timestamp)
    d['src'] = src
    d['sport'] = sport
    d['dst'] = dst
    d['dport'] = dport

    if module_data['prnt']:
        chop.prnt(d)
    if module_data['mongo']:
        module_data['db'].insert(d)
    if module_data['json']:
        chop.json(d)

def shutdown(module_data):
    return
