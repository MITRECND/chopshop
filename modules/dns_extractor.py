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

from dnslib import DNSRecord, QR, OPCODE, RCODE, QTYPE, CLASS
from c2utils import packet_timedate
from optparse import OptionParser
import json

moduleName = 'dns_extractor'
moduleVersion = '0.1'
minimumChopLib = '4.0'

class dns_to_dict(json.JSONEncoder):
    def default(self, d):
        return json.JSONEncoder().encode(d)

def module_info():
    return "Handle DNS messages and print or send to mongo"

def init(module_data):
    module_options = { 'proto': [ { 'dns': '' } ] }
    parser = OptionParser()

    parser.add_option("-M", "--mongo", action="store_true", dest="mongo",
        default=False, help="Send output to mongodb")
    parser.add_option("-H", "--host", action="store", dest="host",
        default="localhost", help="Host to connect to")
    parser.add_option("-P", "--port", action="store", dest="port",
        default=27017, help="Port to connect to")
    parser.add_option("-D", "--db", action="store", dest="db",
        default='pcaps', help="Database to use")
    parser.add_option("-C", "--collection", action="store", dest="col",
        default='dns', help="Collection to use")

    (options,lo) = parser.parse_args(module_data['args'])

    module_data['mongo'] = options.mongo

    if module_data['mongo']:
        try:
            from dbtools import mongo_connector
        except ImportError, e:
            module_options['error'] = str(e)
            return module_options

        module_data['db'] = mongo_connector(options.host, options.port, options.db, options.col)

    chop.set_custom_json_encoder(dns_to_dict)

    return module_options

def handleProtocol(chopp):
    ((src, sport), (dst, dport)) = chopp.addr
    if sport == 53:
        data = chopp.serverData
    elif dport == 53:
        data = chopp.clientData

    if chopp.module_data['mongo']:
        chopp.module_data['db'].insert(data)
    chop.prnt(data)
    chop.json(data)

def shutdown(module_data):
    return
