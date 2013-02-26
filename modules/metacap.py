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

"""
A module to extract metadata from a PCAP.
"""

from optparse import OptionParser
from c2utils import parse_addr, packet_isodate, packet_timedate

moduleName = 'metacap'

def init(module_data):
    module_options = {'proto':'tcp'}
    parser = OptionParser()

    parser.add_option("-i", "--isodate", action="store_true",
        dest="isodate", default=False, help="convert dates to ISODate")

    (opts,lo) = parser.parse_args(module_data['args'])

    module_data['isodate'] = opts.isodate

    module_data['pcap_summary'] = { 'total_packets': 0,
                                    'total_streams': 0,
                                    'end_time': '',
                                    'total_data_transfer': 0,
                                    'streams': {}
                                  }

    return module_options

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    if tcp.module_data['isodate']:
        timestamp = packet_isodate(tcp.timestamp)
    else:
        timestamp = packet_timedate(tcp.timestamp)
    tcp.module_data['pcap_summary']['streams'][str(tcp.addr)] = {
                                   'comm_order': [],
                                   'start_time': timestamp,
                                   'end_time': '',
                                   'src': src,
                                   'sport': sport,
                                   'dst': dst,
                                   'dport': dport,
                                   'client_data_transfer': 0,
                                   'server_data_transfer': 0,
                                }

    if 'start_time' not in tcp.module_data['pcap_summary']:
        tcp.module_data['pcap_summary']['start_time'] = timestamp
    tcp.module_data['pcap_summary']['total_streams'] += 1

    return True

def handleStream(tcp):
    key = str(tcp.addr)
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    if tcp.module_data['isodate']:
        timestamp = packet_isodate(tcp.timestamp)
    else:
        timestamp = packet_timedate(tcp.timestamp)
    ps = tcp.module_data['pcap_summary']
    cs = ps['streams'][key]
    if tcp.server.count_new > 0:
        cs['comm_order'].append(('S', tcp.server.count_new))
        cs['server_data_transfer'] += tcp.server.count_new
        ps['total_data_transfer'] += tcp.server.count_new
        tcp.discard(tcp.server.count_new)
    else:
        cs['comm_order'].append(('C', tcp.client.count_new))
        cs['client_data_transfer'] += tcp.client.count_new
        ps['total_data_transfer'] += tcp.client.count_new
        tcp.discard(tcp.client.count_new)
    cs['end_time'] = timestamp
    ps['total_packets'] += 1
    ps['end_time'] = timestamp

    return

def teardown(tcp):
    return

def shutdown(module_data):
    chop.json(module_data['pcap_summary'])
    chop.prnt(module_data['pcap_summary'])

def module_info():
    return "A module to extract metadata from a PCAP."
