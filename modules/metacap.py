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

"""
A module to extract metadata from a PCAP.
"""

from optparse import OptionParser
from c2utils import parse_addr, packet_isodate, packet_timedate, entropy
from jsonutils import jsonOrReprEncoder

moduleName = 'metacap'

def init(module_data):
    module_options = {'proto':'tcp'}
    parser = OptionParser()

    parser.add_option("-i", "--isodate", action="store_true",
        dest="isodate", default=False, help="convert dates to ISODate")
    parser.add_option("-b", "--bulk", action="store_true",
        dest="bulk", default=False,
        help="output only after all input has been processed")
    parser.add_option("-q", "--quiet", action="store_true",
        dest="quiet", default=False,
        help="only print summary information (json not affected)")

    (opts,lo) = parser.parse_args(module_data['args'])

    module_data['isodate'] = opts.isodate
    module_data['bulk'] = opts.bulk
    module_data['quiet'] = opts.quiet

    module_data['pcap_summary'] = {
                                    'type': 'pcap',
                                    'data': {
                                        'total_packets': 0,
                                        'total_streams': 0,
                                        'end_time': '',
                                        'total_data_transfer': 0,
                                    }
                                  }
    module_data['streams'] = {}

    #This allows json to handle datetime
    chop.set_custom_json_encoder(jsonOrReprEncoder)

    return module_options

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    if tcp.module_data['isodate']:
        timestamp = packet_isodate(tcp.timestamp)
    else:
        timestamp = packet_timedate(tcp.timestamp)

    tcp.module_data['streams'][str(tcp.addr)] = {
                                   'type' : 'stream',
                                   'data' : {
                                       'comm_order': [],
                                       'start_time': timestamp,
                                       'end_time': timestamp,
                                       'src': src,
                                       'sport': sport,
                                       'dst': dst,
                                       'dport': dport,
                                       'client_data_transfer': 0,
                                       'server_data_transfer': 0,
                                       'total_packets': 0
                                   }
                                }

    if 'start_time' not in tcp.module_data['pcap_summary']['data']:
        tcp.module_data['pcap_summary']['data']['start_time'] = timestamp
    tcp.module_data['pcap_summary']['data']['total_streams'] += 1

    return True

def handleStream(tcp):
    key = str(tcp.addr)
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    if tcp.module_data['isodate']:
        timestamp = packet_isodate(tcp.timestamp)
    else:
        timestamp = packet_timedate(tcp.timestamp)

    ps = tcp.module_data['pcap_summary']['data']
    cs = tcp.module_data['streams'][key]['data']
    if tcp.server.count_new > 0:
        comm = { 'data_to': 'S',
                 'data_len': tcp.server.count_new,
                 'entropy': entropy(tcp.server.data[:tcp.server.count_new])
               }
        cs['comm_order'].append(comm)
        cs['server_data_transfer'] += tcp.server.count_new
        ps['total_data_transfer'] += tcp.server.count_new
        tcp.discard(tcp.server.count_new)
    else:
        comm = { 'data_to': 'C',
                 'data_len': tcp.client.count_new,
                 'entropy': entropy(tcp.client.data[:tcp.client.count_new])
               }
        cs['comm_order'].append(comm)
        cs['client_data_transfer'] += tcp.client.count_new
        ps['total_data_transfer'] += tcp.client.count_new
        tcp.discard(tcp.client.count_new)
    cs['end_time'] = timestamp
    cs['total_packets'] += 1
    ps['total_packets'] += 1
    ps['end_time'] = timestamp

    return

def teardown(tcp):
    if not tcp.module_data['bulk']:
        key = str(tcp.addr)
        my_stream = tcp.module_data['streams'][key]
        chop.json(my_stream)

        if not tcp.module_data['quiet']: __print_stream_data(my_stream['data'])

        del tcp.module_data['streams'][key]
    return

def shutdown(module_data):
    if not module_data['bulk']:
        #Any Streams that didn't teardown remove them now
        for stream, metadata in module_data['streams'].iteritems():
            chop.json(metadata)

            if not module_data['quiet']: __print_stream_data(metadata['data'])

        chop.json(module_data['pcap_summary'])

    else:
        output = []
        for stream, metadata in module_data['streams'].iteritems():
            output.append(metadata)
            if not module_data['quiet']: __print_stream_data(metadata['data'])

        output.append(module_data['pcap_summary'])
        chop.json(output)

    chop.prettyprnt("YELLOW", "Summary:")
    chop.prettyprnt("CYAN", "\tStart Time: %s  -> End Time: %s" %
                (module_data['pcap_summary']['data']['start_time'],
                 module_data['pcap_summary']['data']['end_time']))
    chop.prettyprnt("CYAN", "\tTotal Packets: %s\n\tTotal Streams: %s" %
                (module_data['pcap_summary']['data']['total_packets'],
                 module_data['pcap_summary']['data']['total_streams']))
    chop.prettyprnt("CYAN", "\tTotal Data Transfered: %s " %
                (module_data['pcap_summary']['data']['total_data_transfer']))
    chop.prnt("")


def module_info():
    return "A module to extract metadata from a PCAP."


def __print_stream_data(data):
    chop.prettyprnt("YELLOW", "%s:%s -> %s:%s -- %s -> %s" %
                (data['src'],
                 data['sport'],
                 data['dst'],
                 data['dport'],
                 data['start_time'],
                 data['end_time']
                )
             )
    chop.prettyprnt("CYAN", "\tTotal Packets: %s" % data['total_packets'])
    chop.prettyprnt("CYAN", "\tClient Data: %s" % data['client_data_transfer'])
    chop.prettyprnt("CYAN", "\tServer Data: %s" % data['server_data_transfer'])

    if len(data['comm_order']) > 0:
        chop.prettyprnt("MAGENTA",
                        "\tComm Order:\tTo\tLength\tEntropy\n",
                        None)
    for comm_dict in data['comm_order']:
        chop.prettyprnt("MAGENTA",
                        '\t\t\t%s' % comm_dict['data_to'],
                        None)
        chop.prettyprnt("MAGENTA",
                        '\t%s' % comm_dict['data_len'],
                        None)
        chop.prettyprnt("MAGENTA",
                        '\t%s\n' % comm_dict['entropy'],
                        None)
    if len(data['comm_order']) > 0:
        chop.prnt("")

    chop.prnt("")
