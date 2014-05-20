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
A module to dump raw packet payloads from a stream.
Meant to be used to watch netcat reverse shells and other plaintext
backdoors.
"""

import sys
import struct
import time
from base64 import b64encode
from optparse import OptionParser
from c2utils import multibyte_xor, hexdump, parse_addr, entropy

moduleName = 'payloads'
moduleVersion = '2.1'
minimumChopLib = '4.0'

def parse_args(module_data):
    parser = OptionParser()

    parser.add_option("-b", "--base64", action="store_true",
        dest="base64", default=False,
        help="Base64 encode payloads (useful for JSON handling) (TCP)")
    parser.add_option("-v", "--verbose", action="store_true",
        dest="verbose", default=False, help="print all information")
    parser.add_option("-x", "--hexdump", action="store_true",
        dest="hexdump", default=False, help="print hexdump output")
    parser.add_option("-o", "--xor", action="store",
        dest="xor_key", default=None, help="XOR packet payloads with this key")
    parser.add_option("-O", "--oneshot", action="store_true",
        dest="oneshot", default=False,
        help="Buffer entire flow until teardown (TCP)")
    parser.add_option("-S", "--oneshot_split", action="store_true",
        dest="oneshot_split", default=False,
        help="Buffer each side of flow until teardown (TCP)")
    parser.add_option("-u", "--udp-disable", action="store_true",
        dest="disable_udp", default=False, help="Disable UDP support")
    parser.add_option("-t", "--tcp-disable", action="store_true",
        dest="disable_tcp", default=False, help="Disable TCP support")
    parser.add_option("-s", "--sslim-disable", action="store_true",
        dest="disable_sslim", default=False, help="Disable sslim support")

    (opts,lo) = parser.parse_args(module_data['args'])

    module_data['base64'] = opts.base64
    module_data['verbose'] = opts.verbose
    module_data['hexdump'] = opts.hexdump
    module_data['oneshot'] = opts.oneshot
    module_data['oneshot_split'] = opts.oneshot_split

    if opts.xor_key:
        if opts.xor_key.startswith('0x'):
            module_data['xor_key'] = opts.xor_key[2:]
        else:
            module_data['xor_key'] = opts.xor_key

    return opts

def init(module_data):
    opts = parse_args(module_data)

    module_options = {'proto': []}

    tcp = {'tcp': ''}
    udp = {'udp': ''}
    sslim = {'sslim': ''}

    if not opts.disable_tcp:
        module_options['proto'].append(tcp)

    if not opts.disable_udp:
        module_options['proto'].append(udp)

    if not opts.disable_sslim:
        module_options['proto'].append(sslim)

    if len(module_options['proto']) == 0: # They disabled all?
        module_options['error'] = "Must leave one protocol enabled."

    return module_options

# TCP
def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr

    if tcp.module_data['verbose']:
        chop.tsprnt("Start Session %s:%s -> %s:%s"  % (src, sport, dst, dport))

    # Used for oneshot, just concat both directions into a giant blob.
    tcp.stream_data['data'] = ''
    # Used for oneshot_split, concat each direction into it's own blob.
    tcp.stream_data['to_server'] = ''
    tcp.stream_data['to_client'] = ''

    return True

def handleStream(tcp):
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    if tcp.server.count_new > 0:
        data = tcp.server.data[:tcp.server.count_new]
        count = tcp.server.count_new
        direction = 'to_server'
        color = "RED"
    else:
        data = tcp.client.data[:tcp.client.count_new]
        count = tcp.client.count_new
        direction = 'to_client'
        color = "GREEN"

    if tcp.module_data['verbose']:
        chop.tsprettyprnt(color, "%s:%s -> %s:%s %i bytes (H = %0.2f)" % (src, sport, dst, dport, count, entropy(data)))

    if tcp.module_data['oneshot']:
        tcp.stream_data['data'] += data

    if tcp.module_data['oneshot_split']:
        tcp.stream_data[direction] += data

    if tcp.module_data['oneshot'] or tcp.module_data['oneshot_split']:
        return

    handle_bytes(data, color, direction, tcp.module_data)
    tcp.discard(count)

# sslim
def handleProtocol(chopp):
    if chopp.type != 'sslim':
        return

    if chopp.clientData:
        handle_bytes(chopp.clientData, 'GREEN', 'to_client', chopp.module_data)
    if chopp.serverData:
        handle_bytes(chopp.serverData, 'RED', 'to_server', chopp.module_data)

def handle_bytes(data, color, direction, module_data):
    if 'xor_key' in module_data:
        data = multibyte_xor(data, module_data['xor_key'])

    if module_data['hexdump']:
        data = hexdump(data)

    if module_data['base64']:
        data = b64encode(data)

    chop.prettyprnt(color, data)
    chop.json({'payload': data, 'direction': direction})

def teardown(tcp):
    if not tcp.module_data['oneshot'] and not tcp.module_data['oneshot_split']:
        return

    if tcp.module_data['oneshot']:
        data = (alert_data, tcp.module_data, tcp.stream_data['data'])
        chop.prnt(data)
        chop.json({'payload': data, 'direction': 'combined'})

    if tcp.module_data['oneshot_split']:
        for direction in ['to_client', 'to_server']:
            data = alter_data(tcp.module_data, tcp.stream_data[direction])
            chop.prnt(data)
            chop.json({'payload': data, 'direction': direction})

def alter_data(module_data, data):
    if 'xor_key' in module_data:
        data = multibyte_xor(data, module_data['xor_key'])

    if module_data['hexdump']:
        data = hexdump(data)

    if module_data['base64']:
        data = b64encode(data)

    return data

# UDP
def handleDatagram(udp):
	# collect time and IP metadata
	((src, sport), (dst, dport)) = udp.addr
	# handle client system packets
        if udp.module_data['verbose']:
            chop.tsprettyprnt("RED", "%s:%s -> %s:%s 0x%04X bytes" % (src, sport, dst, dport, len(udp.data)))
        if 'xor_key' in udp.module_data:
            data = multibyte_xor(udp.data, udp.module_data['xor_key'])
        else:
            data = udp.data
        if udp.module_data['hexdump']:
            data = hexdump(data)
        chop.prettyprnt("RED", data)

def module_info():
    return "A module to dump raw packet payloads from a stream.\nMeant to be used to watch netcat reverse shells and other plaintext\nbackdoors."
