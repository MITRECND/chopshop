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
A module to dump raw packet payloads from a stream.
Meant to be used to watch netcat reverse shells and other plaintext
backdoors.
"""

import sys
import struct
import time
from base64 import b64encode
from optparse import OptionParser
from c2utils import multibyte_xor, hexdump, parse_addr

moduleName = 'payloads'

def parse_args(module_data):
    parser = OptionParser()

    parser.add_option("-b", "--base64", action="store_true",
        dest="base64", default=False,
        help="Base64 encode payloads (useful for JSON handling)")
    parser.add_option("-v", "--verbose", action="store_true",
        dest="verbose", default=False, help="print all information")
    parser.add_option("-x", "--hexdump", action="store_true",
        dest="hexdump", default=False, help="print hexdump output")
    parser.add_option("-o", "--xor", action="store",
        dest="xor_key", default=None, help="XOR packet payloads with this key")
    parser.add_option("-O", "--oneshot", action="store_true",
        dest="oneshot", default=False, help="Buffer entire flow until teardown")

    (opts,lo) = parser.parse_args(module_data['args'])

    module_data['base64'] = opts.base64
    module_data['verbose'] = opts.verbose
    module_data['hexdump'] = opts.hexdump

    if opts.xor_key:
        module_data['xor_key'] = opts.xor_key[2:]

    module_data['oneshot'] = opts.oneshot

def init(module_data):
    module_options = {'proto':'tcp'}

    parse_args(module_data)
    
    return module_options

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr

    if tcp.module_data['verbose']:
        chop.tsprnt("Start Session %s:%s -> %s:%s"  % (src, sport, dst, dport))

    tcp.stream_data['data'] = ''

    return True

def handleStream(tcp):
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    if tcp.server.count_new > 0:
        data = tcp.server.data[:tcp.server.count_new]
        count = tcp.server.count_new
        color = "RED"
    else:
        data = tcp.client.data[:tcp.client.count_new]
        count = tcp.client.count_new
        color = "GREEN"

    if tcp.module_data['verbose']:
        chop.tsprettyprnt(color, "%s:%s -> %s:%s %i bytes" % (src, sport, dst, dport, count))

    if tcp.module_data['oneshot']:
        tcp.stream_data['data'] += data
        return

    if 'xor_key' in tcp.module_data:
        data = multibyte_xor(data, tcp.module_data['xor_key'])

    if tcp.module_data['hexdump']:
        data = hexdump(data)

    chop.prettyprnt(color, data)

    tcp.discard(count)

def teardown(tcp):
    if not tcp.module_data['oneshot']:
        return

    data = tcp.stream_data['data']

    if 'xor_key' in tcp.module_data:
        data = multibyte_xor(data, tcp.module_data['xor_key'])

    if tcp.module_data['hexdump']:
        data = hexdump(data)

    if tcp.module_data['base64']:
        data = b64encode(data)

    chop.prnt(data)
    chop.json({'payload': data})

def module_info():
    print "A module to dump raw packet payloads from a stream."
    print "Meant to be used to watch netcat reverse shells and other plaintext"
    print "backdoors."
