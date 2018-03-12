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
A module to dump memory leaked from the OpenSSL Heartbleed vulnerability
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
"""

import sys
import struct
import time
from base64 import b64encode
from optparse import OptionParser
from c2utils import multibyte_xor, hexdump, parse_addr, entropy

moduleName = 'heartbleed_payloads'
moduleVersion = '2.0'
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
    
    (opts,lo) = parser.parse_args(module_data['args'])

    module_data['verbose'] = opts.verbose
    module_data['hexdump'] = opts.hexdump

    return opts

def init(module_data):
    opts = parse_args(module_data)

    module_options = {'proto': []}

    tcp = {'tcp' : ''}

    module_options['proto'].append(tcp)

    return module_options

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr

    if tcp.module_data['verbose']:
        chop.tsprnt("Start Session %s:%s -> %s:%s"  % (src, sport, dst, dport))

    tcp.stream_data['dump'] = False

    return True

def handleStream(tcp):
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    if tcp.client.count_new > 0:
        data = tcp.client.data[:tcp.client.count_new]
        count = tcp.client.count_new
        if tcp.stream_data['dump']:
            chop.tsprnt("%s:%s -> %s:%s %i bytes" % (src, sport, dst, dport, count,))
            chop.prnt(hexdump(data))
        if data[:3] in ['\x18\x03\x00', '\x18\x03\x01', '\x18\x03\x02', '\x18\x03\x03']:
            chop.tsprnt("%s:%s -> %s:%s %i bytes" % (src, sport, dst, dport, count,))
            chop.prnt(hexdump(data[8:]))
            tcp.stream_data['dump'] = True
    if tcp.client.server_new > 0:
        count = tcp.server.count_new

    tcp.discard(count)

def teardown(tcp):
	pass

def module_info():
    return "A module to dump memory leaks from PCAPs of the OpenSSL Heartbleed vulnerability" 
