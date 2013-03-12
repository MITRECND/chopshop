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
A module to dump raw packet payloads from a watchlist of IPs.
Meant to be used to watch netcat reverse shells and other plaintext
backdoors.
"""

import sys
import struct
import time
from optparse import OptionParser
from c2utils import multibyte_xor, hexdump

moduleName = 'udp_payloads'

def parse_args(module_data):
    parser = OptionParser()

    parser.add_option("-v", "--verbose", action="store_true",
        dest="verbose", default=False, help="print all information")
    parser.add_option("-x", "--hexdump", action="store_true",
        dest="hexdump", default=False, help="print hexdump output")
    parser.add_option("-o", "--xor", action="store",
        dest="xor_key", default=None, help="XOR packet payloads with this key")

    (opts,lo) = parser.parse_args(module_data['args'])

    if opts.verbose:
        module_data['verbose'] = True

    module_data['hexdump'] = opts.hexdump

    if opts.xor_key:
        module_data['xor_key'] = opts.xor_key[2:]

def init(module_data):
    module_data['verbose'] = False

    module_options = {'proto':'udp'}

    parse_args(module_data)
    
    return module_options

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
    print "A module to dump raw UDP payloads"
