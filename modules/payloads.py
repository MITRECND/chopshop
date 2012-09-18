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

"""
A module to dump raw packet payloads from a watchlist of IPs.
Meant to be used to watch netcat reverse shells and other plaintext
backdoors.

Usage: payloads --ips 192.168.1.254,172.16.1.254
"""

import sys
import struct
import binascii
import time
from optparse import OptionParser
from c2utils import multibyte_xor

moduleName = 'payloads'

def parse_args(module_data):
    parser = OptionParser()

    parser.add_option("-c", "--command", action="store_true",
        dest="commands", default=False, help="print commands")
    parser.add_option("-r", "--response", action="store_true",
        dest="responses", default=False, help="print responses")
    parser.add_option("-v", "--verbose", action="store_true",
        dest="verbose", default=False, help="print all information")
    parser.add_option("-x", "--hexlify", action="store_true",
        dest="hexlify", default=False, help="print hexlified output")
    parser.add_option("-o", "--xor", action="store",
        dest="xor_key", default=None, help="XOR packet payloads with this key")
    parser.add_option("-i", "--ips", action="store", dest="ips",
                      default=None,
                      help="comma separated list of IP addresses to watch")

    (opts,lo) = parser.parse_args(module_data['args'])

    if opts.commands:
        module_data['commands'] = True

    if opts.responses:
        module_data['responses'] = True

    if opts.verbose:
        module_data['verbose'] = True

    module_data['hexlify'] = opts.hexlify

    if opts.xor_key:
        module_data['xor_key'] = opts.xor_key[2:]

    if opts.ips:
        ips = opts.ips.split(',')
        for ip in ips:
            chop.prnt("watching host: %s" % ip)
        module_data['ips'] = ips
    else:
        return "you must specify a list of hosts to watch"

def init(module_data):
    module_data['commands'] = True
    module_data['responses'] = True
    module_data['verbose'] = False

    module_options = {'proto':'tcp'}

    error = parse_args(module_data)
    if error:
        module_options['error'] = error
    
    return module_options

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    if dst in tcp.module_data['ips'] or src in tcp.module_data['ips']:
        if tcp.module_data['verbose']:
            chop.tsprnt("Start Session %s:%s -> %s:%s"  % (src, sport, dst, dport))
        return True
    else:
        return False

def handleStream(tcp):
	# collect time and IP metadata
	((src, sport), (dst, dport)) = tcp.addr
	# handle client system packets
	if tcp.server.count_new > 0:
            if tcp.module_data['verbose']:
                chop.tsprettyprnt("RED", "%s:%s -> %s:%s 0x%04X bytes" % (src, sport, dst, dport, tcp.server.count_new))
            data = tcp.server.data[:tcp.server.count_new]
            if 'xor_key' in tcp.module_data:
                data = multibyte_xor(data, tcp.module_data['xor_key'])
            if tcp.module_data['hexlify']:
                data = binascii.hexlify(data)
            chop.prettyprnt("RED", data)
            tcp.discard(tcp.server.count_new)
	# handle server system packets
	if tcp.client.count_new > 0:
            if tcp.module_data['verbose']:
                chop.tsprettyprnt("GREEN", "%s:%s -> %s:%s 0x%04X bytes" % (dst, dport, src, sport, tcp.client.count_new))
            data = tcp.client.data[:tcp.client.count_new]
            if 'xor_key' in tcp.module_data:
                data = multibyte_xor(data, tcp.module_data['xor_key'])
            if tcp.module_data['hexlify']:
                data = binascii.hexlify(data)
            chop.prettyprnt("GREEN", data)
            tcp.discard(tcp.client.count_new)

def teardown(tcp):
    pass

def module_info():
    print "A module to dump raw packet payloads from a watchlist of IPs."
    print "Meant to be used to watch netcat reverse shells and other plaintext"
    print "backdoors."
