# Copyright (c) 2014, Ankur Tyagi. All rights reserved.
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


"""
A module to extract TCP streams and UDP datagrams from network traffic.
Extracted buffer is passed on to Libemu for shellcode detection.
"""

from optparse import OptionParser
from c2utils import hexdump

moduleName = 'shellcode_detector'
moduleVersion = '0.1'
minimumChopLib = '4.0'


def init(module_data):
    module_options = { 'proto': [{'tcp': ''}, {'udp': ''}] }

    module_data['emu'] = None
    module_data['cliargs'] = { 'shellprofile': False, 'hexdump': False }

    parse_args(module_data)

    try:
        import pylibemu
        module_data['emu'] = pylibemu.Emulator()
    except ImportError, e:
        module_options['error'] = str(e)

    return module_options


def parse_args(module_data):
    parser = OptionParser()

    parser.add_option("-p", "--profile", action="store_true", dest="shellprofile", default=False, help="Enable shellcode profile output")
    parser.add_option("-x", "--hexdump", action="store_true", dest="hexdump", default=False, help="Enable hexdump output")

    (options, lo) = parser.parse_args(module_data['args'])

    if options.shellprofile:
        module_data['cliargs']['shellprofile'] = True

    if options.hexdump:
        module_data['cliargs']['hexdump'] = True


def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr

    chop.tsprnt("TCP %s:%s - %s:%s [NEW]" % (src, sport, dst, dport))
    return True


def handleStream(tcp):
    ((src, sport), (dst, dport)) = tcp.addr

    direction = "NA"
    count = 0

    if tcp.server.count_new > 0:
        buffer = tcp.server.data[:tcp.server.count_new]
        server_count = tcp.server.count_new
        chop.tsprnt("TCP %s:%s -> %s:%s (CTS: %dB)" % (src, sport, dst, dport, server_count))
        tcp.discard(server_count)
        direction = "CTS"
        count = server_count
    else:
        buffer = tcp.client.data[:tcp.client.count_new]
        client_count = tcp.client.count_new
        chop.tsprnt("TCP %s:%s <- %s:%s (STC: %dB)" % (src, sport, dst, dport, client_count))
        tcp.discard(client_count)
        direction = "STC"
        count = client_count

    offset = tcp.module_data['emu'].shellcode_getpc_test(buffer)
    if offset >= 0:
        tcp.stop()
        tcp.module_data['emu'].prepare(buffer, offset)
        tcp.module_data['emu'].test()
        chop.tsprnt("TCP %s:%s - %s:%s contains shellcode in %s[0:%d] @ offset %d" % (src, sport, dst, dport, direction, count, offset))

        if tcp.module_data['cliargs']['hexdump']:
            data = hexdump(buffer[offset:])
            chop.prnt("\n" + data)

        if tcp.module_data['cliargs']['shellprofile']:
            buffer_profile = tcp.module_data['emu'].emu_profile_output
            chop.prnt("\n" + buffer_profile)

    tcp.module_data['emu'].free()


def teardown(tcp):
    ((src, sport), (dst, dport)) = tcp.addr

    chop.tsprnt("TCP %s:%s - %s:%s [CLOSE]" % (src, sport, dst, dport))

    return True


def handleDatagram(udp):
    ((src, sport), (dst, dport)) = udp.addr

    chop.tsprnt("UDP %s:%s - %s:%s (%dB)" % (src, sport, dst, dport, len(udp.data)))

    buffer = udp.data
    offset = udp.module_data['emu'].shellcode_getpc_test(buffer)
    if offset >= 0:
        udp.stop
        udp.module_data['emu'].prepare(buffer, offset)
        udp.module_data['emu'].test()
        chop.tsprnt("UDP %s:%s - %s:%s contains shellcode in [0:%d] @ offset %d" % (src, sport, dst, dport, len(udp.data), offset))

        if udp.module_data['cliargs']['hexdump']:
            data = hexdump(buffer[offset:])
            chop.prnt("\n" + data)

        if udp.module_data['cliargs']['shellprofile']:
            buffer_profile = udp.module_data['emu'].emu_profile_output
            chop.prnt("\n" + buffer_profile)

    udp.module_data['emu'].free()


def module_info():
    return "A module to detect presence of shellcode in network streams."

