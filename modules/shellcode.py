"""
A module to extract TCP streams and UDP datagrams from network traffic.
Extracted buffer is passed on to Libemu for shellcode detection.
"""

import pylibemu
from c2utils import hexdump

moduleName = 'shellcode_test'
moduleVersion = '0.1'
minimumChopLib = '4.0'


emu = pylibemu.Emulator()


def init(module_data):
    module_options = {'proto': []}

    tcp = {'tcp': ''}
    udp = {'udp': ''}

    module_options['proto'].append(tcp)
    module_options['proto'].append(udp)

    return module_options


def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr

    chop.tsprnt("TCP %s:%s - %s:%s [NEW]" % (src, sport, dst, dport))

    return True


def handleStream(tcp):
    ((src, sport), (dst, dport)) = tcp.addr

    direction = "NA"
    count = 0
    color = "WHITE"

    if tcp.server.count_new > 0:
        buffer = tcp.server.data[:tcp.server.count_new]
        server_count = tcp.server.count_new
        chop.tsprnt("TCP %s:%s -> %s:%s (CTS: %dB)" % (src, sport, dst, dport, server_count))
        tcp.discard(server_count)
        direction = "CTS"
        count = server_count
        color = "RED"
    else:
        buffer = tcp.client.data[:tcp.client.count_new]
        client_count = tcp.client.count_new
        chop.tsprnt("TCP %s:%s <- %s:%s (STC: %dB)" % (src, sport, dst, dport, client_count))
        tcp.discard(client_count)
        direction = "STC"
        count = client_count
        color = "BLUE"

    offset = emu.shellcode_getpc_test(buffer)
    if offset >= 0:
        emu.prepare(buffer, offset)
        emu.test()
        buffer_profile = emu.emu_profile_output
        data = hexdump(buffer[offset:])
        chop.tsprnt("TCP %s:%s - %s:%s contains shellcode in %s[0:%d] @ offset %d \n\n%s \n%s" % (src, sport, dst, dport, direction, count, offset, data, buffer_profile))

    emu.free()


def teardown(tcp):
    ((src, sport), (dst, dport)) = tcp.addr

    chop.tsprnt("TCP %s:%s - %s:%s (CLOSE)" % (src, sport, dst, dport))

    return True


def handleDatagram(udp):
    ((src, sport), (dst, dport)) = udp.addr

    buffer = udp.data
    offset = emu.shellcode_getpc_test(buffer)
    if offset >= 0:
        emu.prepare(buffer, offset)
        emu.test()
        buffer_profile = emu.emu_profile_output
        chop.tsprnt("UDP %s:%s - %s:%s contains shellcode @ offset %d \n\n %s" % (src, sport, dst, dport, offset, buffer_profile))

    emu.free()


def module_info():
    return "A module to detect presence of shellcode in network streams."

