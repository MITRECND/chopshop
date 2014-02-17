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
    module_options = { 'proto': [{'tcp' : ''}, {'udp': ''}] }

    module_data['emu'] = None
    module_data['shellprofile'] = False
    module_data['hexdump'] = False

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
        module_data['shellprofile'] = True

    if options.hexdump:
        module_data['hexdump'] = True


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

        if tcp.module_data['hexdump']:
            chop.prnt("")
            data = hexdump(buffer[offset:])
            chop.prnt(data)

        if tcp.module_data['shellprofile']:
            chop.prnt("")
            buffer_profile = tcp.module_data['emu'].emu_profile_output
            chop.prnt(buffer_profile)

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

        if udp.module_data['shellprofile']:
            buffer_profile = udp.module_data['emu'].emu_profile_output
            chop.prnt(buffer_profile)

        if udp.module_data['hexdump']:
            data = hexdump(buffer[offset:])
            chop.prnt(data)

    udp.module_data['emu'].free()


def module_info():
    return "A module to detect presence of shellcode in network streams."

