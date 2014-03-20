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
A module to scan TCP session data with Yara.

Usage: yarashop ...
"""

import argparse

from c2utils import parse_addr, hexdump
import chopring
import yaraprocessor

moduleName = "yarashop"


def module_info():
    return "Process TCP session payloads with Yara."


def init(module_data):
    """Initialize chopshop module."""
    module_options = {'proto': 'tcp'}
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-r', '--rules',
        nargs='+',
        type=str,
        help='One or more rule files to load into Yara, \
              seperated by spaces.')

    parser.add_argument(
        '-m', '--mode',
        default='session',
        choices=['session', 'packet', 'fixed_buffer', 'sliding_window'],
        help='Analyze entire sessions, individual packets, \
              or size based buffers of data with Yara. If analyzing \
              buffers, see "--size" option.')

    parser.add_argument(
        '-s', '--size',
        type=int,
        default=100,
        help='The size of the data buffer in bytes to be passed \
              to yara for analysis.')

    parser.add_argument(
        '-i', '--step',
        type=int,
        default=100,
        help='Amount to increment the window.')

    parser.add_argument(
        '-S', '--save',
        type=str,
        default='',
        help='If Yara matches are found, save the stream to file.')

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        dest='verbose',
        default=False,
        help='Print all information.')

    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        dest='quiet',
        default=False,
        help='Supress printing matches.')

    args = parser.parse_args(module_data['args'])

    module_data['rules'] = args.rules
    module_data['mode'] = args.mode
    module_data['size'] = args.size
    module_data['step'] = args.step
    module_data['save'] = args.save
    module_data['verbose'] = args.verbose
    module_data['quiet'] = args.quiet

    return module_options


def taste(tcp):
    """Called at the start of each new session."""
    # Analyzing all sessions in a capture
    ((src, sport), (dst, dport)) = tcp.addr
    if tcp.module_data['verbose']:
        chop.tsprnt("Start Session %s:%s -> %s:%s" % (src, sport, dst, dport))

    # Session and packet modes map to a raw processor
    if tcp.module_data['mode'] == 'session' or tcp.module_data['mode'] == 'packet':
        server_processor = yaraprocessor.Processor(tcp.module_data['rules'],
                                                    processing_mode='raw',
                                                    buffer_size=tcp.module_data['size'],
                                                    window_step=tcp.module_data['step'])

        client_processor = yaraprocessor.Processor(tcp.module_data['rules'],
                                                    processing_mode='raw',
                                                    buffer_size=tcp.module_data['size'],
                                                    window_step=tcp.module_data['step'])

    # Otherwise we should be able to use what is in 'mode'
    else:
        server_processor = yaraprocessor.Processor(tcp.module_data['rules'],
                                                    processing_mode=tcp.module_data['mode'],
                                                    buffer_size=tcp.module_data['size'],
                                                    window_step=tcp.module_data['step'])

        client_processor = yaraprocessor.Processor(tcp.module_data['rules'],
                                                    processing_mode=tcp.module_data['mode'],
                                                    buffer_size=tcp.module_data['size'],
                                                    window_step=tcp.module_data['step'])

    # Two processors, two lists for results, and two buffers
    tcp.stream_data['server_processor'] = server_processor
    tcp.stream_data['client_processor'] = client_processor
    tcp.stream_data['server_results'] = []
    tcp.stream_data['client_results'] = []
    tcp.stream_data['server_buffer'] = chopring.chopring()
    tcp.stream_data['client_buffer'] = chopring.chopring()

    return True


def handleStream(tcp):
    """
    Analyze payloads with Yara.

    handleStream behaves differently based upon processing mode.
    If mode is set to 'packet', each packet's payload is individually analyzed
    with yara. If mode is set to 'fixed_buffer' or 'sliding_window', packet
    payloads are appended to the analysis buffer. The 'session' mode is not
    handled inside of handleStream.

    """
    ((src, sport), (dst, dport)) = parse_addr(tcp)

    # Check for new packets received by the server
    if tcp.server.count_new:
        tcp.stream_data['server_buffer'] += tcp.server.data[:tcp.server.count_new]

        if tcp.module_data['verbose']:
            chop.tsprettyprnt("RED", "%s:%s -> %s:%s %i bytes" %
                              (src, sport, dst, dport, tcp.server.count_new))

        if tcp.module_data['mode'] == 'packet':
            tcp.stream_data['server_processor'].data = tcp.server.data[:tcp.server.count_new]
            results = tcp.stream_data['server_processor'].analyze()
            tcp.stream_data['server_results'] += results

        elif tcp.module_data['mode'] in ['fixed_buffer', 'sliding_window']:
            tcp.stream_data['server_processor'].data += tcp.server.data[:tcp.server.count_new]

    # Check for new packets received by the client
    if tcp.client.count_new:
        tcp.stream_data['client_buffer'] += tcp.client.data[:tcp.client.count_new]

        if tcp.module_data['verbose']:
            chop.tsprettyprnt("RED", "%s:%s -> %s:%s %i bytes" %
                              (dst, dport, src, sport, tcp.client.count_new))

        if tcp.module_data['mode'] == 'packet':
            tcp.stream_data['client_processor'].data = tcp.client.data[:tcp.client.count_new]
            results = tcp.stream_data['client_processor'].analyze()
            tcp.stream_data['client_results'] += results

        elif tcp.module_data['mode'] in ['fixed_buffer', 'sliding_window']:
            tcp.stream_data['client_processor'].data += tcp.client.data[:tcp.client.count_new]

    # if we are analyzing whole sessions, discard 0 bytes
    if tcp.module_data['mode'] == 'session':
        tcp.discard(0)

    # Handle printing and optionally saving results to file
    handle_results(tcp)


def shutdown(module_data):
    """Called upon chopshop shutdown."""
    return


def teardown(tcp):
    """Called at the end of each network session."""
    ((src, sport), (dst, dport)) = tcp.addr

    if tcp.module_data['mode'] == 'session':
        tcp.stream_data['server_processor'].data = tcp.server.data
        tcp.stream_data['server_results'] = tcp.stream_data['server_processor'].analyze()

        tcp.stream_data['client_processor'].data = tcp.client.data
        tcp.stream_data['client_results'] = tcp.stream_data['client_processor'].analyze()

        # Handle printing and optionally saving results to file
        handle_results(tcp)

    else:
        tcp.stream_data['server_results'] = tcp.stream_data['server_processor'].results
        tcp.stream_data['client_results'] = tcp.stream_data['client_processor'].results


def handle_results(tcp):
    """Print and save results."""
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    # print results
    for match in tcp.stream_data['server_processor'].results:
        if not module_data['quiet']:
            chop.tsprnt('Stream: Match found; %s:%s --> %s:%s' % (src, sport, dst, dport))
            chop.prnt(match)

        # Save results
        if tcp.module_data['save']:
            output = 'Match found in server stream; src=%s; sport=%s; dst=%s; dport=%s\n' \
                      % (src, sport, dst, dport)
            output += str(match) + '\n\n'
            output += hexdump(tcp.stream_data['server_buffer']) + '\n'
            chop.appendfile(tcp.module_data['save'], output)

        chop.json(match)
    tcp.stream_data['server_processor'].clear_results()

    # print results
    for match in tcp.stream_data['client_processor'].results:
        if not module_data['quiet']:
            chop.tsprnt('Stream: Match found; %s:%s --> %s:%s' % (dst, dport, src, sport))
            chop.tsprnt(match)

        # Save results
        if tcp.module_data['save']:
            output = 'Match found in client stream; src=%s; sport=%s; dst=%s; dport=%s\n' \
                      % (dst, dport, src, sport)
            output += str(match) + '\n\n'
            output += hexdump(tcp.stream_data['client_buffer']) + '\n'
            chop.appendfile(tcp.module_data['save'], output)

        chop.json(match)
    tcp.stream_data['client_processor'].clear_results()
