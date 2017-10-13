# Copyright (c) 2017 The MITRE Corporation. All rights reserved.
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

import sys
import os
from optparse import OptionParser
import binascii
import struct
import traceback
import hashlib
from io import BytesIO
import copy
import gzip
import json


from c2utils import parse_addr, sanitize_filename
from ChopProtocol import ChopProtocol


#DEBUG
#import time
#import hexdump

moduleName="http2"
moduleVersion="0.1"
minimumChopLib="4.3"


PREFACE = binascii.unhexlify("505249202a20485454502f322e300d0a0d0a534d0d0a0d0a")
HPACK_DECODER = None

HTTP2_TYPE_MAP = [
                     'DATA',
                     'HEADERS',
                     'PRIORITY',
                     'RST_STREAM',
                     'SETTINGS',
                     'PUSH_PROMISE',
                     'PING',
                     'GOAWAY',
                     'WINDOW_UPDATE',
                     'CONTINUATION'
]

class FrameIncompleteError(Exception):
    pass

class _header_():
    def __init__(self, type, length, flags, stream_id, raw):
        self.type = type
        self.length = length
        self.flags = flags
        self.stream_id = stream_id
        self.raw = raw

    @property
    def frame_type(self):
        try:
            stype = HTTP2_TYPE_MAP[self.type]
        except IndexError:
            raise TypeError("Unknown HTTP 2 frame type (%d) encountered" % (self.type))

        return stype

    def __repr__(self):
        return "_header_(%x, %d, %x, %x)" % (self.type, self.length, self.flags, self.stream_id)


class HTTP2_Frame(object):
    def __init__(self, header, data):
        self.header = header
        self.data = data

    @property
    def stream_id(self):
        return self.header.stream_id

    @property
    def frame_type(self):
        return self.header.frame_type

class HTTP2_Settings_Frame(HTTP2_Frame):
    def __init__(self, header, data):
        super(HTTP2_Settings_Frame, self).__init__(header, data)

        self.ack = (self.header.flags & 0x1) != 0
        self.settings_raw = []

        for start in range(0, len(data), 6): 
            (identifier, value) = struct.unpack('!HI', data[start:start + 6])
            self.settings_raw.append((identifier, value))

class HTTP2_RST_Frame(HTTP2_Frame):
    ERROR_MESSAGES = [
                        'NO_ERROR',
                        'PROTOCOL_ERROR',
                        'INTERNAL_ERROR',
                        'FLOW_CONTROL_ERROR',
                        'SETTINGS_TIMEOUT',
                        'STREAM_CLOSED',
                        'FRAME_SIZE_ERROR',
                        'REFUSED_STREAM',
                        'CANCEL',
                        'COMPRESSION_ERROR',
                        'CONNECT_ERROR',
                        'ENHANCE_YOUR_CALM',
                        'INADEQUATE_SECURITY',
                        'HTTP_1_1_REQUIRED'
    ]

    def __init__(self, header, data):
        super(HTTP2_RST_Frame, self).__init__(header, data)

        (self.error_code) = struct.unpack('!I', data)

    @property
    def error_message(self):
        return self.ERROR_MESSAGES[self.error_code]


class HTTP2_Headers_Frame(HTTP2_Frame):
    def __init__(self, header, data, decoder):
        super(HTTP2_Headers_Frame, self).__init__(header, data)

        self.decoder = decoder
        self.end_stream = (self.header.flags & 0x1) != 0
        self.end_headers = (self.header.flags & 0x4) != 0
        self.padded = (self.header.flags & 0x8) != 0
        self.priority = (self.header.flags & 0x20) != 0
        self.padding = None
        self.priority_exclusive = None
        self.stream_dependency = None

        if self.padded:
            self.padding = struct.unpack('!B', data[0])[0]
            # Remove padding length field
            data = data[1:]
            # Remove padding if padding > 0
            if self.padding > 0:
                self.data = data[:-self.padding]

        if self.priority:
            (ste, self.priority_weight) = struct.unpack('!IB', data[0:5])
            self.priority_exclusive = ste >> 31
            self.stream_dependency = ste & 0x7FFFFFFF
            data = data[5:]


        try:
            self.headers = self.decoder.decode(data)
        except Exception as e:
            chop.prnt("Warning: Unable to decode HTTP2 Header data")
            self.headers = None

    @property
    def flags(self):
        return {
                    'END_STREAM': self.end_stream,
                    'END_HEADERS': self.end_headers,
                    'PADDED': self.padded,
                    'PRIORITY': self.priority
        }



class HTTP2_Continuation_Frame(HTTP2_Frame):
    def __init__(self, header, data, decoder):
        super(HTTP2_Continuation_Frame, self).__init__(header, data)
        self.decoder = decoder
        self.end_headers = self.header.flags & 0x4

        try:
            self.headers = self.decoder.decode(data)
        except Exception as e:
            self.headers = None

class HTTP2_Data_Frame(HTTP2_Frame):
    def __init__(self, header, data):
        super(HTTP2_Data_Frame, self).__init__(header, data)

        self.end_stream = (self.header.flags & 0x1) != 0
        self.padded = (self.header.flags & 0x8) != 0
        self.padding = None


        if self.padded:
            self.padding = struct.unpack('!B', data[0])[0]
            # Remove padding length field
            data = data[1:]
            # Remove padding if padding > 0
            if self.padding > 0:
                self.data = data[:-self.padding]
    @property
    def flags(self):
        return {
                'END_STREAM': self.end_stream,
                'PADDED': self.padded
        }


def _opposite_direction_(direction):
    if direction == 'request':
        return 'response'
    else:
        return 'request'

def _parse_frame_header_(data):
    (length, type, flags, stream_id) = struct.unpack('!IBBI', '\0' + data)
    #stream_id &= 0x7FFFFFFF

    if (type > 9):
        raise TypeError("Unknown HTTP 2 frame type (%d) encountered" % (type))

    return _header_(type, length, flags, stream_id, data)

def _parse_frame_(data):
    try:
        frame_header = _parse_frame_header_(data[:9])
    except TypeError as e:
        chop.prnt("Error processing frame header")
        #chop.prnt(hexdump.hexdump(data, result='return'))
        raise

    rest = data[9:]
    #chop.prnt("Length: %d, Rest: %d" % (frame_header.length, len(rest)))
    if (frame_header.length > len(rest)):
        raise FrameIncompleteError()

    return (frame_header, rest[:frame_header.length], rest[frame_header.length:])

def _process_frames_(data, decoder):
    while 1:
        if (len(data) < 9):
            break

        try:
            (frame_header, frame_data, leftover)  = _parse_frame_(data)
        except FrameIncompleteError as e:
            raise
        except Exception as e:
            raise

        #chop.prnt("\tType: %s, Stream: %d, Length: %d, Flags: %x" % (frame_header.frame_type, frame_header.stream_id, frame_header.length, frame_header.flags))
        if frame_header.frame_type == 'HEADERS':
            frame = HTTP2_Headers_Frame(frame_header, frame_data, decoder)
        elif frame_header.frame_type == 'CONTINUATION':
            frame = HTTP2_Continuation_Frame(frame_header, frame_data, decoder)
        elif frame_header.frame_type == 'DATA':
            frame = HTTP2_Data_Frame(frame_header, frame_data)
        elif frame_header.frame_type == 'SETTINGS':
            frame = HTTP2_Settings_Frame(frame_header, frame_data)
        elif frame_header.frame_type == 'RST_STREAM':
            frame = HTTP2_RST_Frame(frame_header, frame_data)
        else:
            frame = HTTP2_Frame(frame_header, frame_data)

        discard = 9 + frame_header.length
        data = leftover

        yield (frame, discard)

def _process_frame_(frame, direction, tcp):
    if frame.stream_id == 0:
        return

    if frame.stream_id not in tcp.stream_data['stream_cache']:
        tcp.stream_data['stream_cache'][frame.stream_id] = {
                                                            'start': tcp.timestamp,
                                                            'request': {
                                                                            'stream_ended': False,
                                                                            'headers': {},
                                                                            'data': None
                                                            }, 
                                                            'response': {
                                                                            'stream_ended': False,
                                                                            'headers': {},
                                                                            'data': None
                                                            }}

    if isinstance(frame, HTTP2_Headers_Frame):
        try:
            tcp.stream_data['stream_cache'][frame.stream_id][direction]['headers'].update(dict(frame.headers))
        except Exception as e:
            chop.prnt("Unable to parse headers: %s" % str(e))

    elif isinstance(frame, HTTP2_Continuation_Frame):
        try:
            tcp.stream_data['stream_cache'][frame.stream_id][direction]['headers'].update(dict(frame.headers))
        except Exception as e:
            chop.prnt("Unable to parse headers: %s" % str(e))

    elif isinstance(frame, HTTP2_Data_Frame):
        #chop.prnt("%s\tType: %s, Stream: %d, Length: %d, Flags: %s" % ('==>' if direction == 'request' else '<==', frame.header.frame_type, frame.header.stream_id, frame.header.length, frame.flags))
        if tcp.stream_data['stream_cache'][frame.stream_id][direction]['data'] is None:
            tcp.stream_data['stream_cache'][frame.stream_id][direction]['data'] = ""

        tcp.stream_data['stream_cache'][frame.stream_id][direction]['data'] += frame.data

    else:
        pass
        #chop.prnt("%s\tType: %s, Stream: %d, Length: %d, Flags: %x" % ('==>' if direction == 'request' else '<==', frame.header.frame_type, frame.header.stream_id, frame.header.length, frame.header.flags))

def _stream_ended_(frame, direction, tcp):
    hash_fn = tcp.module_data['options']['hash_fn']
    transaction = {
                    'timestamp': tcp.stream_data['stream_cache'][frame.stream_id]['start'],
                    'request': {
                                'truncated': False, #TODO support this
                                'body': None,
                                'body_len': 0,
                                'body_hash': '',
                                'hash_fn': hash_fn,
                                'protocol': '2'
                    },
                    'response': {
                                'truncated': False,
                                'body': None,
                                'body_len': 0,
                                'body_hash': '',
                                'hash_fn': hash_fn,
                    }
    }
    if tcp.stream_data['stream_cache'][frame.stream_id][direction]['stream_ended'] and tcp.stream_data['stream_cache'][frame.stream_id][_opposite_direction_(direction)]['stream_ended']:
        #chop.prnt("Stream: %d" % (frame.stream_id))
        for d in ['request', 'response']:
            headers = copy.deepcopy(tcp.stream_data['stream_cache'][frame.stream_id][d]['headers'])
            if d == 'request':
                headers[':stream_id'] = frame.stream_id
                method = headers.get(':method', None)
                path = headers.get(':path', None)
                if ':method' in headers:
                    del headers[':method']
                if ':path' in headers:
                    del headers[':path']
                transaction[d]['method'] = method
                transaction[d]['uri'] = path
            else:
                status = headers.get(':status', None)
                if ':status' in headers:
                    del headers[':status']
                transaction[d]['status'] = status

            transaction[d]['headers'] = headers
            #chop.prnt("\tHeaders: %s" % (headers))
            if tcp.stream_data['stream_cache'][frame.stream_id][d]['data'] is not None:
                content_encoding = headers.get('content-encoding', None)
                mimetype = headers.get('content-type', None)
                if mimetype is not None:
                    mimetype = mimetype.split(';', 1)[0]
                content_disposition = headers.get('content-disposition', None)

                if content_encoding == 'gzip':
                    try:
                        dataStream = BytesIO(tcp.stream_data['stream_cache'][frame.stream_id][d]['data'])
                        gdata = gzip.GzipFile(fileobj=dataStream, mode='rb')
                        data = gdata.read()
                    except Exception as e:
                        chop.prnt("Warning: Unable to gzip file")
                        data = tcp.stream_data['stream_cache'][frame.stream_id][d]['data']
                else:
                    data = tcp.stream_data['stream_cache'][frame.stream_id][d]['data']

                if mimetype is None:
                    try:
                        import magic
                    except ImportError:
                        pass
                    else:
                        try:
                            mimetype = magic.from_buffer(data, mime=True)
                        except Exception as e:
                            chop.prnt("Warning: Unable to get mime type of file: %s" % (str(e)))

                filename = 'noname'
                if d == 'response':
                    if content_disposition is None:
                        if transaction['request']['uri'] is not None:
                            raw_path = transaction['request']['uri']
                            raw_path = raw_path.split('?', 1)[0]
                            path_parts = os.path.split(raw_path)
                            outPath = None

                            while (len(path_parts) > 0):
                                if path_parts[-1] == '':
                                    path_parts = path_parts[:-1]
                                    continue
                                else:
                                    outPath = os.path.basename(path_parts[-1])
                                    break

                            if outPath is None or outPath == '':
                                outPath = 'index'
                            filename = sanitize_filename(outPath)
                    else:
                        filename = sanitize_filename(content_disposition)

                #chop.prnt("\tData Name: %s, Length: %d, Type: %s" % (filename, len(data), mimetype))
                ((src, sport), (dst, dport)) = parse_addr(tcp)
                chop.savefile("%d-%s-%d-%s-%d-%d-%s" % (tcp.timestamp, src, sport, dst, dport, frame.stream_id, filename), data)

                transaction[d]['body'] = data
                transaction[d]['body_len'] = len(data)
                transaction[d]['body_hash'] = __hash_function__(data).hexdigest()
            #chop.prnt("\n")
        #chop.prnt('\n')
        del tcp.stream_data['stream_cache'][frame.stream_id]
        #chop.prnt(tcp.stream_data['stream_cache'].keys())
        #chop.prnt(json.dumps(transaction, indent=4))

        chopp = ChopProtocol('http')
        chopp.setClientData(transaction['request'])
        chopp.setServerData(transaction['response'])
        chopp.setTimeStamp(transaction['timestamp']) 
        chopp.setAddr(tcp.addr)
        chopp.flowStart = tcp.stream_data['flowStart']
        return chopp
    else:
        return None
    

def module_info():
    return "Basic parser for HTTP 2 traffic, parses HEADERS and DATA frames. Note that HTTP 2 has more complexity than this module parses"

def init(module_data):
    module_options = { 'proto': [{'tcp': 'http'}] } #TODO test with sslim http2
    parser = OptionParser()

    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
        default=False, help="Be verbose about incoming packets and errors")
    parser.add_option("--forgiving", action="store_true", dest="forgiving",
        default=False, help="Attempt to detect http2 in non-standard looking traffic")
    parser.add_option("-a", "--hash-function", action="store", dest="hash_function",
        default="md5", help="Hash Function to use on bodies (default 'md5', available: 'sha1', 'sha256', 'sha512')")
    parser.add_option("-p", "--ports", action="store", dest="ports",
        default="80,443", help="List of ports to check, comma separated, e.g., \"443,4443\", pass an emptry string to scan all ports (default '80,443')")

    (options, lo) =  parser.parse_args(module_data['args'])

    global __hash_function__
    if options.hash_function == 'sha1':
        __hash_function__ = hashlib.sha1
    elif options.hash_function == 'sha256':
        __hash_function__ = hashlib.sha256
    elif options.hash_function == 'sha512':
        __hash_function__ = hashlib.sha512
    else:
        options.hash_function = 'md5'
        __hash_function__ = hashlib.md5


    global hpack
    try:
        import hpack as _hpack
        hpack = _hpack
    except ImportError:
        module_options['error'] = "Unable to find required 'hpack' library"
        return module_options

    ports = options.ports.split(",")
    try: #This will except if ports is empty or malformed
        ports = [int(port) for port in ports]
    except:
        ports = []
    module_data['options'] = {
                                'verbose': options.verbose,
                                'hash_fn': options.hash_function,
                                'ports': ports,
                                'forgiving': options.forgiving,
    }

    return module_options

def handleStream(tcp):
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    data = None
    discard = 0
    new = 0
    direction = None

    completeStreams = []

    if tcp.server.count_new > 0:
        direction = 'request'
        #chop.prnt(hexdump.hexdump(tcp.server.data[:tcp.server.count_new], result='return'))
        if not tcp.stream_data['stream_started']: # Check for preface/magic
            if tcp.server.count_new >= len(PREFACE):
                if tcp.server.data[:tcp.server.count_new][:24] == PREFACE:
                    tcp.stream_data['stream_started'] = True
                    if tcp.module_data['options']['verbose']:
                        chop.tsprnt("New session: %s:%s->%s:%s" % (src, sport, dst, dport))
                    data = tcp.server.data[24:tcp.server.count_new]
                    discard += 24
                else:
                    tcp.stream_data['client_count'] += 1
                    if tcp.stream_data['client_count'] < 3 and tcp.module_data['options']['forgiving']:
                        tcp.discard(tcp.server.count_new)
                        return
                    else:
                        tcp.stop()
                        return

        if tcp.stream_data['stream_started']:
            if data is None:
                data = tcp.server.data[:tcp.server.count-tcp.server.offset]

    elif tcp.client.count_new > 0: 
        direction = 'response'
        #chop.prnt(hexdump.hexdump(tcp.stream_data['buffer'], result='return'))
        #chop.prnt(tcp.client.offset, tcp.client.count, tcp.client.count_new)
        if tcp.stream_data['stream_started']:
            if data is None:
                data = tcp.client.data[:tcp.client.count-tcp.client.offset]
        elif tcp.module_data['options']['forgiving']:
            tcp.discard(tcp.client.count_new)
            return
    else:
        return

    if tcp.stream_data['stream_started']:
        try:
            for (frame, ddiscard) in _process_frames_(data, tcp.stream_data['hpack_client_decoder']if direction == 'request' else tcp.stream_data['hpack_server_decoder']):
                #chop.prnt("%s\tType: %s, Stream: %d, Length: %d, Flags: %x" % ('==>' if direction == 'request' else '<==', frame.header.frame_type, frame.header.stream_id, frame.header.length, frame.header.flags))
                discard += ddiscard

                if False and isinstance(frame, HTTP2_RST_Frame):
                    try:
                        del tcp.stream_data['stream_cache'][frame.stream_id]
                    except:
                        pass
                else:
                    _process_frame_(frame, direction, tcp)

                    try:
                        if frame.end_stream:
                            tcp.stream_data['stream_cache'][frame.stream_id][direction]['stream_ended'] = True
                            chopp = _stream_ended_(frame, direction, tcp)
                            if chopp is not None:
                                completeStreams.append(chopp)
                    except AttributeError:
                        pass
                    
        except FrameIncompleteError as e:
            tcp.discard(discard)
            return
        except Exception as e:
            chop.prnt(traceback.format_exc())
            raise

    #chop.prnt("Discarding %d bytes (new %d) " % (discard, new))
    tcp.discard(discard)

    if len(completeStreams) > 0:
        return completeStreams
    else:
        return None

def shutdown(module_data):
    return

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    if len(tcp.module_data['options']['ports']):
        ports = tcp.module_data['options']['ports']
        if sport not in ports and dport not in ports:
            return False

    tcp.stream_data['stream_started'] = False
    tcp.stream_data['stream_cache'] = {}
    tcp.stream_data['flowStart'] = tcp.timestamp
    tcp.stream_data['hpack_client_decoder'] = hpack.Decoder()
    tcp.stream_data['hpack_client_decoder'].header_table_size = 4294967295
    tcp.stream_data['hpack_client_decoder'].max_allowed_table_size = 4294967295
    tcp.stream_data['hpack_server_decoder'] = hpack.Decoder()
    tcp.stream_data['hpack_server_decoder'].header_table_size = 4294967295
    tcp.stream_data['hpack_server_decoder'].max_allowed_table_size = 4294967295
    tcp.stream_data['client_count'] = 0

    return True

def teardown(tcp):
    return
