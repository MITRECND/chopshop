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

from c2utils import packet_timedate, sanitize_filename, parse_addr
from optparse import OptionParser
from base64 import b64encode
import json
import htpy
import hashlib

import sys
import os
import Queue

from ChopProtocol import ChopProtocol


# TODO
# Add more error checking
# See if any useful information is missing

moduleName = "http"
moduleVersion = '0.3'
# Teardown was introduced in choplib 4.3, but this
# module shouldn't be dependant on it.
minimumChopLib = '4.0'

__hash_function__ = None


class __htpyObj__:
    def __init__(self, options, start):
        self.options = options
        self.timestamp = None
        self.temp = {}
        self.transaction = {}
        self.lines = Queue.Queue()
        self.ready = False
        self.flowStart = start


def log(cp, msg, level, obj):
    if level == htpy.HTP_LOG_ERROR:
        elog = cp.get_last_error()
        if elog is None:
            return htpy.HTP_ERROR
        if not obj.options['suppress']:
            chop.prnt("%s:%i - %s (%i)" % (elog['file'], elog['line'],
                                           elog['msg'], elog['level']))
    else:
        if not obj.options['suppress']:
            slevel = str(level)
            if level == htpy.HTP_LOG_WARNING:
                slevel = "WARNING"
            if level == htpy.HTP_LOG_NOTICE:
                slevel = "NOTICE"
            elif level == htpy.HTP_LOG_INFO:
                slevel = "INFO"
            elif level == htpy.HTP_LOG_DEBUG:
                slevel = "DEBUG"
            elif level == htpy.HTP_LOG_DEBUG2:
                slevel = "DEBUG2"
            chop.prnt("%s - %s" % (slevel, msg))
    return htpy.HTP_OK


# The request and response body callbacks are treated identical with one
# exception: the location in the output dictionary where the data is stored.
# Because they are otherwise identical each body callback is a thin wrapper
# around the real callback.
def request_body(data, length, obj):
    return body(data, length, obj, 'request')


def response_body(data, length, obj):
    return body(data, length, obj, 'response')


def body(data, length, obj, direction):
    try:
        trans = obj.temp

        trans[direction]['body_len'] += length

        if length == 0:
            return htpy.HTP_OK

        trans[direction]['tmp_hash'].update(data)

        if trans[direction]['truncated'] is True:
            return htpy.HTP_OK

        if obj.options['no-body']:
            trans[direction]['body'] = ''
            trans[direction]['truncated'] = True
            return htpy.HTP_OK

        if trans[direction]['body'] is not None:
            trans[direction]['body'] += data
        else:
            trans[direction]['body'] = data

        # Truncate to Maximum Length
        if (obj.options['length'] > 0 and
                len(trans[direction]['body']) > obj.options['length']):
            trans[direction]['body'] = \
                trans[direction]['body'][:(obj.options['length'])]
            trans[direction]['truncated'] = True
    except KeyError as e:
        if obj.options['verbose']:
            if e.args[0] == direction:
                chop.tsprnt(("Body data for %s seen before any headers, "
                             "possible mid-stream traffic") % (direction))
            else:
                chop.tsprnt(("Key not found error while processing "
                             "%s body: %s") % (direction, str(e)))
        return htpy.HTP_ERROR
    except Exception as e:
        if obj.options['verbose']:
            chop.tsprnt("Exception while processing %s body: %s"
                        % (direction, str(e)))
        return htpy.HTP_ERROR

    return htpy.HTP_OK


def request_headers(cp, obj):
    try:
        trans = obj.temp
        trans['start'] = obj.timestamp
        trans['request'] = {}
        trans['request']['truncated'] = False  # Has the body been truncated?
        trans['request']['body'] = None
        trans['request']['body_len'] = 0

        trans['request']['hash_fn'] = obj.options['hash_function']
        trans['request']['tmp_hash'] = __hash_function__()

        trans['request']['headers'] = cp.get_all_request_headers()
        trans['request']['uri'] = cp.get_uri()
        trans['request']['method'] = cp.get_method()

        protocol = cp.get_request_protocol_number()
        proto = "HTTP/"

        if protocol == htpy.HTP_PROTOCOL_UNKNOWN:
            proto = "UNKNOWN"
        elif protocol == htpy.HTP_PROTOCOL_0_9:
            proto += "0.9"
        elif protocol == htpy.HTP_PROTOCOL_1_0:
            proto += "1.0"
        elif protocol == htpy.HTP_PROTOCOL_1_1:
            proto += "1.1"
        else:
            proto = "Error"

        trans['request']['protocol'] = proto
    except KeyError as e:
        if obj.options['verbose']:
            chop.tsprnt(("Key not found error while processing request "
                         "headers: %s") % (str(e)))
        return htpy.HTP_ERROR
    except Exception as e:
        if obj.options['verbose']:
            chop.tsprnt("Exception while processing request headers: %s"
                        % (str(e)))
        return htpy.HTP_ERROR

    return htpy.HTP_OK


def request_complete(cp, obj):
    # Move request data to the lines queue
    trans = obj.temp

    try:
        if trans['request']['body_len'] > 0:
            trans['request']['body_hash'] = \
                trans['request']['tmp_hash'].hexdigest()
        else:
            trans['request']['body_hash'] = ""
        del trans['request']['tmp_hash']

        obj.lines.put(obj.temp['request'])
        obj.temp['request'] = {}
        # del obj.temp['request']
    except KeyError as e:
        if obj.options['verbose']:
            if e.args[0] == 'request':
                chop.tsprnt(("Request completed before headers were seen -- "
                             "possible midstream traffic"))
            else:
                chop.tsprnt(("Key not found error while processing htpy "
                             "request complete event: %s") % (str(e)))
        return htpy.HTP_ERROR
    except Exception as e:
        if obj.options['verbose']:
            chop.tsprnt(("Exception while processing htpy request "
                         "complete event: %s") % (str(e)))
        return htpy.HTP_ERROR

    return htpy.HTP_OK


def response_headers(cp, obj):
    trans = obj.temp

    try:
        trans['response'] = {}
        trans['response']['headers'] = cp.get_all_response_headers()
        trans['response']['status'] = cp.get_response_status()

        trans['response']['hash_fn'] = obj.options['hash_function']
        trans['response']['tmp_hash'] = __hash_function__()

        trans['response']['truncated'] = False
        trans['response']['body'] = None
        trans['response']['body_len'] = 0
    except KeyError as e:
        if obj.options['verbose']:
            chop.tsprnt(("Key not found error while processing "
                         "response headers: %s") % (str(e)))
        return htpy.HTP_ERROR
    except Exception as e:
        if obj.options['verbose']:
            chop.tsprnt("Exception while processing response headers: %s"
                        % (str(e)))
        return htpy.HTP_ERROR

    return htpy.HTP_OK


def response_complete(cp, obj):
    trans = obj.temp

    try:
        if trans['response']['body_len'] > 0:
            trans['response']['body_hash'] = \
                trans['response']['tmp_hash'].hexdigest()
        else:
            trans['response']['body_hash'] = ""
        del trans['response']['tmp_hash']

        try:
            req = obj.lines.get(False)  # Do not block
        except Queue.Empty:
            pass
            # TODO error

        obj.transaction = {'request': req,
                           'response': trans['response'],
                           'timestamp': trans['start']}

        obj.ready = True
    except KeyError as e:
        if obj.options['verbose']:
            if e.args[0] == 'response':
                chop.tsprnt(("Response completed before headers were seen -- "
                             "possible midstream traffic"))
            else:
                chop.tsprnt(("Key not found error while processing htpy "
                             "response complete event: %s") % (str(e)))
        return htpy.HTP_ERROR
    except Exception as e:
        if obj.options['verbose']:
            chop.tsprnt(("Exception while processing htpy response "
                         "complete event: %s") % (str(e)))
        return htpy.HTP_ERROR

    return htpy.HTP_OK


def register_connparser(options):
    connparser = htpy.init()
    if options['disable-decompression']:
        try:
            connparser.cfg.response_decompression = 0
        except AttributeError as e:
            # Errors should have been checked in in the init
            # so this should be unnecessary
            pass
    connparser.register_log(log)
    connparser.register_request_headers(request_headers)
    connparser.register_response_headers(response_headers)
    connparser.register_request_body_data(request_body)
    connparser.register_response_body_data(response_body)
    connparser.register_request_complete(request_complete)
    connparser.register_response_complete(response_complete)
    return connparser


def module_info():
    return ("Takes in TCP traffic and outputs parsed HTTP traffic for "
            "use by secondary modules. Refer to the docs for output format")


def init(module_data):
    module_options = {'proto': [{'tcp': 'http'},
                                {'sslim': 'http'}]}
    parser = OptionParser()

    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                      default=False, help=("Be verbose about incoming "
                                           "packets and errors"))
    parser.add_option("-b", "--no-body", action="store_true", dest="nobody",
                      default=False, help="Do not store http bodies")
    parser.add_option("-s", "--suppress", action="store_true", dest="suppress",
                      default=False, help="Suppress htpy log output")
    parser.add_option("-l", "--length", action="store", dest="length",
                      type="int", default=5242880,
                      help=("Maximum length of bodies in bytes (Default: "
                            "5MB, set to 0 to process all body data)"))
    parser.add_option("-a", "--hash-function", action="store",
                      dest="hash_function", default="md5",
                      help=("Hash Function to use on bodies (default 'md5', "
                            "available: 'sha1', 'sha256', 'sha512')"))
    parser.add_option("-p", "--ports", action="store", dest="ports",
                      default="80",
                      help=("List of ports to check comma separated, e.g., "
                            "\"80,8080\", pass an empty string \"\" to scan "
                            "all ports (default '80')"))
    parser.add_option("-c", "--disable-decompression", action="store_true",
                      default=False, dest="disable_decompression",
                      help=("Disable decompression of response bodies"))
    parser.add_option("-B", "--beast", action="store_false", dest="beast",
                      default=True,
                      help=("By default, this module attempts to account for "
                            "beast mitigations, i.e., the 1/n-1 traffic "
                            "pattern, which seems to cause issues with "
                            "body reconstruction. Settings this flag "
                            "disables that action"))

    (options, lo) = parser.parse_args(module_data['args'])

    if options.disable_decompression:
        try:
            parser = htpy.init()
            parser.cfg.response_decompression = 1
        except AttributeError as e:
            module_options['error'] = \
                ("Version of htpy installed does not support disabling "
                 "decompression. Please upgrade htpy or do not use the "
                 "'-c/--disable-decompression' option")
            return module_options
        except Exception as e:
            module_options['error'] = ("Unknown error attempting to test htpy")
            return module_options

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

    if options.ports == '':
        ports = []
    else:
        ports = options.ports.split(",")
        try:  # This will except if ports is empty or malformed
            ports = [int(port) for port in ports]
        except Exception as e:
            module_options['error'] = \
                "Malformed port list '%s'" % (options.ports)
            return module_options

    module_data['counter'] = 0
    module_data['options'] = {'verbose': options.verbose,
                              'suppress': options.suppress,
                              'no-body': options.nobody,
                              'length': options.length,
                              'hash_function': options.hash_function,
                              'beast': options.beast,
                              'disable-decompression':
                              options.disable_decompression,
                              'ports': ports}

    return module_options


def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    if len(tcp.module_data['options']['ports']):
        ports = tcp.module_data['options']['ports']
        if sport not in ports and dport not in ports:
            return False

    if tcp.module_data['options']['verbose']:
        chop.tsprnt("New session: %s:%s->%s:%s" % (src, sport, dst, dport))

    tcp.stream_data['htpy_obj'] = \
        __htpyObj__(tcp.module_data['options'], tcp.timestamp)
    tcp.stream_data['connparser'] = \
        register_connparser(tcp.module_data['options'])
    tcp.stream_data['connparser'].set_obj(tcp.stream_data['htpy_obj'])
    return True


def handleStream(tcp):
    chopp = ChopProtocol('http')
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    tcp.stream_data['htpy_obj'].timestamp = tcp.timestamp
    if tcp.server.count_new > 0:
        if tcp.module_data['options']['verbose']:
            chop.tsprnt("%s:%s->%s:%s (%i)"
                        % (src, sport, dst, dport, tcp.server.count_new))

        if tcp.server.count_new == 1 and tcp.module_data['options']['beast']:
            tcp.discard(0)
        else:
            data_size = tcp.server.count - tcp.server.offset
            try:
                tcp.stream_data['connparser'].\
                    req_data(tcp.server.data[:data_size])
            except htpy.stop:
                tcp.stop()
            except htpy.error:
                if tcp.module_data['options']['verbose']:
                    chop.tsprnt("Stream error in htpy.")
                tcp.stop()
            tcp.discard(data_size)
    elif tcp.client.count_new > 0:
        if tcp.module_data['options']['verbose']:
            chop.tsprnt("%s:%s->%s:%s (%i)"
                        % (src, sport, dst, dport, tcp.client.count_new))

        if tcp.client.count_new == 1 and tcp.module_data['options']['beast']:
            tcp.discard(0)
        else:
            data_size = tcp.client.count - tcp.client.offset
            try:
                tcp.stream_data['connparser'].\
                    res_data(tcp.client.data[:data_size])
            except htpy.stop:
                tcp.stop()
            except htpy.error:
                if tcp.module_data['options']['verbose']:
                    chop.tsprnt("Stream error in htpy.")
                tcp.stop()
            tcp.discard(data_size)

    if tcp.stream_data['htpy_obj'].ready:
        trans = tcp.stream_data['htpy_obj'].transaction
        chopp.setClientData(trans['request'])
        chopp.setServerData(trans['response'])
        chopp.setTimeStamp(trans['timestamp'])
        chopp.setAddr(tcp.addr)
        chopp.flowStart = tcp.stream_data['htpy_obj'].flowStart

        tcp.stream_data['htpy_obj'].ready = False
        tcp.stream_data['htpy_obj'].temp = {}
        tcp.stream_data['htpy_obj'].transaction = {}

        return chopp

    return None


def teardown(tcp):
    chopp = ChopProtocol('http')
    ((src, sport), (dst, dport)) = tcp.addr
    tcp.stream_data['htpy_obj'].timestamp = tcp.timestamp

    # There's data collected in temp
    if len(tcp.stream_data['htpy_obj'].temp.keys()) > 1:
        # we don't care if only start is populated
        t = tcp.stream_data['htpy_obj'].temp

        if 'request' in t:
            if len(t['request'].keys()) == 0:
                try:
                    req = tcp.stream_data['htpy_obj'].lines.get(False)
                except Queue.Empty:
                    req = None
            else:
                req = t['request']

            if 'tmp_hash' in t['request']:
                if t['request']['body_len'] > 0:
                    t['request']['body_hash'] = \
                        t['request']['tmp_hash'].hexdigest()
                else:
                    t['request']['body_hash'] = ""
                del t['request']['tmp_hash']

        if 'response' in t:
            resp = t['response']
            if 'tmp_hash' in t['response']:
                if t['response']['body_len'] > 0:
                    t['response']['body_hash'] = \
                        t['response']['tmp_hash'].hexdigest()
                else:
                    t['response']['body_hash'] = ""
                del t['response']['tmp_hash']
        else:
            resp = None

        if req is not None or resp is not None:
            chopp.setClientData(req)
            chopp.setServerData(resp)
            chopp.setTimeStamp(t['start'])
            chopp.setAddr(tcp.addr)
            chopp.setTeardown()
            chopp.flowStart = tcp.stream_data['htpy_obj'].flowStart

            tcp.stream_data['htpy_obj'].ready = False
            tcp.stream_data['htpy_obj'].temp = {}
            tcp.stream_data['htpy_obj'].transaction = {}

            return chopp

    return None


def shutdown(module_data):
    return


def handleProtocol(chopp):
    if chopp.type != 'sslim':
        return

    stream_data = chopp.stream_data

    if 'htpy_obj' not in stream_data:
        stream_data['htpy_obj'] = \
            __htpyObj__(chopp.module_data['options'], chopp.timestamp)
        stream_data['connparser'] = register_connparser()
        stream_data['connparser'].set_obj(stream_data['htpy_obj'])

    ((src, sport), (dst, dport)) = chopp.addr
    stream_data['htpy_obj'].timestamp = chopp.timestamp

    if chopp.clientData:
        if chopp.module_data['options']['verbose']:
            chop.tsprnt("%s:%s->%s:%s" % (src, sport, dst, dport))
        try:
            stream_data['connparser'].req_data(chopp.clientData)
        except htpy.stop:
            chopp.stop()
        except htpy.error:
            if chopp.module_data['options']['verbose']:
                chop.tsprnt("Stream error in htpy.")
            chopp.stop()
            return

    if chopp.serverData:
        if chopp.module_data['options']['verbose']:
            chop.tsprnt("%s:%s->%s:%s" % (dst, dport, src, sport))
        try:
            stream_data['connparser'].res_data(chopp.serverData)
        except htpy.stop:
            chopp.stop()
        except htpy.error:
            if chopp.module_data['options']['verbose']:
                chop.tsprnt("Stream error in htpy.")
            chopp.stop()
            return

    if stream_data['htpy_obj'].ready:
        new_chopp = ChopProtocol('http')
        trans = stream_data['htpy_obj'].transaction
        new_chopp.setClientData(trans['request'])
        new_chopp.setServerData(trans['response'])
        new_chopp.setTimeStamp(trans['timestamp'])
        new_chopp.setAddr(chopp.addr)
        new_chopp.flowStart = stream_data['htpy_obj'].flowStart

        stream_data['htpy_obj'].ready = False
        stream_data['htpy_obj'].temp = {}
        stream_data['htpy_obj'].transaction = {}

        return new_chopp


def teardownProtocol(chopp):
    if chopp.type != 'sslim':
        return

    stream_data = chopp.stream_data

    # sslim returns an empty object on teardown
    if 'htpy_obj' not in stream_data:
        return

    hchopp = ChopProtocol('http')
    ((src, sport), (dst, dport)) = chopp.addr
    stream_data['htpy_obj'].timestamp = chopp.timestamp

    # There's data collected in temp
    if len(stream_data['htpy_obj'].temp.keys()) > 1:
        # we don't care if only start is populated
        t = stream_data['htpy_obj'].temp

        if 'request' in t:
            if len(t['request'].keys()) == 0:
                try:
                    req = stream_data['htpy_obj'].lines.get(False)
                except Queue.Empty:
                    req = None
            else:
                req = t['request']

            if 'tmp_hash' in t['request']:
                if t['request']['body_len'] > 0:
                    t['request']['body_hash'] = \
                        t['request']['tmp_hash'].hexdigest()
                else:
                    t['request']['body_hash'] = ""
                del t['request']['tmp_hash']

        if 'response' in t:
            resp = t['response']

            if 'tmp_hash' in t['response']:
                if t['response']['body_len'] > 0:
                    t['response']['body_hash'] = \
                        t['response']['tmp_hash'].hexdigest()
                else:
                    t['response']['body_hash'] = ""
                del t['response']['tmp_hash']

        else:
            resp = None

        if req is not None or resp is not None:
            hchopp.setClientData(req)
            hchopp.setServerData(resp)
            hchopp.setTimeStamp(t['start'])
            hchopp.setAddr(chopp.addr)
            hchopp.setTeardown()
            hchopp.flowStart = stream_data['htpy_obj'].flowStart

            stream_data['htpy_obj'].ready = False
            stream_data['htpy_obj'].temp = {}
            stream_data['htpy_obj'].transaction = {}

            return hchopp

    return None
