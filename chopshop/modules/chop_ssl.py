# Copyright (c) 2015 The MITRE Corporation. All rights reserved.
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

from optparse import OptionParser

from sslim import sslim, sslimException, sslimChopProtocol
from c2utils import parse_addr, hexdump

moduleName="chop_ssl"
moduleVersion="1.0"
minimumChopLib="4.0"

def sslim_metadata_callback(metadata, chopp):
    # Metadata is appended to a list because there can be multiple TLS records
    # in a given TCP packet.
    chopp.metadata.append(metadata)

def sslim_req_callback(data, chopp):
    # Have to append because of multiple SSL records in a single packet.
    chopp.setClientData(chopp.clientData + data)

def sslim_res_callback(data, chopp):
    # Have to append because of multiple SSL records in a single packet.
    chopp.setServerData(chopp.serverData + data)

def module_info():
    return "Decrypt SSL sessions from TCP and pass \"sslim\" out."

def init(module_data):
    module_options = { 'proto': [ { 'tcp': 'sslim' } ] }

    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                      default=False, help="Be verbose about new flows and packets")
    parser.add_option("-k", "--keyfile", action="store", dest="keyfile",
                      default=None, help="Private key file (must be RSA)")

    (opts, lo) = parser.parse_args(module_data['args'])

    module_data['verbose'] = opts.verbose
    module_data['keyfile'] = opts.keyfile

    #if module_data['keyfile'] == None:
    #    module_options['error'] = "Must provide a keyfile."
    #    return module_options

    module_data['sslim'] = sslim(module_data['keyfile'])
    module_data['sslim'].metadata_callback = sslim_metadata_callback
    module_data['sslim'].req_callback = sslim_req_callback
    module_data['sslim'].res_callback = sslim_res_callback

    return module_options

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    if tcp.module_data['verbose']:
        chop.tsprnt("New session: %s:%i -> %s:%i" % (src, sport, dst, dport))
    tcp.stream_data['ssl'] = False
    return True

def handleStream(tcp):
    # Make sure this is really SSL. Sadly we can't do this in taste()
    # because there is no payload data available that early.
    data = ''
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    server_dlen = tcp.server.count - tcp.server.offset
    client_dlen = tcp.client.count - tcp.client.offset
    # If we haven't identified this as SSL yet
    if tcp.stream_data['ssl'] == False:
        # Do we have enough data for checks?
        if tcp.server.count_new > 0 and server_dlen > 7:
            # Check if proxy CONNECT
            if tcp.server.data[:8] == "CONNECT ":
                if tcp.module_data['verbose']:
                    chop.tsprnt("%s:%i -> %s:%i (%i) - CONNECT (ignored)" % (
                                src,
                                sport,
                                dst,
                                dport,
                                server_dlen))
                tcp.discard(server_dlen)
                return
            # Otherwise, prepare to check if SSL handshake
            data = tcp.server.data[:3]
        # Do we have enough data for checks?
        elif tcp.client.count_new > 0 and client_dlen > 5:
            # Check if proxy CONNECT response
            if tcp.client.data[:6] == "HTTP/1":
                if tcp.module_data['verbose']:
                    chop.tsprnt("%s:%i -> %s:%i (%i) - HTTP/1 (ignored)" % (
                                src,
                                sport,
                                dst,
                                dport,
                                client_dlen))
                tcp.discard(client_dlen)
                return
            # Otherwise, prepare to check if SSL handshake
            data = tcp.client.data[:3]
        else:
            # Need more data
            return

        # We have data, so check if it is SSL Handshake.
        # There's probably more to this, but this is good enough for now.
        if data in ('\x16\x03\x00', '\x16\x03\x01', '\x16\x03\x02', '\x16\x03\x03'):
            tcp.stream_data['ssl'] = True
            tcp.stream_data['chopp'] = sslimChopProtocol()
            tcp.module_data['sslim'].callback_obj = tcp.stream_data['chopp']
        else:
            if tcp.module_data['verbose']:
                chop.tsprnt("%s:%i -> %s:%i: Stopping, not really SSL!" % (
                            src,
                            sport,
                            dst,
                            dport))
            tcp.module_data['sslim'].done(tcp.addr)
            tcp.stop()
            return

    # Always clear out any existing data.
    tcp.stream_data['chopp'].clientData = ''
    tcp.stream_data['chopp'].serverData = ''
    tcp.stream_data['chopp'].metadata =  []

    # We have identified this connection as SSL, so just process the packets
    if tcp.server.count_new > 0:
        if tcp.module_data['verbose']:
            chop.tsprnt("%s:%s -> %s:%s (%i)" % (
                        src,
                        sport,
                        dst,
                        dport,
                        len(tcp.server.data[:tcp.server.count_new])))
        try:
            tcp.module_data['sslim'].parse_to_server(tcp.server.data[:tcp.server.count_new], tcp.addr)
        except sslimException as e:
            if tcp.module_data['verbose']:
                chop.prnt(e)
            tcp.module_data['sslim'].done(tcp.addr)
            tcp.stop()
            return
        tcp.discard(tcp.server.count_new)
    if tcp.client.count_new > 0:
        if tcp.module_data['verbose']:
            chop.tsprnt("%s:%s -> %s:%s (%i)" % (
                        src,
                        sport,
                        dst,
                        dport,
                        len(tcp.client.data[:tcp.client.count_new])))
        try:
            tcp.module_data['sslim'].parse_to_client(tcp.client.data[:tcp.client.count_new], tcp.addr)
        except sslimException as e:
            if tcp.module_data['verbose']:
                chop.prnt(e)
            tcp.module_data['sslim'].done(tcp.addr)
            tcp.stop()
            return
        tcp.discard(tcp.client.count_new)

    if (tcp.stream_data['chopp'].clientData or
        tcp.stream_data['chopp'].serverData or
        tcp.stream_data['chopp'].metadata):
        return tcp.stream_data['chopp']

    return

def teardown(tcp):
    chopp = sslimChopProtocol()
    return chopp

def shutdown(module_data):
    return
