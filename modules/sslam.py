# Copyright (c) 2015 Wesley Shields. All rights reserved.
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

from sslim import sslim

from optparse import OptionParser

from c2utils import hexdump
from pprint import pformat

moduleName="sslam"
moduleVersion="1.0"
minimumChopLib="4.0"

def module_info():
    return "Dump number of blocks (or bytes) in application data to a file."

def init(module_data):
    module_options = { 'proto': [{'sslim': ''}]}
    parser = OptionParser()

    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
        default=False, help="Be verbose about incoming messages")
    parser.add_option("-s", "--size", action="store", dest="size", type=int,
        default=1, help="Output one character per <size> bytes (stream cipher only)")

    (options, lo) = parser.parse_args(module_data['args'])

    module_data['verbose'] = options.verbose
    module_data['size'] = options.size

    if module_data['size'] <= 0:
        module_options['error'] = "Size must be positive integer"

    return module_options

def handleProtocol(chopp):
    if chopp.type != 'sslim':
        chop.prnt("Error: Not SSLim.")
        return

    module_data = chopp.module_data
    stream_data = chopp.stream_data

    # If there is a single TCP packet which contains multiple SSL records
    # SSLim will pass along a single chopp with multiple records in metadata.
    for metadata in chopp.metadata:
        if module_data['verbose']:
            chop.tsprnt(metadata)

        # Grab the cipher suite so we know what we are dealing with.
        if (metadata['content_type'] == sslim.HANDSHAKE and
            metadata['handshake_type'] == sslim.SERVER_HELLO):
            stream_data['cipher_suite'] = metadata['cipher_suite_details']
        elif metadata['content_type'] == sslim.APPLICATION_DATA:
            cipher_suite = stream_data.get('cipher_suite', None)
            if not cipher_suite:
                chop.tsprnt("Stopping: Application data with no cipher suite.")
                chopp.stop()
                return

            # Make sure it is a block cipher and that it is an exact multiple
            # of the block size.
            if cipher_suite['cipher'] == 'block':
                block_size = cipher_suite['block_size']
                if (len(metadata['data']) % block_size) != 0:
                    chop.tsprnt("Stopping: Data is not a multiple of block size.")
                    chopp.stop()
                    return

                data_size = len(metadata['data']) / block_size
            elif cipher_suite['cipher'] == 'stream':
                data_size = len(metadata['data']) / module_data['size']
            else:
                chop.tsprnt("Unknown cipher mode.")
                chopp.stop()
                return

            ((sip, sport), (dip, dport)) = chopp.addr
            filename = "%s:%s_%s:%s" % (sip, sport, dip, dport)
            if metadata['direction'] == sslim.CLIENT_TO_SERVER:
                char = 'C'
            else:
                char = 'S'

            data = "%s" % char * data_size
            chop.appendfile(filename, data)
    return

def shutdown(module_data):
    return
