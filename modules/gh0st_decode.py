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

# The purpose of this chopshop module is to decode commands and responses
# for Gh0st backboors.
#
# The typical format for a Gh0st packet is:
# <flag><compressed_size><uncompressed_size><zlib payload>
#
# - flag is a 5 character string
# - compressed size is the size of the entire packet, not just zlib payload
# - uncompressed size of zlib payload
# - zlib payload consists of zlib header ('\x78\x9c') and compressed payload
#

import sys
import zlib
import struct
from optparse import OptionParser
from c2utils import hexdump, packet_time, b2a_printable
from mailutils import send_alert
import binascii
import os
import ntpath
import re

moduleName = "gh0st_decode"

#
# Chopshop functions
#

def init(module_data):
    parser = OptionParser()
    parser.add_option("-a", "--alert", action="store", dest="alert",
                      type="string", help="string to use in alert")
    parser.add_option("-c", "--commands", action="store_true",
                      dest="commands", default=False, help="print commands")
    parser.add_option("-r", "--responses", action="store_true",
                      dest="responses", default=False, help="print responses")
    parser.add_option("-m", "--mail", action="store", dest="addresses",
                      type="string", help="comma separated e-mail address list")
    parser.add_option("-s", "--savefiles", action="store_true", dest="savefiles",
                      help="save carved files")
    parser.add_option("-v", "--verbose", action="store_true",
                      dest="verbose", default=False, help="verbosity")

    (opts,lo) = parser.parse_args(module_data['args'])

    module_data['addresses'] = opts.addresses
    module_data['alert'] = opts.alert
    module_data['commands'] = opts.commands
    module_data['responses'] = opts.responses
    module_data['savefiles'] = opts.savefiles
    module_data['verbose'] = opts.verbose
    module_data['alert_sent'] = False

    module_options = {'proto':'tcp'}
    return module_options


# Only concerned with traffic on ports 80 and 443
def taste(tcp):
    tasty = False
    ((src, sport), (dst, dport)) = tcp.addr
    if dport == 80 or dport == 443:
        tcp.stream_data["client_buf"] = ""
        tcp.stream_data["client_fname"] = ""
        tcp.stream_data["client_fname_size"] = 0
        tcp.stream_data["bytes_written"] = 0
        tcp.stream_data["server_buf"] = ""
        tcp.stream_data["server_fname"] = ""

        tasty = True

    return tasty


# Search for Gh0st packets as they arrive and decode
def handleStream(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    client_data = ""
    server_data = ""

    # Use regex to locate Gh0st packets, add new flags as needed
    pattern = re.compile("^(Gh0st).{8}(\x78\x9c)")

    # Decode the client side
    if tcp.client.count_new > 0:

        # Payload that spans multiple packets is buffered in a stream variable
        client_data = tcp.stream_data["client_buf"] + tcp.client.data[:tcp.client.count_new]
        tcp.stream_data["client_buf"] = ""
        tcp.discard(tcp.client.count_new)

        pattern_found = pattern.search(client_data)


        if pattern_found and tcp.module_data["alert"] and not tcp.module_data["alert_sent"]:
            send_alert(tcp.module_data["addresses"], tcp.module_data["alert"], "localhost", "example@localhost")
            tcp.module_data["alert_sent"] = True

        if pattern_found and tcp.module_data["commands"]:
            offset = pattern_found.start()

            # Pull out the buffer sizes
            comp_len = struct.unpack('<I', client_data[offset+5:offset+9])[0]
            uncomp_len = struct.unpack('<I', client_data[offset+9:offset+13])[0]

            if tcp.module_data["verbose"]:
                chop.prnt("offset: %i - comp: %i - uncomp: %i - len: %i" % (offset,comp_len, uncomp_len, len(client_data[offset:offset+comp_len])))

            # If have full zlib bundle decoded it, else buffer
            if comp_len <= len(client_data[offset:]):
                try:
                    decoded = zlib.decompress(client_data[offset+13:offset+comp_len])

                    #hexdump(decoded)

                    # The first byte of most commands is a command flag
                    if decoded[0] == '\x00':
                        chop.tsprnt("Keepalive")
                    elif decoded[0] == '\x01':
                        chop.tsprnt("List Drives")
                    elif decoded[0] == '\x02':
                        chop.tsprnt("Browse '%s'" % decoded[1:].replace('\x00', ""))
                    elif decoded[0] == '\x03':
                        chop.tsprnt("Print '%s'" % decoded[1:].replace('\x00', ''))

                    # The download request and data transfer are two
                    # separate commands.  These commands also have an
                    # an additional 8 byte buffer between the flag and data
                    elif decoded[0] == '\x04':
                        tcp.stream_data["client_fname_size"] = struct.unpack('<I', decoded[5:9])[0]
                        chop.tsprnt("Download %s (%i)" % (decoded[9:].replace('\x00', ""), tcp.stream_data["client_fname_size"]))
                        tcp.stream_data["client_fname"] = ntpath.split(decoded[9:].replace('\x00', ''))[1]

                    # Save files to specified location
                    elif decoded[0] == '\x05':
                        # The check for client_fname_size ensures that if
                        # an overflow condition happens that we don't end
                        # up in an unexpected state. We will stop carving
                        # until we see a \x04 command again to reset our
                        # state.
                        if tcp.module_data["savefiles"] and tcp.stream_data["client_fname_size"] != 0:
                            finalize = True
                            fname = str(tcp.stream_data["client_fname"])
                            data = decoded[9:]
                            size = len(data)
                            if tcp.stream_data["bytes_written"] + size > tcp.stream_data["client_fname_size"]:
                                status = "Overflow detected. Likely corrupt!"
                            elif tcp.stream_data["bytes_written"] + size < tcp.stream_data["client_fname_size"]:
                                status = "Expecting more, at %i of %i" % (tcp.stream_data["bytes_written"] + size, tcp.stream_data["client_fname_size"])
                                finalize = False
                            else:
                                status = "EOF"
                            chop.savefile(fname, data, finalize)
                            chop.tsprnt("Wrote %i bytes of %s to %s (%s)" % (size, tcp.stream_data["client_fname"], fname, status))
                            if finalize:
                                tcp.stream_data["client_fname"] = ""
                                tcp.stream_data["client_fname_size"] = 0
                                tcp.stream_data["bytes_written"] = 0
                            else:
                                tcp.stream_data["bytes_written"] += size
                        else:
                            chop.tsprnt("Downloaded %i bytes of %s" % (len(decoded[9:]), tcp.stream_data["client_fname"]))

                    # Looks like an ACK of some sort
                    elif decoded[0] == '\x07':
                        None
                    elif decoded[0] == '\x09':
                        chop.tsprnt("Unknown %s" % decoded[1:])
                    elif decoded[0] == '\x1e':
                        chop.tsprnt("Shell %s" % decoded[1:])
                    else:
                        chop.tsprnt("%s" % decoded.strip())

                except Exception, err:
                    chop.prnt("Error: ", err)

            else:
                tcp.stream_data["client_buf"] = client_data


    # Decode server side
    if tcp.server.count_new > 0:

        # Payload that spans multiple packets is buffered in a stream variable
        server_data = tcp.stream_data["server_buf"] + tcp.server.data[:tcp.server.count_new]
        tcp.stream_data["server_buf"] = ""
        tcp.discard(tcp.server.count_new)

        pattern_found = pattern.search(server_data)
        if pattern_found and tcp.module_data["responses"]:
            offset = pattern_found.start()

            # Pull out the buffer sizes
            comp_len = struct.unpack('<I', server_data[offset+5:offset+9])[0]
            uncomp_len = struct.unpack('<I', server_data[offset+9:offset+13])[0]

            if tcp.module_data["verbose"]:
                chop.tsprnt(("offset: %i - comp: %i - uncomp: %i - len: %i" % (offset,comp_len, uncomp_len, len(server_data[offset:offset+comp_len]))))

            # If have full zlib bundle decoded it, else buffer
            if comp_len <= len(server_data[offset:]):
                try:
                    decoded = zlib.decompress(server_data[offset+13:offset+comp_len])
                    #hexdump(decoded)
                    # The first byte of most commands is a command flag

                    # List drives
                    if decoded[0] == "\x67":
                        chop.tsprnt("Drive info")
                        chop.tsprnt(hexdump(decoded))

                    # This command returns some system info.  This decode
                    # is a little crude, we're going to replace strings of
                    # '\x00' with a space and then remove individual '\x00'
                    # from unicode strings.
                    elif decoded[0] == "\x66":
                        p = re.compile("\x00\x00+")
                        chop.tsprnt("%s" % p.sub(" ", decoded[1:]).replace("\x00", ""))

                    elif decoded[0] =="\x69":
                        chop.tsprnt("%s" % decoded[1:].replace("\x00", ""))

                    # Response to an 0x03 command to print a file
                    elif decoded[0] == "\x6a":
                        None

                    elif decoded[0] == "\x68":
                        listing = decoded[2:]
                        name_start = 0
                        name_end = listing.find("\x00\x00", name_start)
                        while name_start > -1 and name_start < len(listing):

                            chop.prnt("\t" + listing[name_start:name_end].replace("\x00", ""))
                            zero_flag = listing.find("\x01\x00", name_end)
                            one_flag = listing.find("\x01\x10", name_end)

                            if zero_flag < 0 and one_flag < 0:
                                name_start = -1
                            elif zero_flag > -1 and one_flag < 0:
                                name_start = zero_flag + 2
                            elif one_flag > -1 and zero_flag < 0:
                                name_start = one_flag + 2
                            elif zero_flag < one_flag:
                                name_start = zero_flag + 2
                            elif one_flag < zero_flag:
                                name_start = one_flag + 2
                            else:
                                name_start = -1

                            if name_start > -1 and name_start < len(listing):
                                name_end = listing.find("\x00\x00", name_start)

                    # Appears to be an ACK to certain commands
                    # particularly downloads
                    elif decoded[0] == "\x70":
                        None

                    # Print drive information
                    elif decoded[0] == "\x71":
                        start = 1
                        while start < len(decoded):
                            drive_letter = decoded[start]

                            start += 10
                            end = decoded.find("\x00", start)
                            if start < end:
                                drive_name = decoded[start:end]
                            else:
                                drive_name = "None"

                            start = end + 1
                            end = decoded.find("\x00", start)
                            if start < end:
                                drive_format = decoded[start:end]
                            else:
                                drive_format = "None"

                            chop.tsprnt("Drive: %s - Name: %s - Format: %s" % (drive_letter, drive_name, drive_format))

                            start = end + 1

                    # Print directory listing
                    elif decoded[0] == "\x72":
                        start = 2
                        while start >= 2:
                            end = decoded.find("\x00", start)
                            chop.prnt("\t%s" % (decoded[start:end]))
                            start = decoded.find("\x01\x10", end) + 2
                    elif decoded[0] == "\x7a":
                        pass
                    else:
                        chop.tsprnt("%s" % decoded)
                except Exception, err:
                    chop.prnt("Error: ", err)

            else:
                tcp.stream_data["server_buf"] = server_data


def teardown(tcp):
    pass

def module_info():
    print "Decode and display Gh0st backdoor commands and responses"

def shutdown(module_data):
    pass

