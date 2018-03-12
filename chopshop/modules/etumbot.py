# Copyright (c) 2014 Wesley Shields. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
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

# This decoder is based upon the report by Arbor Networks:
# http://www.arbornetworks.com/asert/wp-content/uploads/2014/06/ASERT-Threat-Intelligence-Brief-2014-07-Illuminating-Etumbot-APT.pdf
#
# There are variants of Etumbot which use different URLs and do not always
# have a hard-coded referer. The code should be easily adapted to those.

import struct
import binascii

from rc4 import rc4
from base64 import b64decode
from optparse import OptionParser

from c2utils import hexdump

moduleName="etumbot"
moduleVersion="0.1"
minimumChopLib="4.0"

def cmd_exec(data):
    chop.tsprnt("EXEC (not implemented)\n%s" % hexdump(data))

def cmd_putfile(data):
    chop.tsprnt("PUTFILE (not implemented)\n%s" % hexdump(data))

def cmd_readfile(data):
    chop.tsprnt("READFILE (not implemented)\n%s" % hexdump(data))

def cmd_sleep(data):
    chop.tsprnt("SLEEP (not implemented)\n%s" % hexdump(data))

def cmd_uninstall(data):
    chop.tsprnt("UNINSTALL (not implemented)\n%s" % hexdump(data))

def cmd_ping(data):
    chop.tsprnt("Command response: Ping again.")
    # XXX: There's a bunch of data here, no clue what it is.
    #chop.prnt(hexdump(data))

def module_info():
    return 'Process etumbot traffic. Requires "http" parent.'

def init(module_data):
    chop.prnt("*************************************************************")
    chop.prnt("WARNING: This module is still experimental and unfinished.")
    chop.prnt("If you have any PCAPs that contain features that are not")
    chop.prnt("implemented in this module please send them to me.")
    chop.prnt("*************************************************************")
    module_options = { 'proto': [{'http': ''}] }

    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
        default=False, help="Be verbose about incoming messages.")
    parser.add_option("-H", "--hosts", action="store", dest="hosts",
        default=[], help="List of hosts to check. Comma separated.")

    (opts, args) = parser.parse_args(module_data['args'])

    module_data['verbose'] = opts.verbose
    module_data['hosts'] = opts.hosts.split(',')
    module_data['key'] = None
    module_data['opcodes'] = {
        0x03: cmd_exec,
        0x04: cmd_putfile,
        0x05: cmd_readfile,
        0x07: cmd_sleep,
        0x08: cmd_uninstall,
        0x09: cmd_ping
    }

    if not module_data['hosts']:
        module_options['error'] = "Must specify at least one host."

    return module_options

# Handle key "negotiation" ;)
def key_negotiation(data):
    blob = b64decode(data, '_-')
    # The key is 8 bytes in and ends with a NULL.
    null = blob[8:].find('\x00')
    if null == -1:
        chop.prnt("Unable to find key.")
        return
    key = blob[8:8+null]
    chop.tsprnt("Key found: 0x%s" % binascii.hexlify(key))
    return key

# Handle system info
def system_info(data, key):
    blob = b64decode(data, '_-')
    cryptobj = rc4(key=key)
    decrypted = cryptobj.crypt(blob)
    (hostname, username, ip, proxy, id_, unknown) = decrypted.split('|')
    chop.tsprnt("Beacon:")
    chop.tsprnt("\tHostname: %s" % hostname)
    chop.tsprnt("\tUsername: %s" % username)
    chop.tsprnt("\tIP: %s" % ip)
    chop.tsprnt("\tID: %s" % id_)
    chop.tsprnt("\tUnknown: %s" % binascii.hexlify(unknown))

# Handle execution commands
def execution(path, body, module_data):
    key = module_data['key']
    opcodes = module_data['opcodes']
    verbose = module_data['verbose']

    blob = b64decode(path, '_-')
    cryptobj = rc4(key=key)
    decrypted = cryptobj.crypt(blob)
    chop.tsprnt("Command request from %s" % decrypted)
    if body:
        data = b64decode(body, '_-')
        cryptobj = rc4(key=key)
        decrypted = cryptobj.crypt(data)
        if len(decrypted) < 4:
            chop.tsprnt("Command response length invalid.")
            return
        opcode = struct.unpack('<I', decrypted[:4])[0]
        if opcode in opcodes:
            opcodes[opcode](decrypted[4:])
        else:
            chop.tsprnt("Unknown opcode (%i)" % opcode)
            if verbose:
                chop.tsprnt("Data:\n%s" % hexdump(decrypted))

def command_fail(data, module_data):
    # XXX: Pretty sure this will be base64 and rc4 like the rest, but I
    # don't have real data to test with yet.
    chop.tsprnt("Command failure (not implemented):\n%s" % hexdump(data))

# This is different from the cmd_putfile. That command is used to tell the
# implant to fetch a file. This handles the request that actually fetches the
# file.
def put_file(data, body, module_data):
    # XXX: The actual file contents should be in body, and are likely base64
    # and rc4 like the rest.
    chop.tsprnt("Putfile (not implemented):\n%s" % hexdump(body))

# This is different from the cmd_readfile. That command is used to tell the
# implant to send a file. This handles the request which sends the file size.
def read_file(query, body, module_data):
    # XXX: The query will be:
    # id=<encrypted computer name>&&mux=<encrypted total file size>
    # So we need to parse those out. Also, the response body should have 'I'm
    # Ready' in it.
    chop.tsprnt("Readfile (not implemented):\n%s\n%s" % (hexdump(query), hexdump(body)))

def read_file_chunk(query, body, module_data):
    # XXX: The query will be:
    # id=<encoded computer name>&&date=<file chunk data>
    # So we need to parse those out and store it. Also, the response body should
    # have 'OK' in it.
    chop.tsprnt("Readfile chunk (not implemented):\n%s\n%s" % (hexdump(query), hexdump(body)))

def handleProtocol(protocol):
    if protocol.type != 'http':
        chop.prnt("Need http.")
        return

    request = protocol.clientData
    response = protocol.serverData

    module_data = protocol.module_data

    # Make sure the request is to our host and has the hardcoded referer.
    if (request['headers'].get('Referer', '') == 'http://www.google.com/' and
        request['headers'].get('Host', '') in module_data['hosts']):
        if module_data['verbose']:
            chop.tsprnt("Host and referer match, continuing.")
    else:
        protocol.stop()

    # Get the key. Right now this module supports only one key at a time.
    # If there are multiple sessions with different keys you will need to
    # split them out somehow.
    if request['uri']['path'] == '/home/index.asp' and request['uri']['query'].startswith('typeid='):
        key = key_negotiation(response['body'])
        if not key:
            protocol.stop()
            return
        module_data['key'] = key
        return

    # Anything after this point requires a key.
    if not module_data['key']:
        chop.prnt("Request found with no key seen yet, aborting.")
        protocol.stop()
        return

    if request['uri']['path'].startswith('/image/') and request['uri']['path'].endswith('.jpg'):
        # Base64 decode everything between '/image/' and '.jpg' and use the RC4
        # key to decrypt it.
        system_info(request['uri']['path'][7:-4], module_data['key'])
    elif request['uri']['path'].startswith('/history/') and request['uri']['path'].endswith('.asp'):
        # Base64 decode everything between '/history/' and '.jpg'
        # and use the RC4 key to decrypt it.
        execution(request['uri']['path'][9:-4], response['body'], module_data)
    elif request['uri']['path'].startswith('/tech/s.asp/m='):
        # The m= part is the message.
        command_fail(request['uri']['path'][14:], module_data)
    elif request['uri']['path'].startswith('/docs/name='):
        # The name= part is the message and the file is in the response body.
        put_file(request['uri']['path'][11:], response['body'], module_data)
    elif request['uri']['path'].startswith('/manage/asp/item.asp'):
        read_file(request['uri']['query'], response['body'], module_data)
    elif request['uri']['path'].startswith('/article/30441/Review.asp'):
        read_file_chunk(request['uri']['query'], response['body'], module_data)
