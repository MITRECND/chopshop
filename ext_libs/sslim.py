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

# From a module authors perspective the API to SSLim is very minimal:
#  - Instantiate one sslim object for the lifetime of your module.
#  - Set your callback attributes right away. As soon as parsing starts you
#  will not be able to change the callbacks for that parser.
#  - Use the parse_to_client and parse_to_server methods of the sslim object to
#  parse the data. When data has been decrypted (and decompressed if necessary)
#  your callback will be called.
#  - When the session is in teardown delete your parser from the sslim object
#  (this is the done method).
# Quick note on internals:
# While the interface to SSLim is intentionally minimal there is a lot of work
# going on under the hood. The SSLim class is a very small class designed to do
# a couple of things:
#  - Instantiate parsers if the quad-tuple is new.
#  - Store the parsers using the quad-tuple as a key.
#  - Provide a way for parsers to be removed when the session is terminating.
#  - Provide a way for parsers to store the minimal amount of state necessary
#  to support session resuming. This is done with the check_sid and add_sid
#  methods in the sslim class. These are passed in to each parser as functions
#  that can be called as store_ms and check_sid. When a new session id is found
#  the master secret is stored in a dictionary by using the store_ms method.
#  The parser can use check_sid to grab the master secret that has been stored
#  for the old session when a new one is found to be resuming. Each parser
#  stores it's own state internally. This includes the necessary crypto
#  objects, the various descriptions of the cipher suites, the decompression
#  objects, the PRF, everything to do a full parse and decrypt.

import math
import zlib
import struct
from sslim_ciphers import sslim_cipher_suites

from M2Crypto import RC4, RSA, EVP

from ChopProtocol import ChopProtocol

# Our own special ChopProtocol child class. We need to have a list of
# metadata for each record processed.
class sslimChopProtocol(ChopProtocol):
    def __init__(self):
        self.metadata = []
        super(self.__class__, self).__init__('sslim')

class sslimException(Exception):
    pass

class sslimUnknownCipher(sslimException):
    def __init__(self, msg, val=None):
        self.msg = msg
        self.val = val

    def __str__(self):
        if self.val:
            return "%s: 0x%x" % (self.msg, self.val)
        else:
            return "%s" % self.msg

class sslimUnknownCompression(sslimException):
    def __init__(self, msg, val=None):
        self.msg = msg
        self.val = val

    def __str__(self):
        if self.val:
            return "%s: 0x%x" % (self.msg, self.val)
        else:
            return "%s" % self.msg

class sslimBadValue(sslimException):
    def __init__(self, msg, val=None):
        self.msg = msg
        self.val = val

    def __str__(self):
        if self.val:
            return "%s: %s" % (self.msg, hex(self.val))
        else:
            return "%s" % self.msg

class sslimCryptoError(sslimException):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "Crypto failure: %s" % self.msg

class sslimCallbackError(sslimException):
    def __init__(self):
        pass

    def __str__(self):
        return "Callback error"

class sslimCallbackStop(sslimException):
    def __init__(self):
        pass

    def __str__(self):
        return "Callback stopped"

class sslim(object):
    # Constants for callback returns to raise appropriate exceptions
    OK = 1
    STOP = 2
    ERROR = 3

    # Version constants
    SSLv3_0 = 0x0300
    TLSv1_0 = 0x0301
    TLSv1_1 = 0x0302
    TLSv1_2 = 0x0303

    # Extensions we need to parse
    EXT_SESSIONTICKET_TYPE = 0x0023

    # Content type values we need to parse
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17

    # Handshake types (we don't parse all of these (yet?))
    HELLO_REQUEST = 0x00
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    EXT_SESSIONTICKET = 0x04
    CERTIFICATE = 0x0B
    SERVER_KEY_EXCHANGE = 0x0C
    CERTIFICATE_REQUEST = 0x0D
    SERVER_HELLO_DONE = 0x0E
    CERTIFICATE_VERIFY = 0x0F
    CLIENT_KEY_EXCHANGE = 0x10
    FINISHED = 0x14

    # Supported compression algorithms
    DEFLATE_COMPRESSION = 0x01
    NULL_COMPRESSION = 0x00

    # Cipher suites.
    # XXX: Extend this with all of them, along with entries to
    # sslim_cipher_suites.
    TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003
    TLS_RSA_WITH_RC4_128_MD5 = 0x0004
    TLS_RSA_WITH_RC4_128_SHA = 0x0005
    TLS_RSA_WITH_DES_CBC_SHA = 0x0009
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C

    CLIENT_TO_SERVER = 1
    SERVER_TO_CLIENT = 2

    def __init__(self, keyfile=None):
        # All callbacks.
        self.callbacks = {
                           'request': None,
                           'response': None,
                           'request_encrypted': None,
                           'response_encrypted': None,
                           'client_hello': None,
                           'server_hello': None,
                           'certificate': None,
                           'server_hello_done': None,
                           'client_key_exchange': None,
                           'change_cipher_spec': None,
                           'session_ticket': None,
                           'server_key_exchange': None
                         }

        # Only the callbacks for metadata, only useful internally.
        self.__metadata_callbacks = [ k for k in self.callbacks if k != 'request' or k != 'response' ]

        self.keypair = None
        if keyfile:
            # XXX: Support callback?
            self.keypair = RSA.load_key(keyfile)

        self.parsers = {}
        self.sids = {}

    @property
    def req_callback(self):
        return self.callbacks['request']

    @req_callback.setter
    def req_callback(self, func):
        self.callbacks['request'] = func

    @property
    def res_callback(self):
        return self.callbacks['response']

    @res_callback.setter
    def res_callback(self, func):
        self.callbacks['response'] = func

    @property
    def req_encrypted_callback(self):
        return self.callbacks['request_encrypted']

    @req_encrypted_callback.setter
    def req_encrypted_callback(self, func):
        self.callbacks['request_encrypted'] = func

    @property
    def res_encrypted_callback(self):
        return self.callbacks['response_encrypted']

    @res_encrypted_callback.setter
    def res_encrypted_callback(self, func):
        self.callbacks['response_encrypted'] = func

    @property
    def client_hello_callback(self):
        return self.callbacks['client_hello']

    @client_hello_callback.setter
    def client_hello_callback(self, func):
        self.callbacks['client_hello'] = func

    @property
    def server_hello_callback(self):
        return self.callbacks['server_hello']

    @server_hello_callback.setter
    def server_hello_callback(self, func):
        self.callbacks['server_hello'] = func

    @property
    def certificate_callback(self):
        return self.callbacks['certificate']

    @certificate_callback.setter
    def certificate_callback(self, func):
        self.callbacks['certificate'] = func

    @property
    def server_hello_done_callback(self):
        return self.callbacks['server_hello_done']

    @server_hello_done_callback.setter
    def server_hello_done_callback(self, func):
        self.callbacks['server_hello_done'] = func

    @property
    def client_key_exchange_callback(self):
        return self.callbacks['client_key_exchange']

    @client_key_exchange_callback.setter
    def client_key_exchange_callback(self, func):
        self.callbacks['client_key_exchange'] = func

    @property
    def change_cipher_spec_callback(self):
        return self.callbacks['change_cipher_spec']

    @change_cipher_spec_callback.setter
    def change_cipher_spec_callback(self, func):
        self.callbacks['change_cipher_spec'] = func

    @property
    def session_ticket_callback(self):
        return self.callbacks['session_ticket']

    @session_ticket_callback.setter
    def session_ticket_callback(self, func):
        self.callbacks['session_ticket'] = func

    @property
    def server_key_exchange_callback(self):
        return self.callbacks['server_key_exchange']

    @server_key_exchange_callback.setter
    def server_key_exchange_callback(self, func):
        self.callbacks['server_key_exchange'] = func
    # Metadata callback is an easy way to register for all callbacks except
    # for those that pass cleartext data back.
    @property
    def metadata_callback(self):
        return self.callbacks['request']

    @req_callback.setter
    def metadata_callback(self, func):
        for k in self.__metadata_callbacks:
            self.callbacks[k] = func

    def add_sid(self, sid, ms):
        if sid == None or sid == 0:
            return
        self.sids[sid] = ms

    def check_sid(self, sid):
        if sid in self.sids:
            return self.sids[sid]
        else:
            return None

    def parse_to_client(self, data, addr):
        if addr in self.parsers:
            parser = self.parsers[addr]
        else:
            parser = self.parsers[addr] = sslim_parser(self.keypair,
                                                       self.callbacks,
                                                       self.callback_obj,
                                                       self.add_sid,
                                                       self.check_sid)
        parser.parse(data, self.SERVER_TO_CLIENT)

    def parse_to_server(self, data, addr):
        if addr in self.parsers:
            parser = self.parsers[addr]
        else:
            parser = self.parsers[addr] = sslim_parser(self.keypair,
                                                       self.callbacks,
                                                       self.callback_obj,
                                                       self.add_sid,
                                                       self.check_sid)
        parser.parse(data, self.CLIENT_TO_SERVER)

    def done(self, addr):
        self.callback_obj = None
        if addr in self.parsers:
            del self.parsers[addr]

class sslim_parser(sslim):
    def __init__(self, keypair, callbacks, callback_obj, add_sid, check_sid):
        self.keypair = keypair

        # Since this object is tied to a session and sid's can go
        # across sessions when resuming we have to have a way to
        # track them.
        #
        # store_ms is used when a new session ID is found.
        # check_sid returns the master secret or None.
        self.store_ms = add_sid
        self.check_sid = check_sid

        # Callbacks.
        self.callbacks = callbacks
        self.callback_obj = callback_obj

        # Various sizes for most of the things we parse.
        self.hdr_size = struct.calcsize('>BHH')
        self.hs_hdr_size = struct.calcsize('>B')
        self.hs_type_size = struct.calcsize('>I')
        self.version_size = struct.calcsize('>H')
        self.sid_len_size = struct.calcsize('>B')
        self.cipher_suite_size = struct.calcsize('>H')
        self.compression_size = struct.calcsize('>B')
        self.extension_size = struct.calcsize('>H')
        self.hs_key_exch_size = struct.calcsize('>HB')
        self.hs_pms_len_size = struct.calcsize('>H')
        self.hs_change_cipher_size = struct.calcsize('>H')

        # The bits needed to keep track of the stream state.
        self.ver = None
        self.c_rnd = None
        self.s_rnd = None
        self.c_sid = None
        self.s_sid = None
        self.ms = None
        self.client_ticket = None
        self.server_ticket = None
        self.c_cryptobj = None
        self.s_cryptobj = None
        self.c_zobj = None
        self.s_zobj = None
        self.c_gone_crypto = False
        self.s_gone_crypto = False
        self.CLIENT_TO_SERVER = 1
        self.SERVER_TO_CLIENT = 2

        # For the times when a record goes cross packet, buffer it up.
        self.c_buffer = ''
        self.s_buffer = ''

        self.VERSIONS = [ self.SSLv3_0,
                          self.TLSv1_0,
                          self.TLSv1_1,
                          self.TLSv1_2 ]

        self.CONTENT_TYPES = { self.CHANGE_CIPHER_SPEC: "CHANGE CIPHER SPEC",
                               self.ALERT: "ALERT",
                               self.HANDSHAKE: "HANDSHAKE",
                               self.APPLICATION_DATA: "APPLICATION DATA" }

        self.HANDSHAKE_TYPES = [ self.HELLO_REQUEST,
                                 self.CLIENT_HELLO,
                                 self.EXT_SESSIONTICKET,
                                 self.SERVER_HELLO,
                                 self.CERTIFICATE,
                                 self.SERVER_KEY_EXCHANGE,
                                 self.CERTIFICATE_REQUEST,
                                 self.SERVER_HELLO_DONE,
                                 self.CERTIFICATE_VERIFY,
                                 self.CLIENT_KEY_EXCHANGE,
                                 self.FINISHED ]

        # Handshake types we do parse.
        self.HANDSHAKE_PARSERS = { self.CLIENT_HELLO: self.__client_hello,
                                   self.EXT_SESSIONTICKET: self.__session_ticket,
                                   self.SERVER_HELLO: self.__server_hello,
                                   self.CERTIFICATE: self.__certificate,
                                   self.SERVER_KEY_EXCHANGE: self.__server_key_exchange,
                                   self.SERVER_HELLO_DONE: self.__server_hello_done,
                                   self.CLIENT_KEY_EXCHANGE: self.__client_key_exchange }

        self.compressions = [ self.DEFLATE_COMPRESSION, self.NULL_COMPRESSION ]

        # Supported cipher suites for decryption
        self.decryptable_cipher_suites = [ self.TLS_RSA_WITH_RC4_128_MD5,
                                           self.TLS_RSA_WITH_RC4_128_SHA,
                                           self.TLS_RSA_WITH_DES_CBC_SHA,
                                           self.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                                           self.TLS_RSA_WITH_AES_128_CBC_SHA,
                                           self.TLS_RSA_WITH_AES_256_CBC_SHA,
                                           self.TLS_RSA_WITH_AES_128_CBC_SHA256 ]

        # Negotiated cipher suite and compression algorithm
        self.cipher_suite = None
        self.compression = self.NULL_COMPRESSION

        # These are not needed to decrypt, but are collected for callbacks.
        self.cipher_suites = []
        self.compression_methods = []
        self.client_ticket = None
        # Extensions are stored in a list with keys "type" and "data".
        self.extensions = { 'server_extensions': [], 'client_extensions': [] }

    def __callback(self, callback, metadata):
        func = self.callbacks[callback]
        if func == None:
            return

        ret = func(metadata, self.callback_obj)
        # Do not need to handle OK for now in case we want to do
        # something with it later.
        if ret == self.STOP:
            raise sslimCallbackStop()
        elif ret == self.ERROR:
            raise sslimCallbackError()

    def parse(self, x, direction):
        # Not doing this causes unpack to complain about needing a str
        data = x

        if direction == self.CLIENT_TO_SERVER:
            if self.c_buffer:
                data = self.c_buffer + data
                self.c_buffer = ''
        else:
            if self.s_buffer:
                data = self.s_buffer + data
                self.s_buffer = ''

        if len(data) < self.hdr_size:
            if direction == self.CLIENT_TO_SERVER:
                self.c_buffer = data
            else:
                self.s_buffer = data
            return

        # Support SSLv2 (http://www.homeport.org/~adam/ssl.html)
        # http://www.mozilla.org/projects/security/pki/nss/ssl/
        # http://www.mozilla.org/projects/security/pki/nss/ssl/draft02.html
        # If the high order bit is set this is an SSLv2 message who'se
        # header is 2 bytes. XXX: Handle 3 byte headers!
        (byte0, byte1) = struct.unpack('>BB', data[:2])
        if byte0 & 0x80:
            data = data[2:]
            # Check for 2 byte SSL v2 header.
            if (((byte0 & 0x7F) << 8) | byte1) == len(data):
                self.__parse_sslv2(data, direction)
            else:
                raise sslimBadValue("Bad SSLv2 length", ((byte0 & 0x7F) << 8) | byte1)
        else:
            # XXX: Determine if it's SSLv2 or TLS1.0?
            self.__parse_tlsv1(data, direction)

    def __parse_sslv2(self, x, direction):
        # Not doing this causes unpack to complain about needing a str
        data = x

        # First byte is the message type.
        # XXX: Only support CLIENT HELLO for now
        mt = struct.unpack('>B', data[:1])[0]
        data = data[1:]
        if mt == self.CLIENT_HELLO:
            # Skip the version (2 bytes), grab the cipher spec length.
            data = data[2:]
            cipher_len = struct.unpack('>H', data[:2])[0]
            data = data[2:]
            # Skip the SID length (XXX: Don't skip this to support resuming)
            data = data[2:]
            self.c_sid = 0 # XXX: Grab the c_sid for real
            # Grab the challenge length.
            challenge_len = struct.unpack('>H', data[:2])[0]
            data = data[2:]
            # Skip the cipher specs, grab the challenge
            data = data[cipher_len:]
            fmt_str = "%is" % challenge_len
            # The docs call this a challenge... :(
            self.c_rnd = struct.unpack(fmt_str, data[:challenge_len])[0]
        else:
            raise sslimBadValue("Bad MT (SSLV2)", mt)

    def __parse_tlsv1(self, x, direction):
        # Not doing this causes unpack to complain about needing a str
        data = x

        while len(data) > self.hdr_size:
            (ct, self.ver, l) = struct.unpack('>BHH', data[:self.hdr_size])
            if (len(data) - self.hdr_size) < l:
                if direction == self.CLIENT_TO_SERVER:
                    self.c_buffer = data
                else:
                    self.s_buffer = data
                return
            data = data[self.hdr_size:]

            if direction == self.CLIENT_TO_SERVER and self.c_gone_crypto:
                self.__decrypt(data[:l], self.c_cryptobj, self.c_zobj, None)
                self.c_gone_crypto = False
                data = data[l:]
                continue
            elif direction == self.SERVER_TO_CLIENT and self.s_gone_crypto:
                self.__decrypt(data[:l], self.s_cryptobj, self.s_zobj, None)
                self.s_gone_crypto = False
                data = data[l:]
                continue

            self.__parse_record(ct, l, data[:l], direction)
            data = data[l:]

    def __parse_record(self, ct, l, data, direction):
        if ct not in self.CONTENT_TYPES:
            raise sslimBadValue("Bad ct value", ct)

        if self.ver not in self.VERSIONS:
            raise sslimBadValue("Bad ver value", self.ver)

        if ct == self.CHANGE_CIPHER_SPEC:
            # XXX: Change cipher spec messages are encrypted with the current
            # connection state. If a cipher spec is changed from NULL to
            # something this is fine. If it is changed from one cipher suite
            # to another we run the risk of screwing up here.
            # Don't do anything with the change cipher message, but we really
            # should!
            data = data[self.hs_change_cipher_size:]
            if direction == self.CLIENT_TO_SERVER:
                self.c_gone_crypto = True
            elif direction == self.SERVER_TO_CLIENT:
                self.s_gone_crypto = True

            metadata = { 'content_type': self.CHANGE_CIPHER_SPEC }
            self.__callback('change_cipher_spec', metadata)
        elif ct == self.ALERT:
            self.__alert(data[:l], direction)
        elif ct == self.HANDSHAKE:
            self.__handshake(data[:l])
        elif ct == self.APPLICATION_DATA:
            self.__application_data(data[:l], direction)

    def __client_hello(self, data, metadata):
        # CLIENT HELLO records have an inner version.
        version = struct.unpack('>H', data[:self.version_size])[0]
        metadata['handshake_version'] = version
        data = data[self.version_size:]

        (self.c_rnd, self.c_sid, sid_len) = self.__parse_rnd_and_sid(data)

        metadata['client_random'] = self.c_rnd
        metadata['client_sid'] = self.c_sid

        if self.ver != self.SSLv3_0:
            # Move past the random (32), sid_len (1) and SID (sid_len).
            data = data[32 + 1 + sid_len:]

            # We don't care what cipher suites, compression methods or
            # extensions for the client, at least for decryption. We
            # collect them for callbacks though.
            csl = struct.unpack('>H', data[:self.cipher_suite_size])[0]
            self.__cipher_suites(data[self.cipher_suite_size:self.cipher_suite_size + csl])
            metadata['cipher_suites'] = self.cipher_suites
            data = data[self.cipher_suite_size + csl:]

            cmpl = struct.unpack('>B', data[:self.compression_size])[0]
            self.__compression_methods(data[self.compression_size:self.compression_size + cmpl])
            metadata['compression_methods'] = self.compression_methods
            data = data[self.compression_size + cmpl:]

            extl = struct.unpack('>H', data[:self.extension_size])[0]
            self.__extensions(data[self.extension_size:self.extension_size + extl],
                              'client_extensions')
            # See if there is a client ticket extension.
            metadata['extensions'] = self.extensions['client_extensions']
            data = data[self.extension_size:self.extension_size + extl]

            # Specifically check for Session Tickets (RFC 5077).
            self.client_ticket = self.__find_extension(self.EXT_SESSIONTICKET_TYPE,
                                                       'client_extensions')

        # Call the client hello callback if we have one.
        self.__callback('client_hello', metadata)

    def __server_hello(self, data, metadata):
        # SERVER HELLO records have an inner version.
        version = struct.unpack('>H', data[:self.version_size])[0]
        metadata['handshake_version'] = version
        data = data[self.version_size:]
        (self.s_rnd, self.s_sid, sid_len) = self.__parse_rnd_and_sid(data)

        metadata['server_random'] = self.s_rnd
        metadata['server_sid'] = self.s_sid

        # Move past the random (32), sid_len (1) and SID (sid_len).
        data = data[32 + 1 + sid_len:]

        self.cipher_suite = struct.unpack('>H', data[:self.cipher_suite_size])[0]
        metadata['cipher_suite'] = self.cipher_suite
        data = data[self.cipher_suite_size:]

        if (self.cipher_suite not in self.decryptable_cipher_suites and
            self.keypair != None):
            raise sslimUnknownCipher("Can't decrypt cipher suite", self.cipher_suite)

        # Get details of the chosen cipher suite. Each cipher suite is
        # available as a method of the sslim_cipher_suites class. The method
        # names are all the 2 bytes for the cipher suite value preceeded by an
        # underscore (_0035, _002F, etc).
        #
        # See sslim_ciphers for details.
        cs = "_%04X" % self.cipher_suite
        if not hasattr(sslim_cipher_suites, cs):
            message = """Unknown cipher suite. This is likely just missing an entry in
sslim_ciphers.py, please drop me a mail (wxs@atarininja.org) with
this message. Cipher suite"""
            raise sslimUnknownCipher(message, self.cipher_suite)

        method = getattr(sslim_cipher_suites, cs)
        cs = method()
        self.cipher_suite = cs.details
        metadata['cipher_suite_details'] = self.cipher_suite

        self.compression = struct.unpack('>B', data[:self.compression_size])[0]
        metadata['compression'] = self.compression
        data = data[self.compression_size:]
        if (self.compression not in self.compressions and
            self.keypair != None):
            raise sslimUnknownCompression("Unknown compression", self.compression)

        # The only compression allowed in the RFCs is deflate. If that
        # ever changes we need to pay attention to the value here.
        if (self.compression != self.NULL_COMPRESSION and
            self.keypair != None):
            self.c_zobj = zlib.decompressobj()
            self.s_zobj = zlib.decompressobj()

        if self.ver != self.SSLv3_0:
            # Go looking for extensions.
            extl = struct.unpack('>H', data[:self.extension_size])[0]
            self.__extensions(data[self.extension_size:self.extension_size + extl],
                              'server_extensions')
            # See if there is a client ticket extension.
            metadata['extensions'] = self.extensions['server_extensions']
            data = data[self.extension_size:self.extension_size + extl]
            # Specifically for Session Tickets (RFC 5077).
            self.server_ticket = self.__find_extension(self.EXT_SESSIONTICKET_TYPE,
                                                       'server_extensions')

        # Only care about resuming if we have a keypair.
        if self.keypair != None:
            if ((self.s_sid != 0 and self.c_sid == self.s_sid) or
                self.client_ticket):
                # Session resuming.
                # First check the sid, then check the ticket.
                self.ms = self.check_sid(self.s_sid)
                if not self.ms:
                    self.ms = self.check_sid(self.client_ticket)
                    if not self.ms:
                        raise sslimBadValue("Bad resume value")

                km = self.__key_material(self.cipher_suite['km_len'],
                                         self.s_rnd + self.c_rnd,
                                         self.ms)
                keys = self.__split_key_material(km)
                self.cipher_suite['keys'] = keys
                if self.cipher_suite['cipher'] == 'stream':
                    self.c_cryptobj = RC4.RC4(keys['client_enc_key'])
                    self.s_cryptobj = RC4.RC4(keys['server_enc_key'])
                elif self.cipher_suite['cipher'] == 'block':
                    self.c_cryptobj = EVP.Cipher(self.cipher_suite['algo'],
                                                 keys['client_enc_key'],
                                                 keys['client_iv'],
                                                 0,
                                                 padding=0)
                    self.s_cryptobj = EVP.Cipher(self.cipher_suite['algo'],
                                                 keys['server_enc_key'],
                                                 keys['server_iv'],
                                                 0,
                                                 padding=0)

        self.__callback('server_hello', metadata)

    def __certificate(self, data, metadata):
        # CERTIFICATE records _DO NOT_ have an inner version.
        # First three bytes are the length of the certificates.
        if len(data) < 3:
            raise sslimBadValue("Certificate length too short")

        (b0, b1, b2) = struct.unpack('>BBB', data[:3])
        total_len = (b0 << 16) + (b1 << 8) + b2
        data = data[3:]

        # Make sure total length of certificates matches what we have left.
        if len(data) != total_len:
            raise sslimBadValue("Bad certificate length")

        metadata['certificates'] = []

        while len(data) <= total_len:
            # Each certificate is preceeded by a 3 byte length.
            if len(data) < 3:
                break

            (b0, b1, b2) = struct.unpack('>BBB', data[:3])
            cert_len = (b0 << 16) + (b1 << 8) + b2
            data = data[3:]

            # Make sure we have the entire cert.
            if len(data) < cert_len:
                break

            metadata['certificates'].append(data[:cert_len])
            data = data[cert_len:]

        self.__callback('certificate', metadata)

    def __server_hello_done(self, data, metadata):
        self.__callback('server_hello_done', metadata)

    def __session_ticket(self, data, metadata):
        lifetime_hint = struct.unpack('>I', data[:4])[0]
        data = data[4:]

        metadata['lifetime_hint'] = lifetime_hint

        # The next two bytes are the length of the session ticket.
        ticket_len = struct.unpack('>H', data[:2])[0]
        data = data[2:]
        if ticket_len != len(data):
            raise sslimBadValue("Bad ticket length", ticket_len)
        ticket = struct.unpack('%ss' % ticket_len, data[:ticket_len])[0]

        metadata['session_ticket'] = ticket
        self.store_ms(ticket, self.ms)

        self.__callback('session_ticket', metadata)

    def __rsa_key_exchange(self, data, metadata):
        if self.check_sid(self.s_sid):
            # XXX: The fact that the server session ID is in
            # the dictionary already is a really bad thing.
            # There should be no client key exchange message
            # if the client and server agree to resume.
            raise sslimBadValue("SID found with client key exchange")

        # XXX: The size of this is dependent upon the cipher suite chosen!
        # Section 7.4.7.1 of RFC5246 details what these bytes mean for
        # RSA authentication!
        if self.ver == self.SSLv3_0:
            if self.cipher_suite['key_exch'] != 'RSA':
                raise sslimUnknownCipher("SSLv3 not RSA key exchange")
            pms = data
        else:
            # The first two bytes are the length of the key.
            pms_len = int(struct.unpack('>H', data[:self.hs_pms_len_size])[0])
            data = data[self.hs_pms_len_size:]
            pms = struct.unpack('%ss' % pms_len, data[:pms_len])[0]

        metadata['pre_master_secret'] = pms

        if self.keypair:
            try:
                cpms = self.keypair.private_decrypt(pms, RSA.sslv23_padding)
            except Exception as e:
                raise sslimCryptoError(str(e))

            seed = self.c_rnd + self.s_rnd
            self.ms = self.__PRF(cpms, "master secret", seed, 48)[:48]

            metadata['master_secret'] = self.ms

            # Store the master secret in the sids dictionary
            self.store_ms(self.s_sid, self.ms)

            # From the master secret you generate the key material
            seed = self.s_rnd + self.c_rnd
            km = self.__key_material(self.cipher_suite['km_len'],
                                     self.s_rnd + self.c_rnd,
                                     self.ms)
            keys = self.__split_key_material(km)
            metadata['keys'] = keys
            self.cipher_suite['keys'] = keys
            if self.cipher_suite['cipher'] == 'stream':
                self.c_cryptobj = RC4.RC4(keys['client_enc_key'])
                self.s_cryptobj = RC4.RC4(keys['server_enc_key'])
            elif self.cipher_suite['cipher'] == 'block':
                self.c_cryptobj = EVP.Cipher(self.cipher_suite['algo'],
                                             keys['client_enc_key'],
                                             keys['client_iv'],
                                             0,
                                             padding=0)
                self.s_cryptobj = EVP.Cipher(self.cipher_suite['algo'],
                                             keys['server_enc_key'],
                                             keys['server_iv'],
                                             0,
                                             padding=0)
    def __dh_key_exchange(self, data, metadata):
        # First byte is the length of the parameters.
        if len(data) == 0:
            return
        length = struct.unpack('>B', data[:1])[0]
        data = data[1:]

        # Make sure we have all the rest of the data.
        if len(data) != length:
            return

        metadata['dh_params'] = data

    def __client_key_exchange(self, data, metadata):
        if self.cipher_suite['key_exch'] == 'RSA':
            self.__rsa_key_exchange(data, metadata)
        elif self.cipher_suite['key_exch'] in ['ECDHE', 'ECDH']:
            self.__dh_key_exchange(data, metadata)

        self.__callback('client_key_exchange', metadata)

    def __server_key_exchange(self, data, metadata):
        # XXX: Parse out the information from the key but that's more
        # in depth than I care to get into right now.
        metadata['server_key'] = data
        self.__callback('server_key_exchange', metadata)

    def __handshake(self, data):
        if len(data) < self.hs_type_size:
            return

        # The first byte is the hand-shake type, last three are the length.
        hst_length = struct.unpack('>I', data[:self.hs_type_size])[0]

        hst = (hst_length & 0xFF000000) >> 24
        length = hst_length & 0x00FFFFFF

        data = data[self.hs_type_size:]

        # Make sure we have the rest of the data
        if len(data) < length:
            return

        if hst not in self.HANDSHAKE_TYPES:
            raise sslimBadValue("Bad hst value", hst)

        metadata = {}
        metadata['content_type'] = self.HANDSHAKE
        metadata['handshake_type'] = hst
        metadata['length'] = length
        metadata['version'] = self.ver

        if hst in self.HANDSHAKE_PARSERS:
            func = self.HANDSHAKE_PARSERS[hst]
            func(data, metadata)

    def __split_key_material(self, km):
        key_size = self.cipher_suite['key_size']
        mac_size = self.cipher_suite['mac_size']

        keys = { 'client_mac_key': km[:mac_size],
                 'server_mac_key': km[mac_size:mac_size * 2],
                 'client_enc_key': km[mac_size * 2:(mac_size * 2) + key_size],
                 'server_enc_key': km[(mac_size * 2) + key_size:(mac_size * 2) + (key_size * 2)] }

        # Provide the IVs if needed by the cipher suite
        if 'block_size' in self.cipher_suite:
            block_size = self.cipher_suite['block_size']
            keys['client_iv'] = km[(mac_size * 2) + (key_size * 2):(mac_size * 2) + (key_size * 2) + block_size]
            keys['server_iv'] = km[(mac_size * 2) + (key_size * 2) + block_size:(mac_size * 2) + (key_size * 2) + (block_size * 2)]

        return keys

    def __key_material(self, km_len, seed, ms):
        if self.ver == self.SSLv3_0:
            alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            i = 0
            km = ''
            sha_md = EVP.MessageDigest('sha1')
            md5_md = EVP.MessageDigest('md5')

            while len(km) < km_len:
                sha_md.update((alpha[i] * (i + 1)) + ms + seed)
                md5_md.update(ms + sha_md.digest())
                km += md5_md.digest()
                # Reset the message digests and increment the index.
                sha_md.__init__('sha1')
                md5_md.__init__('md5')
                i = (i + 1) % 26
            return km[:km_len]
        else:
            return self.__PRF(ms, "key expansion", seed, km_len)[:km_len]

    def __A(self, num, secret, seed, alg):
        if num == 0:
            return seed
        else:
            return EVP.hmac(secret, self.__A(num - 1, secret, seed, alg), algo=alg)

    # TLS1.0 defines the PRF as splitting the seed, hashing the first half
    # with MD5 and hashing th second half with SHA1, then XOR the two
    # halves to produce the final output.
    # TLS1.2 defines a different PRF - just use SHA256, but also states
    # a cipher suite can define it's own PRF if desired.
    def __PRF(self, secret, label, seed, size):
        if self.ver == self.SSLv3_0:
            alpha = 'ABC'
            i = 0
            out = ''
            sha_md = EVP.MessageDigest('sha1')
            md5_md = EVP.MessageDigest('md5')

            for i in range(len(alpha)):
                sha_md.update((alpha[i] * (i + 1)) + secret + seed)
                md5_md.update(secret + sha_md.digest())
                out += md5_md.digest()
                # Reset the message digests and increment the index.
                sha_md.__init__('sha1')
                md5_md.__init__('md5')
            return out
        elif self.ver == self.TLSv1_0 or self.ver == self.TLSv1_1:
            # Split the secret into two halves.
            ls1 = ls2 = int(math.ceil(len(secret) / 2))
            s1 = secret[:ls1]
            s2 = secret[ls2:]

            label_seed = label + seed

            # s1 is the MD5 half
            ret1 = self.__P_hash(s1, label_seed, size, 'md5')

            # s2 is the SHA1 half
            ret2 = self.__P_hash(s2, label_seed, size, 'sha1')

            # XOR the two halves to get the master secret
            return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(ret1, ret2))
        elif self.ver == self.TLSv1_2:
            label_seed = label + seed
            return self.__P_hash(secret, label_seed, size, 'sha256')

    def __P_hash(self, secret, seed, size, alg):
        ret = ''
        x = 1
        while len(ret) < size:
            ret += EVP.hmac(secret, self.__A(x, secret, seed, alg) + seed, algo=alg)
            x += 1
        return ret

    def __cipher_suites(self, data):
        # Cipher suites are two bytes each. Make sure we have an even number
        # of bytes.
        if len(data) == 0 or len(data) % 2 != 0:
            return

        for x in range(0, len(data), 2):
            self.cipher_suites.append(struct.unpack(">H", data[x:x + 2])[0])

    def __compression_methods(self, data):
        # Compression methods are one byte each.
        if len(data) == 0:
            return

        self.compression_methods = [struct.unpack('>B', data[x])[0] for x in range(len(data))]

    def __extensions(self, data, key):
        # Extensions are two bytes for type and two bytes for length.
        while len(data) >= 4:
            # Extensions are two bytes for type, two bytes for length and
            # then data. There must be at least 4 bytes.
            if len(data) < 4:
                return

            (ext_type, ext_len) = struct.unpack('>HH', data[:4])
            ext = { 'type': ext_type }
            if ext_len != 0:
                ext['data'] = data[4:4 + ext_len]
            else:
                ext['data'] = ''
            self.extensions[key].append(ext)
            data = data[4 + ext_len:]

    def __find_extension(self, extension, key):
        for ext in self.extensions[key]:
            if ext['type'] == extension:
                return ext['data']

    def __parse_rnd_and_sid(self, data):
        # Grab the random bytes
        rnd = struct.unpack('32s', data[:32])[0]
        data = data[32:]
        # Grab the session ID
        sid_len = struct.unpack('>B', data[:self.sid_len_size])[0]
        if sid_len != 0:
            data = data[1:]
            fmt_str = "%is" % sid_len
            sid = struct.unpack(fmt_str, data[:sid_len])[0]
        else:
            sid = 0

        return (rnd, sid, sid_len)

    # This is used as a callback to handle the alert record after
    # it has been decrypted. The decryption is done in __decrypt
    # which is called from __alert.
    def __parse_clear_alert(self, clear, callback_obj):
        pass

    # Assume the alert is encrypted.
    def __alert(self, data, direction):
        if direction == self.CLIENT_TO_SERVER:
            self.__decrypt(data,
                           self.c_cryptobj,
                           self.c_zobj,
                           self.__parse_clear_alert)
        else:
            self.__decrypt(data,
                           self.s_cryptobj,
                           self.s_zobj,
                           self.__parse_clear_alert)

    def __handle_encrypted(self, data, callback_name, direction):
        metadata = { 'content_type': self.APPLICATION_DATA,
                     'data': data,
                     'direction': direction }
        self.__callback(callback_name, metadata)

    def __application_data(self, data, direction):
        if direction == self.CLIENT_TO_SERVER:
            # If we are not decrypting use the encrypted data callback.
            if self.keypair == None:
                self.__handle_encrypted(data, 'request_encrypted', direction)
            else:
                self.__decrypt(data,
                               self.c_cryptobj,
                               self.c_zobj,
                               self.req_callback)
        else:
            # If we are not decrypting use the encrypted data callback.
            if self.keypair == None:
                self.__handle_encrypted(data, 'response_encrypted', direction)
            else:
                self.__decrypt(data,
                               self.s_cryptobj,
                               self.s_zobj,
                               self.res_callback)

    def __decrypt(self, data, cryptobj, zobj, callback):
        # If we have no keypair return early.
        if self.keypair == None:
            return

        clear = cryptobj.update(data)
        # CBC mode ciphers need to throw away the first block when used
        # with TLS1.1 and newer. See section 6.2.3.2 of RFC4346.
        if self.ver >= self.TLSv1_1:
            if (self.cipher_suite['cipher'] == 'block' and
                self.cipher_suite['algo'].endswith('cbc')):
                clear = clear[self.cipher_suite['block_size']:]
        if self.compression == self.DEFLATE_COMPRESSION:
            # Do not strip the MAC and padding because that
            # is done in the decompression step.
            clear = self.__decompress(clear, zobj)
        else:
            # Strip the MAC and padding.
            if 'block_size' in self.cipher_suite:
                pad = ord(clear[-1:]) + 1
            else:
                pad = 0
            clear = clear[:-(self.cipher_suite['mac_size'] + pad)]

        if len(clear) > 0 and callback != None:
            ret = callback(clear, self.callback_obj)
            # Do not need to handle OK for now in case we want to do something
            # with it later.
            if ret == self.STOP:
                raise sslimCallbackStop()
            elif ret == self.ERROR:
                raise sslimCallbackError()

    def __decompress(self, data, zobj):
        # Strip off the padding. For some reason M2Crypto is stripping off
        # more than half the MAC too. So do it manually.
        # The last byte is always the padding length.
        if 'block_size' in self.cipher_suite:
            pad = ord(data[-1:]) + 1
        else:
            pad = 0
        return zobj.decompress(data[:-(self.cipher_suite['mac_size'] + pad)])
