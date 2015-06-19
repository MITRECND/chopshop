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

# This class represents each of the available cipher suites supported by
# sslim. Each supported cipher suite is represented via a classmethod
# which returns an instantiated object with the various details about the
# cipher suite filled in. These details are used for decryption (if supported)
# and also for understanding the various parts of an SSL handshake which rely
# upon them (key exchange).
class sslim_cipher_suites(object):
    def __init__(self, details):
        self.details = details

    # key_size, mac_size and block_size are in bytes!
    # For the ciphers that are not supported for decryption those values
    # aren't used, but are kept here for completeness.

    @classmethod
    def _0004(self):
        details = { 'name': 'TLS_RSA_WITH_RC4_128_MD5',
                    'key_exch': 'RSA',
                    'cipher': 'stream',
                    'key_size': 16,
                    'mac': 'MD5',
                    'mac_size': 16,
                    'km_len': 64 }
        return self(details)

    @classmethod
    def _0005(self):
        details = { 'name': 'TLS_RSA_WITH_RC4_128_SHA',
                    'key_exch': 'RSA',
                    'cipher': 'stream',
                    'key_size': 16,
                    'mac': 'SHA',
                    'mac_size': 20,
                    'km_len': 72 }
        return self(details)

    @classmethod
    def _0009(self):
        details = { 'name': 'TLS_RSA_WITH_DES_CBC_SHA',
                    'key_exch': 'RSA',
                    'algo': 'des_cbc',
                    'cipher': 'block',
                    'key_size': 8,
                    'mac': 'SHA',
                    'mac_size': 20,
                    'km_len': 104,
                    'block_size': 8 }
        return self(details)

    @classmethod
    def _000A(self):
        details = { 'name': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                    'key_exch': 'RSA',
                    'algo': 'des_ede3_cbc',
                    'cipher': 'block',
                    'key_size': 24,
                    'mac': 'SHA',
                    'mac_size': 20,
                    'km_len': 104,
                    'block_size': 8 }
        return self(details)

    @classmethod
    def _002F(self):
        details = { 'name': 'TLS_RSA_WITH_AES_128_CBC_SHA',
                    'key_exch': 'RSA',
                    'algo': 'aes_128_cbc',
                    'cipher': 'block',
                    'key_size': 16,
                    'mac': 'SHA',
                    'mac_size': 20,
                    'km_len': 104,
                    'block_size': 16 }
        return self(details)

    @classmethod
    def _0035(self):
        details = { 'name': 'TLS_RSA_WITH_AES_256_CBC_SHA',
                    'key_exch': 'RSA',
                    'algo': 'aes_256_cbc',
                    'cipher': 'block',
                    'key_size': 32,
                    'mac': 'SHA',
                    'mac_size': 20,
                    'km_len': 136,
                    'block_size': 16 }
        return self(details)

    @classmethod
    def _0039(self):
        details = { 'name': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
                    'key_exch': 'DHE',
                    'algo': 'aes_256_cbc',
                    'cipher': 'block',
                    'key_size': 32,
                    'mac': 'SHA',
                    'mac_size': 20,
                    'km_len': 136,
                    'block_size': 16 }
        return self(details)

    @classmethod
    def _003C(self):
        details = { 'name': 'TLS_RSA_WITH_AES_128_CBC_SHA256',
                    'key_exch': 'RSA',
                    'algo': 'aes_128_cbc',
                    'cipher': 'block',
                    'key_size': 16,
                    'mac': 'SHA',
                    'mac_size': 32,
                    'km_len': 104,
                    'block_size': 16 }
        return self(details)

    @classmethod
    def _C02F(self):
        details = { 'name': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                    'key_exch': 'ECDHE',
                    'algo': 'aes_128_gcm',
                    'cipher': 'block',
                    'key_size': 16,
                    'mac': 'SHA',
                    'mac_size': 32,
                    'km_len': 104,
                    'block_size': 16 }
        return self(details)
