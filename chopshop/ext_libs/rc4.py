# Copyright (c) 2014 Wesley Shields. All Rights reserved.
#                                                                               # Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#                                                                               # THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS       # OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

class rc4:
    def __init__(self, key):
        self.x = 0
        self.y = 0
        self.b = range(256)

        for i in range(256):
            k = key[i % len(key)]
            self.x = (self.x + self.b[i] + ord(k)) % 256
            self.b[i], self.b[self.x] = self.b[self.x], self.b[i]
        self.x = 0
        return

    def crypt(self, data):
        ret = '' 
        for c in data:
            self.x = (self.x + 1) % 256
            self.y = (self.y + self.b[self.x]) % 256
            self.b[self.x], self.b[self.y] = self.b[self.y], self.b[self.x]
            i = self.b[(self.b[self.x] + self.b[self.y]) % 256]
            ret += chr(ord(c) ^ i)
        return ret
