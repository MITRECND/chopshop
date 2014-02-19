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

import struct
import sys
from c2utils import unpack_from

class lznt1Error(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

def _dCompressBlock(x):
    size = len(x)
    u = ''
    while len(x):

        p = ord(x[0])
        ##print "BLOCK START ", hex(size - len(x)),hex(p),len(u)

        if p == 0: # These are symbol are tokens
            u += x[1:9]
            x = x[9:]
        else:  # There is a phrase token
            idx = 8
            x = x[1:]
            while idx and len(x):
                ustart = len(u)
                #print u[-250:]
                #print "======================================="
                #print "OFFSET ",hex(size - len(x)),ustart,p
                if not (p & 1):
                    u += x[0]
                    x = x[1:]
                else:
                    pt = unpack_from('H', x)[0]
                    pt = pt & 0xffff
                    #print "PT = %x" % pt
                    i = (len(u)-1)  # Current Pos
                    l_mask = 0xfff
                    p_shift = 12
                    while i >= 0x10:
                        ##print i,l_mask,p_shift
                        l_mask >>= 1
                        p_shift -= 1
                        i >>= 1
                    #print "LMASK %x SHIFT %x" % (l_mask,p_shift)

                    length = (pt & l_mask) + 3
                    bp = (pt  >> p_shift) + 1
                    #print "\n\n\n"
                    #print "BackPtr = %d Len = %d" % (bp,length)

                    if length >= bp:
                        tmp = u[-bp:]
                        while length >= len(tmp):
                            u += tmp
                            length -= len(tmp)
                        u += tmp[:length]
                    else:
                        insert = u[-bp : -bp + length]
                        #print "INSERT <%s>,%d,%d" % (insert,-bp,-bp+length)
                        u = u + insert

                    x = x[2:]
                p >>= 1
                idx -= 1
    return u

def dCompressBuf(blob):
    good = True
    unc = ''
    while good:
        try:
            hdr = blob[0:2]
            blob = blob[2:]

            length = struct.unpack('H', hdr)[0]
            length &= 0xfff
            length += 1
            if length > len(blob):
                raise lznt1Error("invalid block len")
                good = False
            else:
                y = blob[:length]
                blob = blob[length:]
                unc += _dCompressBlock(y)
        except:
            good = False

    return unc
