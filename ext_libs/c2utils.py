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
import binascii
from datetime import datetime
import time
import string
import math

#### UTILITIES #########################

def parse_addr(tcp):
    if tcp.server.count_new > 0:
        return tcp.addr
    elif tcp.client.count_new > 0:
        ((src, sport), (dst, dport)) = tcp.addr
        return ((dst, dport), (src, sport))

def winsizeize(hsize, lsize):
    return (hsize * (0xFFFFFFFF + 1)) + lsize

def pad_string(str, align=8, char=' '):
    new_str = str
    pad_chars = align - (len(str) % align)

    if pad_chars != 0:
        for x in range(pad_chars):
            new_str += char

    return new_str

def reflect(s):
    res = ''
    for char in s:
        if char in ['.', '/', '\\', '-', ' ', ':', ';']:
            res += char
        elif char in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']:
            res += char
        elif char.isupper():
            res += chr(ord('Z') - ord(char) + ord('A'))
        else:
            res += chr(ord('z') - ord(char) + ord('a'))
    return res


def entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

def one_byte_xor(data, key):
    return "".join([chr(ord(b) ^ key) for b in data])

def multibyte_xor(data, key):
    output = ""
    key_bytes = len(key) / 2
    for i, char in enumerate(data):
        byte = ord(char)
        key_offset = i % key_bytes * 2
        k = key[key_offset:key_offset + 2]
        #print "k = %s" % k
        key_byte = int(k, 16)
        #print "key_byte = %d, byte = %d" % (key_byte, byte)
        output += chr(byte ^ key_byte)
    return output

def sanitize_filename(inf, default='NONAME'):
    fname = ""
    bad = [ '/', '\\', ':', '~', '*' ]
    for c in inf:
        if c in bad:
            fname += '_'
        else:
            fname += c
    if not fname:
        fname = default
    return fname

def replace_nonascii(line, repl):
    clean_line = ""
    for c in line:
        if c in string.printable:
            clean_line += c
        else:
            clean_line += repl
    return clean_line

def strip_nonascii(line):
    clean_line = ""
    for c in line:
        if c in string.printable:
            clean_line += c
        else:
            continue
    return clean_line

def unpack_from(fmt, buf, offset=0):
    """Unpack binary data, using struct.unpack(...)"""
    slice = buffer(buf, offset, struct.calcsize(fmt))
    return struct.unpack(fmt, slice)

def b2a_printable(s):
    """Given a string of binary data, return a copy of that string
    with each non-printable ASCII character converted to a single
    period.
    """
    result = ""
    for c in map(ord, s):
        if c >= 0x20 and c <= 0x7e:
            result = result + chr(c)
        else:
            result = result + '.'
    return result

def packet_isodate(t):
    return packet_time(t, date=True, isodate=True)

def packet_timedate(t):
    return packet_time(t, date=True)

def packet_gmttimedate(t):
    return packet_time(t, date=True, utc=True)

def packet_gmttime(t):
    return packet_time(t, utc=True)

def packet_time(t, date=False, utc=False, isodate=False):
    """Given a unixtime (seconds since epoch) value, return a
    human-readable string describing that time.  if DATE is
    True, then also include the year, month, day, and timezone.
    If UTC is true, return the time in UTC instead of local
    """
    if utc:
        fmt = "%Y-%m-%d %H:%M:%S +0000"
        ts = time.gmtime(t)
    else:
        fmt = "%Y-%m-%d %H:%M:%S %z"
        ts = time.localtime(t)
    if date:
        if isodate:
            return datetime.fromtimestamp(time.mktime(ts))
        else:
            return time.strftime(fmt, ts).rstrip()
    return "%02d:%02d:%02d" % (ts[3], ts[4], ts[5])

def hexdump(data, tabs=0, spaces=0, show_offset=True):
    """Given a buffer of binary data, return a string with a hexdump
    of that data.  Optionally, indent each line by the given
    number of tabs and spaces.  Also, optionally, do not show the offset.
    """
    result = ''
    for i in range(0, len(data), 16):
        hexstring = ' '.join([binascii.hexlify(a) for a in data[i:i+16]])

        asciistring = b2a_printable(data[i:i+16])
        if show_offset:
                result += "%s%s%07x: %-48s |%-16s|\n" % (tabs * '\t', spaces * ' ', i, hexstring, asciistring)
        else:
            result += "%s%s%-48s |%-16s|\n" % (tabs * '\t', spaces * ' ', hexstring, asciistring)
    return result
