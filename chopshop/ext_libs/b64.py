# Base64 utilities

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

import base64
import string

def b64decode(s, alpha='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', padbyte='=', strict=True):
    '''
    Decode the given string with the given alphabet.
    If strict==False, tries modifying the input string in the following order:
    1. add pad byte(s) to end
    2. remove non-alphabet bytes at end
    3. remove 1-4 bytes at end (to make strlen % 4 == 0)
    4. remove non-alphabet bytes at beginning
    '''
    b64_alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    b64_pad = '='
    over = len(s) % 4
    if not strict:
        if over == 1:
            # three-character padding at end is worthless/illegal, so just remove one char
            s = s[:-1]
        else:
            # try padding end
            s += padbyte * (4 - over)
    if alpha != b64_alpha or padbyte != b64_pad:
        # translate, if needed
        translator = string.maketrans(alpha+padbyte,b64_alpha+b64_pad)
        #print "DEBUG: before:", s
        s = s.translate(translator)
        #print "DEBUG: after:", s
    if strict:
        return base64.b64decode(s)
    # not strict mode, so try a few things...
    try:
        return base64.b64decode(s)
    except TypeError:
        pass
    # check for illegal bytes at end and remove them
    i = 1
    c = s[-i]
    while c not in b64_alpha:
        i+=1
        c = s[-i]
    if i > 1:
        # illegal bytes found, remove 'em!
        i -= 1
        s = s[:-i]
        # add padding
        if len(s) % 4 != 0:
            s += b64_pad * (4 - (len(s) % 4))
        try:
            return base64.b64decode(s)
        except TypeError:
            pass
    else:
        # try removing the "over" bytes
        try:
            return base64.b64decode(s[:-4])
        except TypeError:
            pass
    # try removing bad chars from start of string
    i = 0
    c = s[i]
    while c not in b64_alpha:
        i+=1
        c = s[i]
    if i > 1:
        # illegal bytes found, remove 'em!
        s = s[i:]
        # add padding
        if len(s) % 4 != 0:
            s += b64_pad * (4 - (len(s) % 4))
        return base64.b64decode(s)
