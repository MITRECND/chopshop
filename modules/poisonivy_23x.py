# Copyright (c) 2013 FireEye, Inc. All rights reserved.
# Copyright (c) 2013 The MITRE Corporation. All rights reserved.
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

import sys
from struct import *
import re
import os
from optparse import OptionParser
import camcrypt
import binascii
import string
import socket
import subprocess
from c2utils import *
import lznt1

moduleName="poisonivy_23x"

def portlist(data):
    statuses = {2 : 'LISTENING', 5 : 'ESTABLISHED'}
    chop.tsprnt("*** Active Ports Listing Sent ***")
    #big endian short, UDP == 1, TCP == 0
    #if UDP, carry on but skip remote pair
    #4 bytes - local IP
    #big endian short local port
    #2 null bytes
    # remote IP
    # remort port
    #2 null bytes
    #1 byte status
    # little endian int PID
    #1 byte proc name length
    chop.prnt("Protocol\tLocal IP\tLocal Port\tRemote IP\tRemote Port\tStatus\tPID\tProc Name")
    while data != "":
        if unpack(">H", data[:2])[0] == 1:
            proto = "UDP"
        else:
            proto = "TCP"
        data = data[2:]
        localip = socket.inet_ntoa(data[:4])
        data = data[4:]
        localport = unpack(">H",data[:2])[0]
        data = data[4:]
        if proto == "TCP":
            remoteip = socket.inet_ntoa(data[:4])
            data = data[4:]
            remoteport = unpack(">H",data[:2])[0]
            data = data[4:]
            status = ord(data[0])
            data = data[1:]
            if remoteip == "0.0.0.0":
                remoteport = "*"
                remoteip = "*"
        (pid, proclen) = unpack("<IB",data[:5])[0]
        data = data[5:]
        procname = data[:proclen]
        procname = string.strip(procname, "\x00")
        data = data[proclen:]
        if proto == "TCP":
            chop.prnt("%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s" % (proto,
                       localip,
                       localport,
                       remoteip,
                       remoteport,
                       statuses.get(status, "UNKNOWN: 0x%x" % status),
                       pid,
                       procname))
        else:
            chop.prnt("%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s" % (proto,
                       localip,
                       localport,
                       "*",
                       "*",
                       "*",
                       pid,
                       procname))

def dirEnt(data):
    # Print either the directory name (if) or it's contents (else)
    if data[:10] == '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01':
        chop.prnt("%s" % data[10:])
    else:
        l =ord(data[0])
        data = data[1:]
        if data[0] == '\x00':
            return

        chop.prnt("\t%s"  % (data[:l]))
        data = data[l:]
        #l =ord(data[0])

        data = data[24:]

        if len(data):
            dirEnt(data)
    return

def heartbeat(data):
    return

def shell(data):
    chop.tsprnt("*** Shell Session ***")
    chop.prnt(data)
    return

def dirlist(data):
    chop.tsprnt("*** Directory Listing Sent ***")
    if module_data['savelistings']:
        filename = "PI-directory-listing-%d.txt" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    dirEnt(data)
    return

def hostinfo(data):
    chop.tsprnt("*** Host Information ***")
    str_regex = r"^([\w\x20\t\\\:\-\.\&\%\$\#\@\!\(\)\*]+)$"
    profilegroup = ""
    #grab profile id string, not in fixed position
    for i in range(len(data)):
        if ord(data[i]) == 0:
            continue
        match = re.match(str_regex,data[i+1:i+1+ord(data[i])])
        if match is not None:
            profileid = match.group(1)
            #move past profile string
            i = i+1+ord(data[i])
            break

    #check for profile group string
    if ord(data[i]) != 0:
        groupend = i + 1 + ord(data[i])
        profilegroup = data[i+1:groupend]
        i = groupend
    else:
        i += 1

    ip = socket.inet_ntoa(data[i:i+4])
    i += 4
    hostname = data[i+1:i+1+ord(data[i])]
    i = i+1+ord(data[i])
    username = data[i+1:i+1+ord(data[i])]
    i = i+1+ord(data[i])
    producttype = ord(data[i])
    i += 5
    (majorver, minorver, build) = unpack("<III",data[i:i+12])
    i += 16 # Not sure why skipping another 4 bytes
    csd = ""
    if (ord(data[i]) >= 32 and ord(data[i]) <= 126):
        for i in range(i, len(data[i:])):
            if ord(data[i]) == 0:
                break
            csd += data[i]

    if majorver == 5 and minorver == 0:
        osver = "Windows 2000"
    elif majorver == 5 and minorver == 1:
        osver = "Windows XP"
    elif majorver == 5 and minorver == 2 and build == 2600:
        osver = "Windows XP Professional x64 Edition"
    elif majorver == 5 and minorver == 2:
        osver = "Windows Server 2003"
    elif majorver == 6 and minorver == 0 and build == 6000:
        osver = "Windows Vista"
    elif majorver == 6 and minorver == 0:
        osver = "Windows Server 2008"
    elif majorver == 6 and minorver == 1 and build == 7600:
        osver = "Windows 7"
    elif majorver == 6 and minorver == 1:
        osver = "Windows Server 2008 R2"
    elif majorver == 6 and minorver == 2 and build == 9200:
        osver = "Windows 8"
    elif majorver == 6 and minorver == 2:
        osver = "Windows Server 2012"

    chop.prnt("PI profile ID: %s" % profileid)
    if profilegroup != "":
        chop.prnt("PI profile group: %s" % profilegroup)
    chop.prnt("IP address: %s" % ip)
    chop.prnt("Hostname: %s" % hostname)
    chop.prnt("Windows User: %s" % username)
    chop.prnt("Windows Version: %s" % osver)
    chop.prnt("Windows Build: %d" % build)
    if csd != "":
        chop.prnt("Service Pack: %s" % csd)

    return

def reglist(data):
    chop.tsprnt("*** Registry Listing Sent ***")
    if module_data['savelistings']:
        filename = "PI-registry-listing-%d.txt" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def servicelist(data):
    chop.tsprnt("*** Service Listing Sent ***")
    if module_data['savelistings']:
        filename = "PI-service-listing-%d.txt" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def proclist(data):
    chop.tsprnt("*** Process Listing Sent ***")
    if module_data['savelistings']:
        filename = "PI-process-listing-%d.txt" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def devicelist(data):
    chop.tsprnt("*** Device Listing Sent ***")
    if module_data['savelistings']:
        filename = "PI-device-listing-%d.txt" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def windowlist(data):
    chop.tsprnt("*** Window Listing Sent ***")
    if module_data['savelistings']:
        filename = "PI-window-listing-%d.txt" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def installedlist(data):
    chop.tsprnt("*** Installed Application Listing Sent ***")
    if module_data['savelistings']:
        filename = "PI-installed-listing-%d.txt" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def passwordlist(data):
    if len(data) == 0:
        chop.tsprnt("*** Password Listing Request - Nothing Found ***")
        return

    chop.tsprnt("*** Password Listing Sent ***")
    if module_data['savelistings']:
        filename = "PI-password-listing-%d.txt" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def nofilesearchresults(data):
    chop.tsprnt("*** End of File Search Results ***")
    return

def noregsearchresults(data):
    chop.tsprnt("*** End of Registry Search Results ***")
    return

def filesearchresults(data):
    chop.tsprnt("*** File Search Results ***")
    dirlen = ord(data[0])
    endofdir = 1 + dirlen
    directory = data[1:endofdir]
    chop.prnt("Directory: %s" % directory)
    data = data[endofdir:]
    while data != "":
        filelen = ord(data[0])
        endoffile = 1 + filelen
        filename = data[1:endoffile]
        chop.prnt("File Name: %s" % filename)
        data = data[endoffile+20:]
    return

def regsearchresults(data):
    chop.tsprnt("*** Registry Search Results ***")
    keylen = ord(data[0])
    endofkey = 1 + keylen
    keyroot = data[1:endofkey]
    data = data[endofkey:]

    while data != "":
        if ord(data[0]) == 0:
            root = "HKEY_CLASSES_ROOT"
        elif ord(data[0]) == 1:
            root = "HKEY_CURRENT_USER"
        elif ord(data[0]) == 2:
            root = "HKEY_LOCAL_MACHINE"
        elif ord(data[0]) == 3:
            root = "HKEY_USERS"
        elif ord(data[0]) == 5:
            root = "HKEY_CURRENT_CONFIG"
        else:
            root = "??"

        #TODO: find the other types
        if ord(data[1]) == 1:
            type = "REG_SZ"
        elif ord(data[1]) == 4:
            type = "REG_DWORD"
        elif ord(data[1]) == 11:
            type = "KEY"
        else:
            type = "??"

        data = data[2:]
        chop.prnt("Root: %s" % root)
        if type == "KEY":
            strlen = ord(data[0])
            data = data[1:]
            key = keyroot + data[:strlen]
        else:
            key = keyroot
            if ord(data[0]) == 0:
                valname = "(default)"
                data = data[1:]
            else:
                valnamelen = ord(data[0])
                endofvalname = 1 + valnamelen
                valname = data[1:endofvalname]
                data = data[endofvalname:]

            strlen = unpack("<I", data[0:4])[0]
            data = data[4:]
            value = data[:strlen-1]

        data = data[strlen:]

        chop.prnt("Key: %s" % key)
        chop.prnt("Type: %s" % type)
        chop.prnt("Value Name: %s" % valname)
        if type in ["REG_DWORD", "REG_BINARY"]:
            chop.prnt("Value (hex): %s" % binascii.hexlify(value))
        else:
            chop.prnt("Value: %s" % value)

    return

def skip(data):
    return

def remotedesktop(data):
    chop.tsprnt("*** Remote Desktop Session ***")
    return

def webcam(data):
    chop.tsprnt("*** Web Cam Capture Sent ***")
    if module_data['savecaptures']:
        filename = "PI-extracted-file-%d-webcam.bmp" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def audio(data, tcp):
    chop.tsprnt("*** Audio Capture Sent ***")
    if module_data['savecaptures']:
        filename = "PI-extracted-file-%d-audio.raw" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("audio capture was saved in RAW format as %s" % filename)
    return

def screenshot(data):
    chop.tsprnt("*** Screen Capture Sent ***")
    if module_data['savecaptures']:
        filename = "PI-extracted-file-%d-screenshot.bmp" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def keylog(data):
    if len(data) == 0:
        chop.tsprnt("*** Keystroke Data Request - Nothing Found ***")
        return

    chop.tsprnt("*** Keystroke Data Sent ***")
    if module_data['savecaptures'] and len(data) > 0:
        filename = "PI-extracted-file-%d-keystrokes.txt" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def cachedpwlist(data):
    if len(data) == 0:
        chop.tsprnt("*** Cached Password Request - Nothing Found ***")
        return

    chop.tsprnt("*** Cached Password Listing Sent ***")
    if module_data['savelistings']:
        filename = "PI-cachedpw-listing-%d.txt" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def ntlmhashlist(data):
    if len(data) == 0:
        chop.tsprnt("*** NT/NTLM Hash Listing Request - Nothing Found ***")
        return

    chop.tsprnt("*** NT/NTLM Hash Listing Sent ***")
    while data != "":
        nthash = binascii.hexlify(data[:16])
        lmhash = binascii.hexlify(data[16:32])
        userlen = unpack("<I", data[32:36])[0]
        username = data[36:36+userlen]
        chop.prnt("User Name: %s" % username)
        chop.prnt("LM Hash: %s" % lmhash)
        chop.prnt("NT Hash: %s" % nthash)
        chop.prnt("*" * 41)
        data = data[36+userlen:]
    return

def wirelesspwlist(data):
    if len(data) == 0:
        chop.tsprnt("*** Wireless Listing Request - Nothing Found ***")
        return
    chop.tsprnt("*** Wireless Listing Sent ***")
    if module_data['savelistings']:
        filename = "PI-wireless-listing-%d.txt" % module_data['filecount']
        module_data['filecount'] += 1
        chop.savefile(filename, data)
        chop.prnt("%s saved.." % filename)
    return

def analyzeCode(code, type, tcp=None):
    if module_data['debug']:
        chop.tsprnt("code: %s" % hexdump(code))

    if type == 0x5c:
        #look for audio data parameters at the end of the code
        audioparams = code[-32:]
        chan = {1 : "Mono", 2: "Stereo"}
        # mono / 8 bits
        p = string.rfind(audioparams, "\x00\x00\x01\x00\x08\x00")

        # stereo / 8 bits
        if p == -1:
            p = string.rfind(audioparams, "\x00\x00\x02\x00\x08\x00")

        # mono / 16 bits
        if p == -1:
            p = string.rfind(audioparams, "\x00\x00\x01\x00\x10\x00")

        # stereo / 16 bits
        if p == -1:
            p = string.rfind(audioparams, "\x00\x00\x02\x00\x10\x00")

        if p != -1:
            try:
                sample = unpack("<I",audioparams[p-2:p+2])[0]
                channels = unpack("<H",audioparams[p+2:p+4])[0]
                bits = unpack("<H",audioparams[p+4:p+6])[0]
                chop.tsprnt("*** Audio Sample Settings ***")
                chop.prnt("Sample Rate: %0.3f kHz" % (sample / 1000.00))
                chop.prnt("Channels: %s" % chan[channels])
                chop.prnt("Bits: %d" % bits)
                tcp.stream_data['audio-sample'] = sample
                tcp.stream_data['audio-channels'] = channels
                tcp.stream_data['audio-bits'] = bits
            except:
                pass
    elif type == 0x05:
        chop.tsprnt("*** File Search Initiated ***")

        #find start of data
        #look for function epilogue
        p = string.rfind(code, "\x8b\xe5\x5d\xc3")
        if p == -1:
            p = 10
        else:
            p += 4

        if code[p+ord(code[p])] == "\\":
            dirend = p + 1 + ord(code[p])
            dirstart = p + 1

        chop.prnt("Search Directory: %s" % code[dirstart:dirend])

        p = dirend
        if code[p] == "\x00":
            p += 1
            type = "word in file"
            termend = p+1+ord(code[p])
            term = code[p+1:termend]
        else:
            type = "file name"
            termend = p+1+ord(code[p])
            term = code[p+1:termend]
            termend += 1

        options = ""
        if code[termend] == "\x01":
            options += "Include subdirectories\n"
        if code[termend+1] == "\x01":
            options += "Fuzzy matching (wildcards prepended and appended to search term)\n"
        if code[termend+2] == "\x01":
            options += "Case sensitive\n"
        else:
            options += "Case insensitive\n"

        chop.prnt("Search Term: %s" % term)
        chop.prnt("Search Type: %s" % type)
        chop.prnt("Options: %s" % options)
    elif type == 0x36:
        chop.tsprnt("*** Registry Search Initiated ***")
        #chop.prnt(hexdump(code))

        #find start of data
        #look for function epilogue
        p = string.rfind(code[:-11], "\x8b\xe5\x5d\xc3")
        if p == -1:
            p = 6
        p += 4
        if ord(code[p]) == 0:
            root = "HKEY_CLASSES_ROOT"
        elif ord(code[p]) == 1:
            root = "HKEY_CURRENT_USER"
        elif ord(code[p]) == 2:
            root = "HKEY_LOCAL_MACHINE"
        elif ord(code[p]) == 3:
            root = "HKEY_USERS"
        elif ord(code[p]) == 5:
            root = "HKEY_CURRENT_CONFIG"
        else:
            root = "??"
        p += 4

        if code[p+ord(code[p])] == "\\":
            keyend = p + 1 + ord(code[p])
            keystart = p + 1
        else:
            chop.prnt("unrecognizable format..")
            return

        key = code[keystart:keyend]
        p = keyend+4

        termend = p+1+ord(code[p])
        term = code[p+1:termend]

        options = ""
        if code[termend] == "\x01":
            options += "Look at keys\n"
        if code[termend+1] == "\x01":
            options += "Look at values\n"
        if code[termend+3] == "\x01":
            options += "Look at REG_SZ data\n"
        if code[termend+4] == "\x01":
            options += "Look at REG_BINARY data\n"
        if code[termend+5] == "\x01":
            options += "Look at REG_DWORD data\n"
        if code[termend+6] == "\x01":
            options += "Look at REG_MULTI_SZ data\n"
        if code[termend+7] == "\x01":
            options += "Look at REG_EXPAND_SZ data\n"
        if code[termend+8] == "\x01":
            options += "Include subkeys\n"
        if code[termend+9] == "\x01":
            options += "Fuzzy matching (wildcards prepended and appended to search term)\n"
        if code[termend+10] == "\x01":
            options += "Case sensitive\n"
        else:
            options += "Case insensitive\n"

        chop.prnt("Search Root: %s" % root)
        chop.prnt("Search Key: %s" % key)
        chop.prnt("Search Term: %s" % term)
        chop.prnt("Options: %s" % options)

    elif type == 2:
        chop.tsprnt("*** Directory Listing Initiated ***")
        p = string.rfind(code, ":\\")
        if p == -1:
            chop.prnt("unrecognizable format..")
            return
        chop.prnt("Directory: %s" % code[p-1:])

    elif type == 0x1e:
        chop.tsprnt("*** Registry Listing Initiated ***")

        if string.rfind(code, "\x90\x90") == -1:
            if ord(code[10]) == 0:
                root = "HKEY_CLASSES_ROOT"
            elif ord(code[10]) == 1:
                root = "HKEY_CURRENT_USER"
            elif ord(code[10]) == 2:
                root = "HKEY_LOCAL_MACHINE"
            elif ord(code[10]) == 3:
                root = "HKEY_USERS"
            elif ord(code[10]) == 5:
                root = "HKEY_CURRENT_CONFIG"
            else:
                root = "??"
            reg = code[14:]
            chop.prnt("Root: %s" % root)
            chop.prnt("Registry Key: %s" % reg)
    elif type == 0x47 or type == 0x43:
        chop.tsprnt("*** Relay Service Started ***")
        if type == 0x43:
            type = "Socks4"
        else:
            type = "Socks5"

        #find start of data
        #look for function epilogue
        p = string.rfind(code, "\x8b\xe5\x5d\xc3")
        if p == -1:
            p = 10
        else:
            p += 4

        relayport = unpack("<H", code[p:p+2])[0]
        p += 2
        user = ""
        pw = ""
        if ord(code[p]) == 1:
            p += 1
            userend = p + 1 + ord(code[p])
            user = code[p+1:userend]
            pwend = userend + 1 + ord(code[userend])
            pw = code[userend+1:pwend]
            srcipend = pwend + 1 + ord(code[pwend])
            srcip = code[pwend+1:srcipend]
            dstipend = srcipend + 1 + ord(code[srcipend])
            dstip = code[srcipend+1:dstipend]
            dstport = unpack("<H", code[dstipend:dstipend+2])[0]

        elif ord(code[p]) != 0:
            userend = p + 1 + ord(code[p])
            user = code[p+1:userend]
            srcipend = userend + 1 + ord(code[userend])
            srcip = code[userend+1:srcipend]
            dstipend = srcipend + 1 + ord(code[srcipend])
            dstip = code[srcipend+1:dstipend]
            dstport = unpack("<H", code[dstipend:dstipend+2])[0]

        chop.prnt("Relay Type: %s" % type)
        chop.prnt("Relay Port: %d" % relayport)
        if user != "":
            chop.prnt("User: %s" % user)
            if pw != "":
                chop.prnt("Password: %s" % pw)
            chop.prnt("Source IP: %s" % srcip)
            chop.prnt("Destination IP: %s" % dstip)
            chop.prnt("Destination Port: %d" % dstport)
    elif type == 0x46:
        chop.tsprnt("*** Relay Service Stopped ***")
    elif type == 0x4c:
        chop.tsprnt("*** Gateway Service Started ***")
        #find start of data
        #look for function epilogue
        p = string.rfind(code, "\x8b\xe5\x5d\xc3")
        if p == -1:
            p = 10
        else:
            p += 4
        srcip = ""
        relayport = unpack("<H", code[p:p+2])[0]
        p += 2
        dstipend = p + 1 + ord(code[p])
        dstip = code[p+1:dstipend]
        dstport = unpack("<H", code[dstipend:dstipend+2])[0]
        if ord(code[dstipend+2]) != 0:
            srcipend = dstipend + 3 + ord(code[dstipend+2])
            srcip = code[dstipend+3:srcipend]

        chop.prnt("Relay Port: %d" % relayport)
        if srcip != "":
            chop.prnt("Source IP: %s" % srcip)
        chop.prnt("Destination IP: %s" % dstip)
        chop.prnt("Destination Port: %d" % dstport)
    return

#returns listid and bool for new PI stream
def getHeaders(direction, buf, tcp):
    buf = CamelliaDecrypt(buf, module_data['camcrypt'], tcp.stream_data.get('xor', None))
    listid = unpack("<I",buf[4:8])[0]
    type = unpack("<I",buf[0:4])[0]
    newstream = False
    if module_data['debug']:
        chop.tsprnt("%s headers: %s" % (direction,hexdump(buf)))
    if direction == "in":
        if tcp.stream_data['inbound_type'].get(listid, -1) != type:
            newstream = True
        tcp.stream_data['inbound_type'][listid] = type
        tcp.stream_data['inbound_chunk_size'][listid] = unpack("<I",buf[8:12])[0]
        tcp.stream_data['inbound_total_size'][listid] = unpack("<q",buf[20:28])[0]
        tcp.stream_data['inbound_unpadded_chunk_size'][listid] = unpack("<I",buf[12:16])[0]
        tcp.stream_data['inbound_decompressed_chunk_size'][listid] = unpack("<I",buf[16:20])[0]
        if tcp.stream_data['client_collect_buffer'].get(listid) == None:
            tcp.stream_data['client_collect_buffer'][listid] = ""

    else:
        if tcp.stream_data['outbound_type'].get(listid, -1) != type:
            newstream = True
        tcp.stream_data['outbound_type'][listid] = type
        tcp.stream_data['outbound_chunk_size'][listid] = unpack("<I",buf[8:12])[0]
        tcp.stream_data['outbound_total_size'][listid] = unpack("<q",buf[20:28])[0]
        tcp.stream_data['outbound_unpadded_chunk_size'][listid] = unpack("<I",buf[12:16])[0]
        tcp.stream_data['outbound_decompressed_chunk_size'][listid] = unpack("<I",buf[16:20])[0]
        if tcp.stream_data['server_collect_buffer'].get(listid) == None:
            tcp.stream_data['server_collect_buffer'][listid] = ""

    return (listid, newstream)

def pad(buf):
    size = len(buf)
    next = size
    while next % 16 != 0:
        next+=1

    pad = next - size
    buf += "\x00" * pad

    return buf

def CamelliaEncrypt(buf, camobj, xor=None):
    out = ""
    for i in range(0, len(buf), 16):
        out+=camobj.encrypt(buf[i:i+16])

    if xor is not None:
        out = one_byte_xor(out, xor)

    return out

def CamelliaDecrypt(buf, camobj, xor=None):
    out = ""
    if xor is not None:
        buf = one_byte_xor(buf, xor)

    for i in range(0, len(buf), 16):
        out+=camobj.decrypt(buf[i:i+16])

    return out

def TryKeyList(keylist, challenge, response, camobj, xor=None):
    #just in case admin is not included in the list
    camobj.keygen(256,"admin" + "\x00" * 27)
    if response == CamelliaEncrypt(challenge,module_data['camcrypt'], xor):
        chop.prnt("Key found: admin")
        return True

    with open(keylist, 'r') as f:
        for line in f:
            line = string.strip(line)
            key = line
            if key[:2] == "0x":
                key = binascii.unhexlify(key[2:])

            if len(key) > 32:
                continue

            #pad to 256 bits
            if len(key) < 32:
                key += "\x00" * (32 - len(key))
            camobj.keygen(256,key)
            if response == CamelliaEncrypt(challenge,module_data['camcrypt'], xor):
                chop.prnt("Key found: %s" % line)
                return True

        return False

def init(module_data):
    module_options = { 'proto': 'tcp' }
    parser = OptionParser()
    parser.add_option("-f", "--save-files", action="store_true",
                      dest="savefiles", default=False, help="save transferred files")
    parser.add_option("-l", "--save-listings", action="store_true",
                      dest="savelistings", default=False, help="save reg/dir/proc/etc listings to files")
    parser.add_option("-c", "--save-captures", action="store_true",
                      dest="savecaptures", default=False, help="save screen/webcam/audio/key captures to files")
    parser.add_option("-v", "--verbose", action="store_true",
                      dest="verbose", default=False, help="verbosity")
    parser.add_option("-d", "--debug", action="store_true",
                      dest="debug", default=False, help="debug output")
    parser.add_option('-p', '--lib-path', dest='libpath', default="", help='the path to the required lib file (camellia.so)')
    parser.add_option('-w', '--password', dest='pw', default="admin", help='the password used to build the encryption key (optional, a default key will be used if not provided)')
    parser.add_option('-x', '--hex-pw', dest='asciihexpw', help='the hex-encoded password used to build the encryption key (with or without spaces)')
    parser.add_option('-t', '--try-pw-list', dest='pwlist', help='a file containing a line delimited list of passwords used to build the encryption key. each password will be tried during the challenge phase until the proper password is found or all passwords have been tried. ascii hex passwords should be prepended with \'0x\'')

    (opts, lo) = parser.parse_args(module_data['args'])

    module_data['cmdhandler'] = {0x27 : heartbeat,
                                 0x17 : shell,
                                 0x0b : dirlist,
                                 0x02 : dirlist,
                                 0x01 : hostinfo,
                                 0x1e : reglist,
                                 0x2b : servicelist,
                                 0x14 : proclist,
                                 0x68 : devicelist,
                                 0x53 : skip,
                                 0x44 : skip,
                                 0x2a : nofilesearchresults,
                                 0x05 : filesearchresults,
                                 0x1c : webcam,
                                 0x5c : audio,
                                 0x58 : installedlist,
                                 0x49 : keylog,
                                 0x19 : screenshot,
                                 0x39 : remotedesktop,
                                 0x3c : cachedpwlist,
                                 0x5b : ntlmhashlist,
                                 0x5a : wirelesspwlist,
                                 0x36 : regsearchresults,
                                 0x37 : noregsearchresults,
                                 0x0d : windowlist,
                                 0x38 : portlist}

    module_data['savefiles'] = opts.savefiles
    module_data['savelistings'] = opts.savelistings
    module_data['savecaptures'] = opts.savecaptures
    module_data['verbose'] = opts.verbose
    module_data['pwlist'] = opts.pwlist
    module_data['debug'] = opts.debug

    try:
        if opts.libpath != "":
            module_data['camcrypt'] = camcrypt.CamCrypt(opts.libpath)
        else:
            module_data['camcrypt'] = camcrypt.CamCrypt("camellia.so")
    except:
        module_options = { 'proto': 'tcp', 'error':  "Couldn't locate camellia.so"}
        return module_options

    if not module_data['pwlist']:
        if opts.asciihexpw:
            module_data['key'] = binascii.unhexlify(string.replace(opts.asciihexpw, " ", ""))
        else:
            module_data['key'] = opts.pw

        if len(module_data['key']) > 32:
            module_options = { 'proto': 'tcp', 'error':  "Supplied password must be 32 bytes long or less.."}
            return module_options
        elif len(module_data['key']) < 32:
            #pad key to 256 bits
            for i in range(32 - len(module_data['key'])):
                module_data['key']+="\x00"

        module_data['camcrypt'].keygen(256, module_data['key'])

    elif not os.path.exists(module_data['pwlist']):
        module_options = { 'proto': 'tcp', 'error':  "Supplied password list does not exist.."}
        return module_options

    module_data['filecount'] = 1

    module_options = { 'proto': 'tcp' }
    return module_options

def handleStream(tcp):
    if tcp.client.count_new > 0:
        tcp.stream_data['client_buffer'] += tcp.client.data[:tcp.client.count_new]
        if tcp.stream_data['client_state'] == "challenged":
            if len(tcp.stream_data['client_buffer']) >= 256:
                challenge_resp = tcp.stream_data['client_buffer'][:256]
                tcp.stream_data['client_buffer'] = tcp.stream_data['client_buffer'][256:]
                if module_data['pwlist']:
                    if TryKeyList(module_data['pwlist'], tcp.stream_data['challenge'], challenge_resp, module_data['camcrypt']):
                        if module_data['verbose'] or module_data['debug']:
                            chop.tsprnt("PI challenge response accepted..")
                        tcp.stream_data['client_state'] = "challenge_accepted"
                        tcp.discard(tcp.client.count_new)
                        return
                if challenge_resp == CamelliaEncrypt(tcp.stream_data['challenge'], module_data['camcrypt']):
                    if module_data['verbose'] or module_data['debug']:
                        chop.tsprnt("PI challenge response accepted..")
                    tcp.stream_data['client_state'] = "challenge_accepted"
                    tcp.discard(tcp.client.count_new)
                    return
                else:
                    tcp.stream_data['client_state'] = "challenge_failed"
                    if module_data['verbose'] or module_data['debug']:
                        chop.tsprnt("PI challenge response not valid for supplied passwords(s), skipping stream..")
                    #tcp.stream_data['challenge_accepted'] = True
                    tcp.stop()
                    return

        if tcp.stream_data['client_state'] == "double_challenged":
            if len(tcp.stream_data['client_buffer']) >= 260:
                challenge_resp = tcp.stream_data['client_buffer'][:256]
                tcp.stream_data['client_buffer'] = tcp.stream_data['client_buffer'][256:]
                (a, b) = struct.unpack('>HH', tcp.client.data[:4])
                a ^= 0xd015
                if a != b:
                    tcp.stream_data['client_state'] = "challenge_failed"
                    if module_data['verbose'] or module_data['debug']:
                        chop.tsprnt("PI challenge not valid, skipping stream..")
                    tcp.stop()
                    return
                tcp.stream_data['xor'] = a & 0xFF
                chop.tsprnt("PI double nonce xor variant, xor key: %02X" % tcp.stream_data['xor'])
                if module_data['pwlist']:
                    if TryKeyList(module_data['pwlist'], tcp.stream_data['challenge'], challenge_resp, module_data['camcrypt'], tcp.stream_data['xor']):
                        if module_data['verbose'] or module_data['debug']:
                            chop.tsprnt("PI challenge response accepted..")
                        tcp.stream_data['client_state'] = "challenge_accepted"
                        tcp.discard(tcp.client.count_new)
                        return
                if challenge_resp == CamelliaEncrypt(one_byte_xor(tcp.stream_data['challenge'], tcp.stream_data['xor']), module_data['camcrypt'], tcp.stream_data['xor']):
                    if module_data['verbose'] or module_data['debug']:
                        chop.tsprnt("PI challenge response accepted..")
                    tcp.stream_data['client_state'] = "challenge_accepted"
                    tcp.discard(tcp.client.count_new)
                    return
                else:
                    tcp.stream_data['client_state'] = "challenge_failed"
                    if module_data['verbose'] or module_data['debug']:
                        chop.tsprnt("PI double challenge response not valid for supplied passwords(s), skipping stream..")
                    #tcp.stream_data['challenge_accepted'] = True
                    tcp.stop()
                    return

        if tcp.stream_data['client_state'] == "challenge_accepted":
            if len(tcp.stream_data['client_buffer']) >= 4:
                if 'xor' in tcp.stream_data:
                    tcp.stream_data['init_size'] = unpack("<I",one_byte_xor(tcp.stream_data['client_buffer'][:4], tcp.stream_data['xor']))[0]
                else:
                    tcp.stream_data['init_size'] = unpack("<I",tcp.stream_data['client_buffer'][:4])[0]
                tcp.stream_data['client_state'] = "init_code_collection"
                tcp.stream_data['client_buffer'] = tcp.stream_data['client_buffer'][4:]


        if tcp.stream_data['client_state'] == "init_code_collection":
            if tcp.stream_data['init_size'] <= len(tcp.stream_data['client_buffer']):
                tcp.stream_data['client_state'] = "init_code_collected"
                #decrypted = CamelliaDecrypt(tcp.stream_data['client_buffer'][:tcp.stream_data['init_size']],module_data['camcrypt'])
                if module_data['debug']:
                    chop.tsprnt("init code size: %08X" % tcp.stream_data['init_size'])
                tcp.stream_data['client_buffer'] = tcp.stream_data['client_buffer'][tcp.stream_data['init_size']:]

        if tcp.stream_data['client_state'] == "init_code_collected":
            if len(tcp.stream_data['client_buffer']) >= 4:
                if 'xor' in tcp.stream_data:
                    tcp.stream_data['version'] = unpack("<I", one_byte_xor(tcp.stream_data['client_buffer'][:4], tcp.stream_data['xor']))[0]
                else:
                    tcp.stream_data['version'] = unpack("<I", tcp.stream_data['client_buffer'][:4])[0]
                tcp.stream_data['client_buffer'] = tcp.stream_data['client_buffer'][4:]
                tcp.stream_data['client_state'] = "version_collected"
                chop.tsprnt("Poison Ivy Version: %0.2f" % (tcp.stream_data['version'] / 100.00))

        if tcp.stream_data['client_state'] == "version_collected":
            if len(tcp.stream_data['client_buffer']) >= 4:
                if 'xor' in tcp.stream_data:
                    tcp.stream_data['init_size'] = unpack("<I",one_byte_xor(tcp.stream_data['client_buffer'][:4], tcp.stream_data['xor']))[0]
                else:
                    tcp.stream_data['init_size'] = unpack("<I",tcp.stream_data['client_buffer'][:4])[0]
                tcp.stream_data['client_buffer'] = tcp.stream_data['client_buffer'][4:]
                tcp.stream_data['client_state'] = "stub_code_collection"
                if module_data['debug']:
                    chop.tsprnt("stub code size: %08X" % tcp.stream_data['init_size'])

        if tcp.stream_data['client_state'] == "stub_code_collection":
            if tcp.stream_data['init_size'] <= len(tcp.stream_data['client_buffer']):
                tcp.stream_data['client_state'] = "stub_code_collected"
                if module_data['debug']:
                    chop.tsprnt("stub code collected..")
                tcp.stream_data['client_buffer'] = tcp.stream_data['client_buffer'][tcp.stream_data['init_size']:]

        if tcp.stream_data['client_state'] == "stub_code_collected":
            #initialization complete
            if module_data['debug']:
                chop.tsprnt("init complete..")
            tcp.stream_data['client_state'] = "read_header"
            tcp.stream_data['server_state'] = "read_header"
            tcp.stream_data['server_buffer'] = ""


        if tcp.stream_data['client_state'] == "read_header":
            listid = tcp.stream_data['client_cur_listid']
            if len(tcp.stream_data['client_buffer']) >= 32:
                (tcp.stream_data['client_cur_listid'], newstream) = getHeaders("in",tcp.stream_data['client_buffer'][:32],tcp)
                listid = tcp.stream_data['client_cur_listid']
                tcp.stream_data['client_state'] = "recv_chunk"
                tcp.stream_data['client_buffer'] = tcp.stream_data['client_buffer'][32:]
                if newstream:
                    if tcp.stream_data['inbound_type'].get(listid) == 6:
                        #handle file data
                        decrypted = CamelliaDecrypt(tcp.stream_data['client_buffer'][:tcp.stream_data['inbound_chunk_size'].get(listid)], module_data['camcrypt'], tcp.stream_data.get('xor', None))
                        tcp.stream_data['client_buffer'] = tcp.stream_data['client_buffer'][tcp.stream_data['inbound_chunk_size'].get(listid):]
                        if tcp.stream_data['inbound_unpadded_chunk_size'].get(listid) != tcp.stream_data['inbound_decompressed_chunk_size'].get(listid):
                            buf = lznt1.dCompressBuf(decrypted[:tcp.stream_data['inbound_unpadded_chunk_size'].get(listid)])
                            if buf == None:
                                chop.tsprnt("decompression error: %s" % hexdump(decrypted))
                                tcp.stop()
                        else:
                            buf = decrypted[:tcp.stream_data['inbound_unpadded_chunk_size'].get(listid)]
                        #decompressed = lznt1.dCompressBuf(decrypted[:tcp.stream_data['inbound_unpadded_chunk_size']])
                        filename = string.strip(buf, "\x00")
                        tcp.stream_data['inbound_filename'][listid] = "PI-extracted-inbound-file-%d-%s" % (module_data['filecount'], filename[string.rfind(filename, "\\")+1:])
                        module_data['filecount'] += 1
                        chop.tsprnt("inbound file %s " % filename)

                        tcp.stream_data['client_state'] = "read_header"

                    tcp.stream_data['inbound_size_left'][listid] = tcp.stream_data['inbound_total_size'].get(listid)

            if tcp.stream_data['inbound_size_left'].get(listid) == 0:
                    tcp.stream_data['inbound_size_left'][listid] = tcp.stream_data['inbound_total_size'].get(listid)


        if tcp.stream_data['client_state'] == "recv_chunk":
            listid = tcp.stream_data['client_cur_listid']
            if tcp.stream_data['inbound_chunk_size'].get(listid) <= len(tcp.stream_data['client_buffer']):
                if module_data['debug']:
                    chop.tsprnt("handling inbound chunk.. %d bytes to go" % tcp.stream_data['inbound_size_left'].get(listid))
                tcp.stream_data['client_state'] = "read_header"
                decrypted = CamelliaDecrypt(tcp.stream_data['client_buffer'][:tcp.stream_data['inbound_chunk_size'].get(listid)], module_data['camcrypt'], tcp.stream_data.get('xor', None))
                decrypted = decrypted[:tcp.stream_data['inbound_unpadded_chunk_size'].get(listid)]
                buf = decrypted
                if tcp.stream_data['inbound_unpadded_chunk_size'].get(listid) != tcp.stream_data['inbound_decompressed_chunk_size'].get(listid):
                    buf = lznt1.dCompressBuf(decrypted)
                    if buf == None:
                        chop.tsprnt("decompression error: %s" % hexdump(decrypted))
                        tcp.stop()
                tcp.stream_data['client_collect_buffer'][listid] += buf
                tcp.stream_data['client_buffer'] = tcp.stream_data['client_buffer'][tcp.stream_data['inbound_chunk_size'].get(listid):]
                tcp.stream_data['inbound_size_left'][listid] -= tcp.stream_data['inbound_decompressed_chunk_size'].get(listid)
                if tcp.stream_data['inbound_type'].get(listid) == 6 and module_data['savefiles']:
                        #inbound file
                        chop.savefile(tcp.stream_data['inbound_filename'].get(listid), buf, False)

                if tcp.stream_data['inbound_size_left'].get(listid) == 0:
                    if tcp.stream_data['inbound_type'].get(listid) == 6:
                        if module_data['savefiles']:
                            #inbound file
                            chop.finalizefile(tcp.stream_data['inbound_filename'].get(listid))
                            chop.tsprnt("saved %s.." % tcp.stream_data['inbound_filename'].get(listid))
                    else:
                        analyzeCode(tcp.stream_data['client_collect_buffer'].get(listid),tcp.stream_data['inbound_type'].get(listid), tcp)
                        if module_data['debug']:
                            chop.tsprnt("analyzing code..")

                    tcp.stream_data['client_collect_buffer'][listid] = ""


        #chop.tsprnt("to client:%d" % tcp.client.count_new)
        tcp.discard(tcp.client.count_new)
        return

    elif tcp.server.count_new > 0:
        tcp.stream_data['server_buffer'] += tcp.server.data[:tcp.server.count_new]
        if tcp.stream_data['client_state'] == "unauthenticated":
            if len(tcp.stream_data['server_buffer']) >= 256:
                tcp.stream_data['client_state'] = "challenged"
                #chop.tsprnt(hexdump(tcp.server.data[:tcp.server.count_new]))
                tcp.stream_data['challenge'] = tcp.stream_data['server_buffer'][:256]
                tcp.stream_data['server_buffer'] = tcp.stream_data['server_buffer'][256:]
                #chop.tsprnt(hexdump(tcp.stream_data['challenge']))
        elif tcp.stream_data['client_state'] == "challenged":
            if len(tcp.stream_data['server_buffer']) >= 256:
                tcp.stream_data['client_state'] = "double_challenged"
                tcp.stream_data['challenge'] = tcp.stream_data['server_buffer'][:256]
                tcp.stream_data['server_buffer'] = tcp.stream_data['server_buffer'][256:]
        elif tcp.stream_data['client_state'] == "double_challenged":
            if module_data['verbose'] or module_data['debug']:
                chop.tsprnt("PI challenge not found, skipping stream..")
            tcp.stop()

        if tcp.stream_data['server_state'] == "read_header":
            listid = tcp.stream_data['server_cur_listid']
            if len(tcp.stream_data['server_buffer']) >= 32:
                (tcp.stream_data['server_cur_listid'], newstream) = getHeaders("out",tcp.stream_data['server_buffer'][:32],tcp)
                listid = tcp.stream_data['server_cur_listid']
                tcp.stream_data['server_state'] = "recv_chunk"
                tcp.stream_data['server_buffer'] = tcp.stream_data['server_buffer'][32:]
                if newstream:
                    if tcp.stream_data['outbound_type'].get(listid) == 4:
                        #handle file data
                        decrypted = CamelliaDecrypt(tcp.stream_data['server_buffer'][:tcp.stream_data['outbound_chunk_size'].get(listid)], module_data['camcrypt'], tcp.stream_data.get('xor', None))
                        if tcp.stream_data['outbound_unpadded_chunk_size'].get(listid) != tcp.stream_data['outbound_decompressed_chunk_size'].get(listid):
                            buf = lznt1.dCompressBuf(decrypted[:tcp.stream_data['outbound_unpadded_chunk_size'].get(listid)])
                            if buf == None:
                                chop.tsprnt("decompression error: %s" % hexdump(decrypted))
                                tcp.stop()
                        else:
                            buf = decrypted[:tcp.stream_data['outbound_unpadded_chunk_size'].get(listid)]

                        tcp.stream_data['server_buffer'] = tcp.stream_data['server_buffer'][tcp.stream_data['outbound_chunk_size'].get(listid):]
                        filename = string.strip(buf, "\x00")
                        tcp.stream_data['outbound_filename'][listid] = "PI-extracted-outbound-file-%d-%s" % (module_data['filecount'], filename[string.rfind(filename, "\\")+1:])
                        module_data['filecount'] += 1
                        chop.tsprnt("outbound file %s " % filename)

                        tcp.stream_data['server_state'] = "read_header"

                    tcp.stream_data['outbound_size_left'][listid] = tcp.stream_data['outbound_total_size'].get(listid)


                if tcp.stream_data['outbound_size_left'].get(listid) == 0:
                    tcp.stream_data['outbound_size_left'][listid] = tcp.stream_data['outbound_total_size'].get(listid)

        if tcp.stream_data['server_state'] == "recv_chunk":
            listid = tcp.stream_data['server_cur_listid']
            if tcp.stream_data['outbound_chunk_size'].get(listid) <= len(tcp.stream_data['server_buffer']):
                if module_data['debug']:
                    chop.tsprnt("handling outbound chunk.. %d bytes to go" % tcp.stream_data['outbound_size_left'].get(listid))
                tcp.stream_data['server_state'] = "read_header"
                decrypted = CamelliaDecrypt(tcp.stream_data['server_buffer'][:tcp.stream_data['outbound_chunk_size'].get(listid)], module_data['camcrypt'], tcp.stream_data.get('xor', None))
                decrypted = decrypted[:tcp.stream_data['outbound_unpadded_chunk_size'].get(listid)]
                buf = decrypted
                if tcp.stream_data['outbound_unpadded_chunk_size'].get(listid) != tcp.stream_data['outbound_decompressed_chunk_size'].get(listid):
                    buf = lznt1.dCompressBuf(decrypted)
                    if buf == None:
                        chop.tsprnt("decompression error: %s" % hexdump(decrypted))
                        tcp.stop()
                tcp.stream_data['server_collect_buffer'][listid] += buf
                tcp.stream_data['server_buffer'] = tcp.stream_data['server_buffer'][tcp.stream_data['outbound_chunk_size'].get(listid):]
                tcp.stream_data['outbound_size_left'][listid] -= tcp.stream_data['outbound_decompressed_chunk_size'].get(listid)
                if tcp.stream_data['outbound_type'].get(listid) == 4 and module_data['savefiles']:
                        #outbound file
                        chop.savefile(tcp.stream_data['outbound_filename'].get(listid), buf, False)

                if tcp.stream_data['outbound_size_left'].get(listid) == 0:
                    if tcp.stream_data['outbound_type'].get(listid) == 4:
                        if module_data['savefiles']:
                            #outbound file
                            chop.finalizefile(tcp.stream_data['outbound_filename'].get(listid))
                            chop.tsprnt("saved %s.." % tcp.stream_data['outbound_filename'].get(listid))
                    else:
                        if module_data['debug']:
                            chop.tsprnt("outbound data: %s" % hexdump(tcp.stream_data['server_collect_buffer'].get(listid)))

                        try:
                            if tcp.stream_data['outbound_type'].get(listid) == 0x5c:
                                module_data['cmdhandler'][tcp.stream_data['outbound_type'].get(listid)](tcp.stream_data['server_collect_buffer'].get(listid), tcp)
                            else:
                                module_data['cmdhandler'][tcp.stream_data['outbound_type'].get(listid)](tcp.stream_data['server_collect_buffer'].get(listid))
                        except:
                            if module_data['verbose'] or module_data['debug']:
                                chop.tsprnt("unrecognized command..")

                    tcp.stream_data['server_collect_buffer'][listid] = ""

        tcp.discard(tcp.server.count_new)
        return

    tcp.discard(tcp.server.count_new)
    return

def taste(tcp):
    tcp.stream_data['challenge'] = ''
    tcp.stream_data['version'] = 0
    tcp.stream_data['server_buffer'] = ''
    tcp.stream_data['client_buffer'] = ''
    tcp.stream_data['server_cur_listid'] = 0
    tcp.stream_data['client_cur_listid'] = 0
    tcp.stream_data['server_collect_buffer'] = {}
    tcp.stream_data['client_collect_buffer'] = {}
    tcp.stream_data['init_size'] = 0
    tcp.stream_data['inbound_type'] = {}
    tcp.stream_data['inbound_filename'] = {}
    tcp.stream_data['inbound_chunk_size'] = {}
    tcp.stream_data['inbound_total_size'] = {}
    tcp.stream_data['inbound_size_left'] = {}
    tcp.stream_data['inbound_unpadded_chunk_size'] = {}
    tcp.stream_data['inbound_decompressed_chunk_size'] = {}
    tcp.stream_data['outbound_type'] = {}
    tcp.stream_data['outbound_filename'] = {}
    tcp.stream_data['outbound_chunk_size'] = {}
    tcp.stream_data['outbound_total_size'] = {}
    tcp.stream_data['outbound_size_left'] = {}
    tcp.stream_data['outbound_unpadded_chunk_size'] = {}
    tcp.stream_data['outbound_decompressed_chunk_size'] = {}
    tcp.stream_data['client_state'] = "unauthenticated"
    tcp.stream_data['server_state'] = ""
    tcp.stream_data['audio-sample'] = 0
    tcp.stream_data['audio-channels'] = 0
    tcp.stream_data['audio-bits'] = 0
    return True

def teardown(tcp):
    pass

def module_info():
    return "Poison Ivy 2.3.X network protocol decoder"

def shutdown(module_data):
    pass
