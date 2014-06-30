# Copyright (c) 2014 FireEye, Inc. All rights reserved.
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
import zlib
import struct
import re
import binascii
import string
from c2utils import *
from optparse import OptionParser
from Crypto.Cipher import ARC4

moduleName="spynet_26"
moduleVersion="1.0"
minimumChopLib="4.0"

def processInboundData(data, tcp):
    module_data = tcp.module_data
    params = string.split(data, "|")
    if params[0] == "mymessagebox":
        chop.prnt("*** MessageBox Created ***")
        chop.prnt("\nTitle: %s" % params[3])
        chop.prnt("Message: %s" % params[4])
    elif params[0] == "upload":
        chop.tsprnt("*** Inbound File Transfer Initiated ***\nAttacker's filename: %s\nVictim's filename: %s" % (params[1],params[2]))
        module_data['inbound_files'][params[1]] = int(params[3])
    elif params[0] == "downexec":
        chop.tsprnt("*** Download and Execute Initiated ***\nLaunch Hidden?: %s\nURL: %s" % (params[1],params[2]))
    elif params[0] == "startproxy":
        chop.prnt("*** HTTP Proxy Started on Port %s ***" % params[1])
    elif params[0] == "executarcomandos":
        chop.prnt("*** Execute Command Received ***\nCommand: %s" % params[1])
    elif params[0] == "updateservidorweb":
        chop.tsprnt("*** Server Update From Web ***\nURL: %s" % params[1])

def listDrives(params, tcp):
    module_data = tcp.module_data
    chop.tsprnt("*** Drive Listing Sent ***")
    if module_data['listings']:
        types = {2: "removable", 3: "local", 5: "CD/DVD"}
        for i in range(0, len(params) - 1, 2):
            chop.prnt("\nName: %s" % params[i])
            chop.prnt("Type: %s" % types.get(int(params[i+1]), params[i+1]))
        chop.prnt("\n\n")

def listInstalled(params, tcp):
    module_data = tcp.module_data
    chop.tsprnt("*** Installed Programs Listing Sent ***")
    if module_data['listings']:
        lines = string.split(params, "\r\n")
        for line in lines:
            fields = string.split(line, "##@@")
            if len(fields) < 3:
                break
            chop.prnt("\nProgram name: %s" % fields[0])
            chop.prnt("Uninstaller file: %s" % fields[1])
            if fields[2] == "YYY":
                chop.prnt("Silent uninstall: YES")
            else:
                chop.prnt("Silent uninstall: NO")
        chop.prnt("\n\n")

def listActivePorts(params, tcp):
    module_data = tcp.module_data
    chop.tsprnt("*** Active Ports Listing Sent ***")
    if module_data['listings']:
        for i in range(0, len(params) - 2, 8):
            chop.prnt("\nProtocol: %s" % string.strip(params[i], "\r\n"))
            chop.prnt("Local IP: %s" % params[i+1])
            chop.prnt("Local port: %s" % params[i+2])
            chop.prnt("Remote IP: %s" % params[i+3])
            chop.prnt("Remote port: %s" % params[i+4])
            chop.prnt("Status: %s" % params[i+5])
            chop.prnt("PID: %s" % params[i+6])
            chop.prnt("Process name: %s" % params[i+7])
        chop.prnt("\n\n")

def listWindows(params, tcp):
    module_data = tcp.module_data
    chop.tsprnt("*** Windows Listing Sent ***")
    if module_data['listings']:
        for i in range(0, len(params) - 1, 3):
            hidden = False
            if params[i][:4] == "*@*@":
                hidden = True
                name = params[i][4:]
            else:
                name = params[i]
            chop.prnt("\nName: %s" % name)
            chop.prnt("Handle: %s" % params[i+1])
            chop.prnt("Path: %s" % params[i+2])
            if hidden:
                chop.prnt("Hidden: YES")
            else:
                chop.prnt("Hidden: NO")
        chop.prnt("\n\n")

def listServices(params, tcp):
    module_data = tcp.module_data
    chop.tsprnt("*** Service Listing Sent ***")
    if module_data['listings']:
        status = {1: 'Stopped', 4: 'Running'}
        items = string.split(params, "\xae")
        for i in range(0, len(items) - 1, 4):
            chop.prnt("\nName: %s" % items[i])
            chop.prnt("Display name: %s" % items[i+1])
            chop.prnt("Description: %s" % items[i+2])
            chop.prnt("Status: %s" % status.get(int(items[i+3][0]), items[i+3]))
        chop.prnt("\n\n")

def listProcesses(params, tcp):
    module_data = tcp.module_data
    chop.tsprnt("*** Process Listing Sent ***")
    if module_data['listings']:
        for i in range(0, len(params) - 1, 4):
            chop.prnt("\nName: %s" % params[i][2:])
            chop.prnt("PID: %s" % params[i+1])
            chop.prnt("Memory: %s" % params[i+2])
            chop.prnt("Path: %s" % params[i+3])
        chop.prnt("\n\n")

def serverConfig(params, tcp):
    chop.tsprnt("*** Configuration Details ***")
    i = 2
    while params[i][0] != "#":
        chop.prnt("C2: %s" % params[i])
        i += 1

    chop.prnt("ID: %s" % params[i])
    chop.prnt("Password: %s" % params[i+1])
    chop.prnt("Install path: %s" % params[i+2])
    chop.prnt("Host process: %s" % params[i+3])
    chop.prnt("HKLM run: %s" % params[i+4])
    chop.prnt("HKCU run: %s" % params[i+5])
    chop.prnt("ActiveSetup GUID: %s" % params[i+6])
    chop.prnt("Policies Startup: %s" % params[i+7])
    chop.prnt("Watchdog: %s" % params[i+8])
    chop.prnt("Hide file: %s" % params[i+9])
    chop.prnt("Timestomp file: %s" % params[i+10])
    chop.prnt("Delete original file: %s" % params[i+11])
    chop.prnt("Mutex: %s" % params[i+12])
    chop.prnt("Alert message title: %s" % params[i+13])
    chop.prnt("Alert message text: %s" % params[i+14])
    chop.prnt("Keylogger enabled: %s" % params[i+15])
    chop.prnt("Transfer keylogs via FTP: %s" % params[i+16])
    chop.prnt("FTP host: %s" % params[i+17])
    chop.prnt("FTP directory: %s" % params[i+18])
    chop.prnt("FTP user: %s" % params[i+19])
    chop.prnt("FTP password: %s" % params[i+20])
    chop.prnt("FTP port: %s" % params[i+21])
    chop.prnt("FTP transfer delay: %s minutes" % params[i+22])
    chop.prnt("Anti Sandboxie: %s" % params[i+23])
    chop.prnt("Anti Virtual PC: %s" % params[i+24])
    chop.prnt("Anti VMware: %s" % params[i+25])
    chop.prnt("Anti VirtualBox: %s" % params[i+26])
    chop.prnt("Anti ThreatExpert: %s" % params[i+27])
    chop.prnt("Anti Anubis: %s" % params[i+28])
    chop.prnt("Anti CWSandbox: %s" % params[i+29])
    chop.prnt("Anti JoeBox: %s" % params[i+30])
    chop.prnt("Anti Norman Sandbox: %s" % params[i+31])
    chop.prnt("Anti SoftIce: %s" % params[i+32])
    chop.prnt("Anti Debugger: %s" % params[i+33])
    chop.prnt("Anti other: %s" % params[i+34])
    chop.prnt("USB spreader: %s" % params[i+35])
    chop.prnt("P2P spreader: %s" % params[i+36])
    chop.prnt("Rootkit: %s" % params[i+37])
    chop.prnt("\n\n")

def mainInfo(params, tcp):
    chop.tsprnt("*** Host Information ***")
    buf = params[1]

    while buf != "":
        i = 0
        while buf[i] == "\x00":
            i += 1
            if i >= len(buf):
                break
        buf = buf[i:]
        dat = buf[1:ord(buf[0])+1]
        buf = buf[ord(buf[0])+1:]
        chop.prnt(dat)
    chop.prnt("\n\n")

def processOutboundData(data, tcp):
    params = string.split(data, "|")
    module_data = tcp.module_data
    if (len(params) >= 5 and params[4] == "mainInfo"):
        mainInfo(params[4:], tcp)
    elif params[0] == "mainInfo":
        mainInfo(params, tcp)
    elif (len(params) >= 5 and params[4] == "configuracoesdoserver"):
        serverConfig(params[4:], tcp)
    elif params[0] == "configuracoesdoserver":
        serverConfig(params, tcp)
    elif (len(params) >= 5 and params[4] == "imgdesk") or params[0] == "imgdesk":
        if params[4] == "imgdesk":
            idx = 5
        else:
            idx = 1
        if params[idx][6:10] == "JFIF":
            params = string.split(data, "|", idx)
            chop.tsprnt("*** Screenshot Taken ***")
            if module_data['savefiles']:
                savefile = "SN-extracted-file-%d-screenshot.jpg" % module_data['sscnt']
                module_data['sscnt'] += 1
                chop.savefile(savefile, params[idx])
                chop.tsprnt("%s saved (%d bytes).." % (savefile, len(params[idx])))
    elif (len(params) >= 5 and params[4] == "listarprocessos"):
        listProcesses(params[11:], tcp)
    elif params[0] == "listarprocessos":
        listProcesses(params[7:], tcp)
    elif (len(params) >= 5 and params[4] == "listarservicos"):
        listServices(params[6], tcp)
    elif params[0] == "listarservicos":
        listServices(params[2], tcp)
    elif (len(params) >= 5 and params[4] == "listarjanelas"):
        listWindows(params[6:], tcp)
    elif params[0] == "listarjanelas":
        listWindows(params[2:], tcp)
    elif (len(params) >= 5 and params[4] == "listarportas"):
        listActivePorts(params[7:], tcp)
    elif params[0] == "listarportas":
        listActivePorts(params[3:], tcp)
    elif (len(params) >= 5 and params[4] == "listarprogramasinstalados"):
        listInstalled(params[6], tcp)
    elif params[0] == "listarprogramasinstalados":
        listInstalled(params[2], tcp)
    elif (len(params) >= 6 and params[5] == "listararquivos"):
        chop.tsprnt("*** Directory Listing Sent ***\nDirectory: %s" % params[6])
    elif params[1] == "listararquivos":
        chop.tsprnt("*** Directory Listing Sent ***\nDirectory: %s" % params[2])
    elif (len(params) >= 6 and params[5] == "listardrives"):
        listDrives(params[6:], tcp)
    elif params[1] == "listardrives":
        listDrives(params[2:], tcp)
    elif (len(params) >= 6 and params[5] == "download"):
        tcp.stream_data['server_buf_len'] = int(params[7])
        tcp.stream_data['outbound_filename'] = params[6][string.rfind(params[6], "\\")+1:]
        chop.tsprnt("*** Outbound File Transfer Initiated ***\nFile: %s" % params[6])
    elif params[1] == "download":
        tcp.stream_data['server_buf_len'] = int(params[3])
        tcp.stream_data['outbound_filename'] = params[2][string.rfind(params[2], "\\")+1:]
        chop.tsprnt("*** Outbound File Transfer Initiated ***\nFile: %s" % params[2])
    elif (len(params) >= 6 and params[5] == "upload"):
        if params[6] in module_data['inbound_files']:
            tcp.stream_data['inbound_filename'] = params[6][string.rfind(params[6], "\\")+1:]
            tcp.stream_data['client_buf_len'] = module_data['inbound_files'][params[6]]
    elif params[1] == "upload":
        if params[2] in module_data['inbound_files']:
            tcp.stream_data['inbound_filename'] = params[2][string.rfind(params[2], "\\")+1:]
            tcp.stream_data['client_buf_len'] = module_data['inbound_files'][params[2]]
    elif (len(params) >= 6 and params[5] == "obterclipboard"):
        chop.tsprnt("*** Clipboard Data Sent ***\nData: %s" % params[6])
    elif params[1] == "obterclipboard":
        chop.tsprnt("*** Clipboard Data Sent ***\nData: %s" % params[2])
    elif (len(params) >= 6 and params[5] == "obterclipboardfiles"):
        chop.tsprnt("*** Clipboard Data Sent ***\nFilename: %s" % params[6])
    elif params[1] == "obterclipboardfiles":
        chop.tsprnt("*** Clipboard Data Sent ***\nFilename: %s" % params[2])
    elif (len(params) >= 7 and params[6] == "keyloggerativar"):
        chop.tsprnt("*** Keylogger Activated ***")
    elif params[2] == "keyloggerativar":
        chop.tsprnt("*** Keylogger Activated ***")
    elif (len(params) >= 6 and params[5] == "keyloggergetlog"):
        chop.tsprnt("*** Keylogger Data Sent ***")
    elif params[1] == "keyloggergetlog":
        chop.tsprnt("*** Keylogger Data Sent ***")
    elif (len(params) >= 5 and params[4][:10] == "enviarexec"):
        tcp.stream_data['inbound_filename'] = params[1][string.rfind(params[1], "\\")+1:]
    elif params[0][:10] == "enviarexec":
        tcp.stream_data['inbound_filename'] = params[1][string.rfind(params[1], "\\")+1:]
    elif (len(params) >= 6 and params[5] == "shellresposta"):
        chop.tsprnt("*** Shell Session ***\n%s" % params[6])
    elif params[1] == "shellresposta":
        chop.tsprnt("*** Shell Session ***\n%s" % params[2])
    elif len(params) == 3 and params[1] == "Y":
        chop.tsprnt("*** Authentication ***\nPassword: %s" % params[0])
    else:
        chop.prnt("\n")
        for i in range(len(params)):
            chop.prnt("%d : %s" % (i,params[i]))

def decodeResponse(buf):
    alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
    var10 = 0
    edi = 0
    out = ""
    for i in range(len(buf)):
        c = buf[i]
        pos = string.find(alpha, c)
        if pos < 0:
            return None
        var10 = pos + (var10 << 6)
        edi += 6
        if edi >= 8:
            edi -= 8
            ebx = var10 >> edi
            ecx = 1 << edi
            var10 = int(var10 % ecx)
            out += chr(ebx)
    return out

def init(module_data):
    module_options = { 'proto': [ { 'tcp': '' } ] }
    parser = OptionParser()
    parser.add_option("-s", "--savefiles", action="store_true",
                      dest="savefiles", default=False, help="save carved files")
    parser.add_option("-v", "--verbose", action="store_true",
                      dest="verbose", default=False, help="verbosity")
    parser.add_option("-l", "--listings", action="store_true",
                      dest="listings", default=False, help="display file/registry/process/etc listings")
    parser.add_option("-d", "--debug", action="store_true",
                      dest="debug", default=False, help="debug")
    parser.add_option('-k', '--key', dest='key', default=False, help='the string used to build the encryption key (optional, a default key will be used if not provided)')

    (opts, lo) = parser.parse_args(module_data['args'])

    module_data['savefiles'] = opts.savefiles
    module_data['verbose'] = opts.verbose
    module_data['listings'] = opts.listings
    module_data['debug'] = opts.debug
    module_data['inbound_files'] = {}

    if module_data['verbose']:
        chop.prnt("Verbose output enabled.")
    if opts.key:
        module_data['key'] = opts.key
    else:
        module_data['key'] = "njkvenknvjebcddlaknvfdvjkfdskv"

    if module_data['savefiles']:
        chop.prnt("Carving enabled.")
    module_data['len_regex'] = r"^([0-9]+)\|\r?\n"
    module_data['sscnt'] = 1
    return module_options

def handleInbound(tcp):
    module_data = tcp.module_data
    if module_data['debug']:
        chop.tsprnt("%d inbound bytes" % tcp.client.count_new)

    if tcp.stream_data['client_buf_len'] > 0:
        tcp.stream_data['client_buf'] += tcp.client.data[:tcp.client.count_new]
        tcp.stream_data['client_buf_len'] -= tcp.client.count_new
        if module_data['verbose'] or module_data['debug']:
            if tcp.stream_data['inbound_filename'] != "":
                chop.tsprnt("collected %d inbound bytes for %s, %d to go" % (tcp.client.count_new, tcp.stream_data['inbound_filename'], tcp.stream_data['client_buf_len']))
            else:
                chop.tsprnt("collected %d inbound bytes, %d to go" % (tcp.client.count_new, tcp.stream_data['client_buf_len']))
    else:
        matched = re.match(module_data['len_regex'], tcp.client.data[:tcp.client.count_new])
        if matched:
            tcp.stream_data['client_buf_len'] = int(matched.group(1))
            if module_data['verbose'] or module_data['debug']:
                chop.tsprnt("%d inbound bytes designated" % int(matched.group(1)))

            if len(matched.group(0)) < tcp.client.count_new:
                tcp.stream_data['client_buf'] = tcp.client.data[len(matched.group(0)):tcp.client.count_new]
                tcp.stream_data['client_buf_len'] -= (tcp.client.count_new - len(matched.group(0)))
                if module_data['verbose'] or module_data['debug']:
                    chop.tsprnt("collected %d inbound bytes for decryption" % (tcp.client.count_new - len(matched.group(0))))

    if len(tcp.stream_data['client_buf']) > 0 and tcp.stream_data['client_buf_len'] <= 0:
        if tcp.stream_data['inbound_filename'] != "":
            if module_data['savefiles']:
                savefile = "SN-extracted-inbound-file-%d-%s" % (module_data['sscnt'], tcp.stream_data['inbound_filename'])
                module_data['sscnt'] += 1
                chop.savefile(savefile, tcp.stream_data['client_buf'])
                chop.tsprnt("%s saved.." % savefile)
            tcp.stream_data['inbound_filename'] = ""
        else:
            decompressed = None
            rc4 = ARC4.new(module_data['key'])
            decrypted = rc4.decrypt(tcp.stream_data['client_buf'])
            decompressed = checkZlib(decrypted)
            if decompressed != None:
                processInboundData(decompressed, tcp)
                if module_data['debug']:
                    chop.tsprnt("inbound decrypted/decompressed payload:\n%s" % hexdump(decompressed))
    elif tcp.stream_data['client_buf_len'] <= 0:
        data = tcp.client.data[:tcp.client.count_new]
        if data[-8:] == "###@@@\r\n":
            if data[:3] == "$$$":
                tcp.stream_data['client_buf_len'] = int(data[3:string.find(data,"|")])
                chop.tsprnt("*** Inbound File to be Executed ***\nFilename: %s" % tcp.stream_data['inbound_filename'])
            else:
                decoded = decodeResponse(data[:-8])
                if module_data['debug']:
                    chop.tsprnt("inbound decoded command: %s" % decoded)
                processInboundData(decoded, tcp)
    return

def handleOutbound(tcp):
    module_data = tcp.module_data
    if module_data['debug']:
        chop.tsprnt("%d outbound bytes" % tcp.server.count_new)

    if tcp.stream_data['server_buf_len'] > 0:
        tcp.stream_data['server_buf'] += tcp.server.data[:tcp.server.count_new]
        tcp.stream_data['server_buf_len'] -= tcp.server.count_new
        if module_data['verbose'] or module_data['debug']:
            chop.tsprnt("collected %d outbound bytes for decryption" % tcp.server.count_new)

    else:
        matched = re.match(module_data['len_regex'], tcp.server.data[:tcp.server.count_new])
        if matched:
            tcp.stream_data['server_buf_len'] = int(matched.group(1))
            if module_data['verbose'] or module_data['debug']:
                chop.tsprnt("%d outbound bytes designated" % int(matched.group(1)))

            if len(matched.group(0)) < tcp.server.count_new:
                tcp.stream_data['server_buf'] = tcp.server.data[len(matched.group(0)):tcp.server.count_new]
                tcp.stream_data['server_buf_len'] -= (tcp.server.count_new - len(matched.group(0)))
                if module_data['verbose'] or module_data['debug']:
                    chop.tsprnt("collected %d outbound bytes for decryption" % (tcp.server.count_new - len(matched.group(0))))

    if len(tcp.stream_data['server_buf']) > 0 and tcp.stream_data['server_buf_len'] <= 0:
        if tcp.stream_data['outbound_filename'] != "":
            if module_data['savefiles']:
                savefile = "SN-extracted-outbound-file-%d-%s" % (module_data['sscnt'], tcp.stream_data['outbound_filename'])
                module_data['sscnt'] += 1
                chop.savefile(savefile, tcp.stream_data['server_buf'])
                chop.tsprnt("%s saved.." % savefile)
            tcp.stream_data['outbound_filename'] = ""
        else:
            rc4 = ARC4.new(module_data['key'])
            decrypted = rc4.decrypt(tcp.stream_data['server_buf'])
            decompressed = checkZlib(decrypted)
            if decompressed != None:
                if decompressed[6:10] == "JFIF":
                    chop.tsprnt("*** Remote Desktop Session Ongoing ***")
                    if module_data['savefiles']:
                        savefile = "SN-extracted-file-%d-remote-desktop-screen.jpg" % module_data['sscnt']
                        module_data['sscnt'] += 1
                        chop.savefile(savefile, decompressed)
                        chop.tsprnt("%s saved.." % savefile)
                else:
                    processOutboundData(decompressed, tcp)
                    if module_data['debug']:
                        chop.tsprnt("outbound decrypted/decompressed payload:\n%s" % hexdump(decompressed))
            else:
                chop.tsprnt("could not find zlib header in decrypted data")

        tcp.stream_data['server_buf'] = ''
    return

def checkZlib(data):
    decompressed = None
    j = 0
    while j < 32 and j < len(data):
        try:
            (b0, b1) = struct.unpack('BB', data[j:j+2])
        except struct.error as e:
            chop.prnt(e)
            break

        # look for possible zlib header, but only
        # if the FDICT flag is not set
        if ((b0 * 256 + b1) % 31 == 0 and
            b1 & 0x20 == 0x00 and
            b0 & 0x0F == 0x08 and
            b0 >> 4 <= 7):
            zlibofs = j
            wbits = ((b0 >> 4) & 0x0F) + 8
            compressed = data[zlibofs:]
            decompressed = zlib.decompress(compressed, wbits)
            break
        j += 1

    return decompressed

def handleStream(tcp):
    module_data = tcp.module_data
    if tcp.client.count_new > 0:
        handleInbound(tcp)
        tcp.discard(tcp.client.count_new)
    elif tcp.server.count_new > 0:
        handleOutbound(tcp)
        tcp.discard(tcp.server.count_new)
    return

def taste(tcp):
    tcp.stream_data['client_buf'] = ''
    tcp.stream_data['client_buf_len'] = 0
    tcp.stream_data['server_buf'] = ''
    tcp.stream_data['server_buf_len'] = 0
    tcp.stream_data['outbound_filename'] = ""
    tcp.stream_data['inbound_filename'] = ""
    return True

def teardown(tcp):
    pass

def module_info():
    return "Decrypt and display Spy-Net 2.6 outbound data"

def shutdown(module_data):
    pass