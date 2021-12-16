# Copyright (c) 2014 Palo Alto Networks. All rights reserved.
# Copyright (c) 2021 The MITRE Corporation. All rights reserved.
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

"""
Program to decode netwire traffic based on the initial exchange of keys.

"""
import argparse
import binascii
import struct
import base64
import urllib
import copy

from Crypto.Cipher import AES

# chopshop ext_libs
import c2utils
from c2Event import Event


moduleName = "netwire"
moduleVersion = "0.5"
minimumChopLib = "4.0"
author = "unit 42; MITRE"

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

CLIENT="client"
SERVER="server"


class CmdState(object):
    def __init__(self, dlen=0, opcode=None, timestamp=None, sender=None):
        self.dlen = dlen
        self.opcode = opcode
        self.ts = timestamp
        self.sender = sender

    def clear(self):
        """
        Clear the state for reuse, which is quicker than creating a new object.
        """
        self.dlen = 0
        self.opcode = None
        self.ts = None


def create_key ( password, seed ):
    ## seed is assumed to be hex
    flip = ''
    result = ''

    # This will flip the lower and upper order nibbles
    for i in password:
        i_bin = binascii.hexlify(i)
        tmp = i_bin[1] + i_bin[0]
        flip += tmp

    result += binascii.unhexlify(flip)

    for i in xrange(len(password), 32):
        tmp = i >> 5 | i * 8
        tmp = tmp & i
        result += chr(tmp)

    a1 = ord(result[len(password) >> 2]) ^ len(password)

    for i in xrange(0, 32):
        v4 = ord(result[i]) ^ ord(seed[i])
        v10 = a1 ^ v4
        v10 = v10 & 0xFF

        v11 = 4 * v10

        #only the low byte gets changed below
        v11 = ord( seed[i] ) ^ ( 4 * v10 )

        a1 = ~v11 & 0xFFF

        v4 = (i ^ (i + len(password))) | (v10 >> 5) | (8 * v10)
        v4 = v4 & 0xFF
        v4 = hex(v4)[2:].zfill(2)
        v4 = binascii.unhexlify(v4)

        pieces = list(result)
        pieces[i] = str(v4)
        result = "".join(pieces)

    return result


def encrypt( raw, key, iv ):
    """
    Encrypt the raw data using the provided key and initial IV.  Data will be 
    encrypted using AES OFB mode.
    
    Args:
        raw: plaintext data to be encrypted
        key: AES key used for encryption
        iv: Initial IV used for encryption
    """
    result = ''
    tmp_iv = iv 
    text = pad(raw)

    for i in xrange(0, len(text) / BS):
        lower_bound = i * 16
        upper_bound = (i+1) * 16
        
        tmp = AES.new(key, AES.MODE_OFB, tmp_iv).decrypt( text[lower_bound:upper_bound] )
        tmp_iv = tmp
        result += tmp

    return result


def decrypt( raw, key, iv ):
    """
    Decrypt the raw data using the provided key and iv.  
    Netwire encrypts data using AES OFB mode.  Initial IV is sent in the key exchange
    packet.  This iv will decrypt the initial block of 16 bytes of data, each 
    subsequent block will use the previous block as an IV.
    
    Args:
        raw: raw data to be decrypted
        key: AES key used to decrypt the data
        iv: initial IV used for decryption
    """
    result = ''
    tmp_iv = iv
    rlen = len(raw)
    ciphertext = pad(raw)

    for i in xrange(0, len(ciphertext) / BS):
        lower_bound = i * 16
        upper_bound = (i+1) * 16
        
        tmp = AES.new(key, AES.MODE_OFB, tmp_iv).decrypt( ciphertext[lower_bound:upper_bound] )
        tmp_iv = ciphertext[lower_bound:upper_bound]
        result += tmp

    return result[:rlen]


def command_conversion(dest, command, payload, command_list):
    """
    Convert the command info (if known).
    http://www.circl.lu/pub/tr-23/
    Args:
        dest: a string containing either 'server' or 'client' to dictate which direction the packet is going.
        command: hex string of the command byte
        payload: hest string of the packet payload data
    
    """
    decoded_text = ''
    
    command_string = binascii.hexlify(chr(command)).upper()
    
    if command_list.has_key(command_string):
        decoded_text = command_list[command_string]
    else:
        decoded_text = ''
    
    return decoded_text, payload


def decode_command(dest, command, payload, command_list):
    """
    Print out the command info response from command_conversion.
    Args:
        dest: a string containing either 'server' or 'client' to dictate which direction the packet is going.
        command: hex string of the command byte
        payload: hest string of the packet payload data
    
    """
    decoded_text, payload = command_conversion(dest, command, payload, command_list)
    
    # convert to character since hexlify expects string
    command = chr(command)
    if (dest == SERVER):
        chop.tsprnt('client -> server :: %s (%s)' % (binascii.hexlify(command), decoded_text))
        #Payload: %r \n' % ( payload ))
        chop.prnt(c2utils.hexdump(payload, spaces=4, show_offset=True))
    else:
        chop.tsprnt('server -> client :: %s (%s)' % (binascii.hexlify(command), decoded_text))
        chop.prnt(c2utils.hexdump(payload, spaces=4, show_offset=True))


def data_split_07(data):
    """
    Payloads are sometimes internally field-delimited by byte 0x07
    """
    return data.strip("\x07").split("\x07")


def op_register_server(data, tcp, dgram):
    dlen = len(data)
    if dlen < 48:
        chop.tsprnt("WARN: register payload length ({}) less than expected (48)".format(dlen))
        return dlen
    server_seed = data[:32]
    server_iv = data[32:48]
    server_key = create_key(tcp.module_data['password'], server_seed)
    hex_seed = binascii.hexlify(server_seed)
    hex_iv = binascii.hexlify(server_iv)
    hex_key = binascii.hexlify(server_key)
    chop.tsprnt("Server seed: %s" % hex_seed)
    chop.tsprnt("Server iv:   %s" % hex_iv)
    chop.tsprnt("Server key:  %s" % hex_key)

    tcp.stream_data['server_key'] = server_key
    tcp.stream_data['server_iv'] = server_iv

    chop.tsprnt("Server Key Generated")
    chop.tsprnt('')

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.controller
    ev.type = Event.Types.crypto
    ev.subtype = Event.Types.crypto.negotiate
    ev.data = base64.b64encode(data)
    ev.encoding = Event.Encodings.base64
    d = {"opcode": hex(dgram.opcode), "seed": hex_seed, "iv": hex_iv, "key": hex_key}
    d.update(ev.dict())
    chop.tsjson(d)

    return dlen


def op_register_client(data, tcp, dgram):
    dlen = len(data)
    if dlen < 48:
        chop.tsprnt("WARN: register payload length ({}) less than expected (48)".format(dlen))
        return dlen
    client_seed = data[:32]
    hex_seed = binascii.hexlify(client_seed)
    client_iv = data[32:48]
    hex_iv = binascii.hexlify(client_iv)
    client_key = create_key(tcp.module_data['password'], client_seed)
    hex_key = binascii.hexlify(client_key)
    chop.tsprnt("Client seed: %s" % hex_seed)
    chop.tsprnt("Client iv:   %s" % hex_iv)
    chop.tsprnt("client key:  %s" % hex_key)

    tcp.stream_data['client_key'] = client_key
    tcp.stream_data['client_iv'] = client_iv

    chop.tsprnt('Client Key Generated')
    chop.tsprnt('')

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.implant
    ev.type = Event.Types.crypto
    ev.subtype = Event.Types.crypto.negotiate
    ev.data = base64.b64encode(data)
    ev.encoding = Event.Encodings.base64
    d = {"opcode": hex(dgram.opcode), "seed": hex_seed, "iv": hex_iv, "key": hex_key}
    d.update(ev.dict())
    chop.tsjson(d)

    return dlen


def op_unknown(data, tcp, sender='unknown', dgram=None):

    ev = Event(tcp.addr, moduleName)
    ev.sender = sender
    ev.type = Event.Types.unknown
    ev.data = binascii.hexlify(data)
    ev.encoding = Event.Encodings.hex
    d = {"opcode": hex(dgram.opcode), "dlen": len(data)}
    d.update(ev.dict())
    chop.tsjson(d)


def op_sysinfo(data, tcp, dgram):

    hex_unk0 = binascii.hexlify(data[0])
    hex_unk1 = binascii.hexlify(data[1:9])
    msg = urllib.quote(data[9:])

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.implant
    ev.type = Event.Types.sysinfo
    ev.data = msg
    ev.encoding = Event.Encodings.url
    d = {"opcode": hex(dgram.opcode), "unknown0": hex_unk0, "unknown1": hex_unk1}
    d.update(ev.dict())
    chop.tsjson(d)

    #chop.prnt(c2utils.hexdump(data))
    chop.tsprnt("unknown0: {}  unknown1: {}".format(hex_unk0, hex_unk1))
    chop.tsprnt("System info: %s" % msg)
    chop.prnt('')


def op_heartbeat_req(data, tcp, dgram):

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.controller
    ev.type = Event.Types.keepalive
    d = {"opcode": hex(dgram.opcode),}
    d.update(ev.dict())
    chop.tsjson(d)

    #chop.prnt(c2utils.hexdump(data))
    chop.tsprnt("Heartbeat (controller)")
    chop.prnt('')


def op_heartbeat_resp(data, tcp, dgram):

    msg = urllib.quote(data)

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.implant
    ev.type = Event.Types.keepalive
    ev.data = msg
    ev.encoding = Event.Encodings.url
    d = {"opcode": hex(dgram.opcode),}
    d.update(ev.dict())
    chop.tsjson(d)

    #chop.prnt(c2utils.hexdump(data))
    chop.tsprnt("Heartbeat (implant): %s" % msg)
    chop.prnt('')


def op_screenshot_req(data, tcp, dgram):

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.controller
    ev.type = Event.Types.monitor
    ev.subtype = Event.Types.monitor.screencap
    d = {"opcode": hex(dgram.opcode),}
    d.update(ev.dict())
    chop.tsjson(d)
    chop.tsprnt("CONTROLLER :: requesting screenshot")


def op_screenshot_start(data, tcp, dgram):
    if not tcp.module_data["savefiles"]:
        # don't do any of this if we aren't carving
        return
    # reset screenshot payload
    if 'screenshot' not in tcp.stream_data:
        tcp.stream_data['screenshot'] = dict()
    tcp.stream_data["screenshot"]["data"] = b""
    # payload is ASCII-encoded file size
    num_bytes_needed = int(data.decode('ascii'))
    tcp.stream_data['screenshot']["size"] = num_bytes_needed
    # TIMESTAMP-SRC-DST-screenshot.bin
    tcp.stream_data['screenshot']["fname"] = mkfilename("screenshot.bin", tcp)


def op_screenshot_end(data, tcp, dgram):
    # if buffered data, then write it out to disk

    if tcp.module_data["savefiles"] and "screenshot" in tcp.stream_data:
        ss = tcp.stream_data["screenshot"]
        if "size" in ss and "data" in ss and ss["size"] > 0 and ss["data"]:
            fname = ss["fname"]
            chop.tsprnt("IMPLANT :: end of screenshot data - {} bytes".format(ss["size"]))
            chop.tsprnt("Screenshot saved to: '%s'" % fname)
            chop.savefile(fname, ss["data"])
            d = {"opcode": hex(dgram.opcode), "saved_to": ss["fname"], "size": ss["size"] }
        else:
            chop.tsprnt("IMPLANT :: unexpected end of screenshot data")
            d = {"opcode": hex(dgram.opcode)}
        # reset buffer
        ss["size"] = 0
        ss["data"] = b""
        ss["fname"] = None
    else:
        # carving not enabled
        chop.tsprnt("IMPLANT :: end of screenshot data")
        d = {"opcode": hex(dgram.opcode)}

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.implant
    ev.type = Event.Types.monitor
    ev.subtype = Event.Types.monitor.screencap
    d.update(ev.dict())
    chop.tsjson(d)


def op_screenshot_data(data, tcp, dgram):
    if not tcp.module_data["savefiles"]:
        return
    dlen = len(data)
    if dlen <= 0:
        return 0

    # add to buffered screenshot data
    if "screenshot" in tcp.stream_data:
        ss = tcp.stream_data["screenshot"]
        if "size" in ss and "data" in ss and ss["size"] > 0:
            ss["data"] += data


def op_drives_req(data, tcp, dgram):
    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.controller
    ev.type = Event.Types.filesystem
    ev.subtype = Event.Types.filesystem.enumerate_drives
    d = {"opcode": hex(dgram.opcode),}
    d.update(ev.dict())
    chop.tsjson(d)


class DrivesInfo(object):
    def __init__(self, data):
        self.drives = list()
        if not data or len(data) < 2:
            return
        data_list = data_split_07(data)
        for item in data_list:
            if not item or len(item) < 2:
                continue
            entry = dict()
            entry["name"] = item[:-1]
            entry["type"] = hex(ord(item[-1]))
            self.drives.append(entry)

    def to_list(self):
        return copy.deepcopy(self.drives)


def op_drives_resp(data, tcp, dgram):
    # data is a simple array, split on \x07
    # last byte of item is a type indicator?
    # item[0:-1] is ASCII string
    #
    # EXAMPLE: C:\x04\x07D:\x06\x07Z:\x05\x07

    o = DrivesInfo(data)

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.implant
    ev.type = Event.Types.filesystem
    ev.subtype = Event.Types.filesystem.enumerate_drives
    d = { "opcode": hex(dgram.opcode), "drives": o.to_list() }
    d.update(ev.dict())
    chop.tsjson(d)
    chop.tsprnt("IMPLANT - drive list ({}) - NAME   TYPE".format(dgram.opcode))
    for item in o.to_list():
        chop.prnt("    %s   %s" % (item["name"], item["type"]))


def op_dir_req(data, tcp, dgram):
    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.controller
    ev.type = Event.Types.filesystem
    ev.subtype = Event.Types.filesystem.dir
    ev.data = data
    d = { "opcode": hex(dgram.opcode) }
    d.update(ev.dict())
    chop.tsjson(d)
    chop.tsprnt("CONTROLLER :: dir - '%s'" % data)


class DirInfo(object):
    def __init__(self, data):
        self.entries = list()
        if not data or len(data) < 1:
            return
        data_list = data_split_07(data)
        list_len = len(data_list)
        i=0
        while i < len(data_list):
            dwFileAttributes = int(data_list[i])
            if dwFileAttributes & 0x10 > 0:
                # dir - attr name datetime
                name = data_list[i+1]
                size = ""
                timestamp = data_list[i+2]
                i += 3
            else:
                # file - attr name size datetime
                name = data_list[i+1]
                size = data_list[i+2]
                timestamp = data_list[i+3]
                i += 4
            item = "%8x   %20s   %20s   %s" % (dwFileAttributes, timestamp, size, name)
            self.entries.append(item)

    def to_list(self):
        return copy.deepcopy(self.entries)


def op_dir_resp(data, tcp, dgram):
    # Data is a simple ascii string array, split on \x07
    # Directory entries are triples, file entries are quads
    # First item in entry is(?) a WIN32_FIND_DATAA dwFileAttributes
    #   - bit 0x10 indicates dir, otherwise file

    o = DirInfo(data)

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.implant
    ev.type = Event.Types.filesystem
    ev.subtype = Event.Types.filesystem.dir
    d = { "opcode": hex(dgram.opcode), "entries": o.to_list() }
    d.update(ev.dict())
    chop.tsjson(d)
    chop.tsprnt("IMPLANT :: dir response")
    for item in o.entries:
        chop.prnt("    %s" % item)


def op_mkdir_req(data, tcp, dgram):
    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.controller
    ev.type = Event.Types.filesystem
    ev.subtype = Event.Types.filesystem.mkdir
    ev.data = data
    d = { "opcode": hex(dgram.opcode) }
    d.update(ev.dict())
    chop.tsjson(d)
    chop.tsprnt("CONTROLLER :: mkdir - '%s'" % data)


def op_mkdir_resp(data, tcp, dgram):
    # response is simply the directory created

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.implant
    ev.type = Event.Types.filesystem
    ev.subtype = Event.Types.filesystem.mkdir
    ev.data = data
    d = { "opcode": hex(dgram.opcode) }
    d.update(ev.dict())
    chop.tsjson(d)
    chop.tsprnt("IMPLANT :: mkdir response - '%s'" % data)


def op_putfile_start(data, tcp, dgram):

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.controller
    ev.type = Event.Types.file_transfer
    ev.subtype = Event.Types.file_transfer.put
    ev.data = urllib.quote(data)
    ev.encoding = Event.Encodings.url
    d = {"opcode": hex(dgram.opcode)}
    d.update(ev.dict())
    chop.tsjson(d)
    chop.tsprnt("CONTROLLER :: PUT file - '{}'".format(ev.data))

    if not tcp.module_data["savefiles"]:
        return
    # reset putfile payload
    if 'putfile' not in tcp.stream_data:
        tcp.stream_data['putfile'] = dict()
    tcp.stream_data["putfile"]["data"] = b""
    # payload is ASCII-encoded file size
    tcp.stream_data['putfile']["size"] = 0
    # TIMESTAMP-SRC-DST-screenshot.bin
    tcp.stream_data['putfile']["fname"] = mkfilename("putfile.bin", tcp)


def op_putfile_resp(data, tcp, dgram):

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.implant
    ev.type = Event.Types.file_transfer
    ev.subtype = Event.Types.file_transfer.put
    ev.data = urllib.quote(data)
    ev.encoding = Event.Encodings.url
    d = {"opcode": hex(dgram.opcode)}
    d.update(ev.dict())
    chop.tsjson(d)


def op_putfile_data(data, tcp, dgram):
    if not tcp.module_data["savefiles"] or not data:
        return
    dlen = len(data)
    if dlen <= 0:
        return

    # add to buffered data
    if "putfile" in tcp.stream_data:
        pf = tcp.stream_data["putfile"]
        if "data" in pf and ( pf["size"] > 0 or len(pf["data"]) > 0 ):
            pf["data"] += data
            pf["size"] += dlen
        else:
            pf["data"] = data[1:]
            pf["size"] = dlen - 1


def op_putfile_end(data, tcp, dgram):
    # if buffered data, then write it out to disk
    if tcp.module_data["savefiles"] and "putfile" in tcp.stream_data:
        pf = tcp.stream_data["putfile"]
        if "size" in pf and "data" in pf and pf["size"] > 0 and pf["data"]:
            fname = pf["fname"]
            chop.tsprnt("CONTROLLER :: PUT file complete - {} bytes".format(pf["size"]))
            chop.tsprnt("File saved to: '%s'" % fname)
            chop.savefile(fname, pf["data"])
            d = {"opcode": hex(dgram.opcode), "saved_to": pf["fname"], "size": pf["size"] }
        else:
            d = {"opcode": hex(dgram.opcode)}
            chop.tsprnt("CONTROLLER :: unexpected PUT file complete")
        # reset buffer
        pf["size"] = 0
        pf["data"] = b""
        pf["fname"] = None
    else:
        d = {"opcode": hex(dgram.opcode)}
        chop.tsprnt("CONTROLLER :: PUT file complete")

    ev = Event(tcp.addr, moduleName)
    ev.sender = Event.implant
    ev.type = Event.Types.file_transfer
    ev.subtype = Event.Types.file_transfer.put
    d.update(ev.dict())
    chop.tsjson(d)


def mkfilename(filename, tcp):
    ts = int(tcp.timestamp)
    isodt = str(c2utils.packet_time(ts, date=True, utc=True, isodate=True)).replace(" ", "_")
    ((src,sport), (dst,dport)) = tcp.addr
    addr = "%s-%d-%s-%d" % (src,sport,dst,dport)
    return "%s-%s-%s" % (isodt, addr, filename)


def module_info():
    return "A module to dump decoded netwire packet payloads from a stream.  Meant to be used to decode traffic from that Remote Administration Tool (RAT)."


def init(module_data):
    module_options = { 'proto': [{'tcp': ''}] }

    parser = argparse.ArgumentParser(description="A module to dump decoded netwire packet payloads from a stream.  Meant to be used to decode traffic from that Remote Administration Tool (RAT).")
    parser.add_argument("--savefiles", "-s", dest="savefiles", default=False, action="store_true")
    parser.add_argument("-P", "--password", default="Password", dest="password")
    opts = parser.parse_args(module_data['args'])
    module_data['password'] = opts.password
    module_data['savefiles'] = opts.savefiles

    # NOTE: these opcode values can and have changed between versions, but the
    # underlying functionality has remained consistent.
    module_data['commands'] = {
        "97": "heartbeat",
        "98": "Socket created",
        "99": "registered",
        "9A": "setting password failed",
        "9B": "set password, identifier and fetch computer information such as user, computername, windows version",
        "9C": "create process from local file or fetch from URL first and create process",
        "9D": "create process from local file and exit",
        "9E": "failed to create process",
        "9F": "stop running threads, cleanup, exit",
        "A0": "stop running threads, cleanup, sleep",
        "A1": "stop running threads, delete autostart registry keys, cleanup, exit",
        "A2": "add identifier, IE .Identifier file",
        "A3": "Download file over HTTP to TEMP and execute",
        "A4": "fetch and send logical drives and types",
        "A5": "Failed to obtain logical drive info",
        "A6": "locate and send file with time, attributes and size",
        "A8": "find file",
        "A9": "file information",
        "AA": "unset tid for 0x12",
        "AA": "file not found",
        "AB": "send file",
        "AC": "write into file",
        "AD": "close file",
        "AE": "copy file",
        "AF": "execute file",
        "B0": "move file",
        "B1": "delete file",
        "B2": "create directory",
        "B3": "file copy",
        "B4": "create directory or send file to server",
        "B5": "close file",
        "B6": "start remote shell",
        "B7": "write into WritePipe",
        "B8": "reset tid for remote shell",
        "B8": "terminated remote shell",
        "B9": "failed to start remote shell",
        "BA": "collect client information and configuration",
        "BB": "failed to get client information and configuration",
        "BC": "get logged on users",
        "BC": "send logged on users",
        "BD": "failed to send logged on users",
        "BE": "get detailed process information",
        "BF": "failed to get detailed process information",
        "C0": "terminate process",
        "C1": "enumerate windows",
        "C1": "send windows",
        "C2": "make window visible, invisible or show text",
        "C3": "get file over HTTP and execute",
        "C4": "HTTP connect failed",
        "C5": "set keyboard event 'keyup'",
        "C6": "set keyboard event $event",
        "C7": "set mouse button press",
        "C8": "set cursor position",
        "C9": "take screenshot and send",
        "CB": "failed to take screenshot",
        "CA": "screenshot data",
        "CC": "locate and send file from log directory with time, attributes and size",
        "CE": "check if log file exists",
        "CF": "delete logfile",
        "D0": "read key log file and send",
        "D2": "failed to read key log file",
        "D3": "fetch and send stored credentials, history and certificates from common browsers",
        "D4": "fetch and send stored credentials, history and certificates from common browsers",
        "D5": "fetch and send chat Windows Live, Pidgin credentials",
        "D6": "fetch and send chat Windows Live, Pidgin credentials",
        "D7": "fetch and send mail Outlook, Thunderbird credentials and certificates",
        "D8": "fetch and send mail Outlook, Thunderbird credentials and certificates",
        "D9": "socks_proxy",
        "DA": "get audio devices and formats",
        "DA": "audio devices and formats",
        "DB": "failed to get audio devices",
        "DC": "start audio recording",
        "DD": "error during recording",
        "DE": "stop audio recording",
        "DF": "find file get md5",
        "E2": "unset tid for find file get md5",
        "80": "continuation of file download",
        "78": "continuation of response"
    }
    module_data['server_handlers'] = {
        0x97: op_heartbeat_req,
        0x9b: op_register_server,
        0xa4: op_drives_req,
        0xa6: op_dir_req,
        0xab: op_putfile_start,
        0xac: op_putfile_data,
        0xad: op_putfile_end,
        0xb2: op_mkdir_req,
        0xc9: op_screenshot_req,
    }  # opcode : data processing function
    module_data['client_handlers'] = {
        0x97: op_heartbeat_resp,
        0x99: op_register_client,
        0x9b: op_sysinfo,
        0xa4: op_drives_resp,
        0xa6: op_dir_resp,
        0xab: op_putfile_resp,
        0xb2: op_mkdir_resp,
        0xc9: op_screenshot_start,
        0xca: op_screenshot_data,
        0xcb: op_screenshot_end,
    }  # opcode : data processing function

    return module_options


def _post_process(dgram, tcp):
    tcp.discard(4 + dgram.dlen)
    dgram.clear()


def handleStream(tcp):
  #chop.tsprnt('--------------------------------')
  """
  Process given TCP packet, guaranteed to be in stream-order, not arrival order.

  NOTE: the below logic assumes a new dgram starts in a new packet, not in the
  middle of a packet.
  """

  ((sip, sport), (dip, dport)) = tcp.addr

  if tcp.client.count_new:
    dgram = tcp.stream_data[CLIENT]
    available_len = tcp.client.count - tcp.client.offset
    # header = int32 dlen, int8 opcode
    if available_len < 5:
        # not enough data
        #chop.tsprnt("Need more data from client")
        # this is needed to indicate we do not want to discard any data yet
        tcp.discard(0)
        return
    # don't process datagram header again if we don't have to
    if not dgram.dlen:
        dgram.dlen = struct.unpack('<I', tcp.client.data[0:4])[0]
        dgram.opcode = ord(tcp.client.data[4])
        dgram.ts = tcp.timestamp
    # dlen includes opcode byte, so +4 instead of +5
    if available_len < dgram.dlen + 4:
        # not enough data
        #chop.tsprnt("Need more data from client (opcode:{}), again (got:{}  need:{})".format(hex(dgram.opcode), available_len, dgram.dlen+4))
        # this is needed to indicate we do not want to discard any data yet
        tcp.discard(0)
        return

    #chop.tsprnt("{}:{} -> {}:{} - SERVER opcode:{} dlen:{}".format(sip, sport, dip, dport, hex(dgram.opcode), dgram.dlen))

    if 'server_key' in tcp.stream_data:
        # dlen includes opcode byte, so only grab after opcode
        payload = decrypt(tcp.client.data[5:dgram.dlen+4], tcp.stream_data['server_key'], tcp.stream_data['client_iv'])
    else:
        # dlen includes opcode byte, so only grab after opcode
        payload = tcp.client.data[5:dgram.dlen+4]

    # if we have a function handler for this opcode
    if dgram.opcode in tcp.module_data["server_handlers"]:
        op_func = tcp.module_data["server_handlers"][dgram.opcode]
        # call it
        op_func(payload, tcp, dgram)
    elif 'server_key' not in tcp.stream_data:
        chop.tsprnt('Skipping')
    else:
        op_unknown(payload, tcp, sender=Event.controller, dgram=dgram)
        # dlen includes opcode byte, so dlen=1 means no payload
        if dgram.dlen == 1:
            decode_command(CLIENT, dgram.opcode, b"", tcp.module_data['commands'])
        else:
            decode_command(CLIENT, dgram.opcode, payload, tcp.module_data['commands'])

    # clear state, discard
    _post_process(dgram, tcp)
    return

  if tcp.server.count_new:
    dgram = tcp.stream_data[SERVER]
    available_len = tcp.server.count - tcp.server.offset #len(tcp.server.data)
    # header = int32 dlen, int8 opcode
    if available_len < 5:
        # not enough data
        #chop.tsprnt("Need more data from server")
        # this is needed to indicate we do not want to discard any data yet
        tcp.discard(0)
        return
    # don't process datagram header again if we don't have to
    if not dgram.dlen:
        dgram.dlen = struct.unpack('<I', tcp.server.data[0:4])[0]
        dgram.opcode = ord(tcp.server.data[4])
        dgram.ts = tcp.timestamp
    # dlen includes opcode byte, so +4 instead of +5
    if available_len < dgram.dlen + 4:
        # not enough data
        #chop.tsprnt("Need more data from server (opcode:{}), again (got:{}  need:{})".format(hex(dgram.opcode), available_len, dgram.dlen+4))
        # this is needed to indicate we do not want to discard any data yet
        tcp.discard(0)
        return

    #chop.tsprnt("{}:{} -> {}:{} - CLIENT opcode:{} dlen:{}".format(sip, sport, dip, dport, hex(dgram.opcode), dgram.dlen))

    if 'client_key' in tcp.stream_data:
        # dlen includes opcode byte, so only grab after opcode
        payload = decrypt(tcp.server.data[5:dgram.dlen+4], tcp.stream_data['client_key'], tcp.stream_data['client_iv'])
    else:
        # dlen includes opcode byte, so only grab after opcode
        payload = tcp.server.data[5:dgram.dlen+4]

    # if we have a function handler for this opcode
    if dgram.opcode in tcp.module_data["client_handlers"]:
        op_func = tcp.module_data["client_handlers"][dgram.opcode]
        # call it
        op_func(payload, tcp, dgram)
    elif 'client_key' not in tcp.stream_data:
        chop.tsprnt('Skipping')
    else:
        op_unknown(payload, tcp, sender=Event.implant, dgram=dgram)
        # dlen includes opcode byte, so dlen=1 means no payload
        if dgram.dlen == 1:
            decode_command(SERVER, dgram.opcode, b"", tcp.module_data['commands'])
        else:
            decode_command(SERVER, dgram.opcode, payload, tcp.module_data['commands'])

    # clear state, discard
    _post_process(dgram, tcp)
    return


def shutdown(module_data):
    return


def taste(tcp):
    tcp.stream_data[CLIENT] = CmdState(sender=Event.controller)
    tcp.stream_data[SERVER] = CmdState(sender=Event.implant)
    return True


def teardown(tcp):
    return
