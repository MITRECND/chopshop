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

# The purpose of this chopshop module is to decode commands and responses
# for Gh0st backboors.
#
# The typical format for a Gh0st packet is:
# <flag><compressed_size><uncompressed_size><zlib payload>
#
# - flag is a 5 character string
# - compressed size is the size of the entire packet, not just zlib payload
# - uncompressed size of zlib payload
# - zlib payload consists of zlib header ('\x78\x9c') and compressed payload

import zlib
import struct
import binascii
import os
import ntpath
from optparse import OptionParser
from c2utils import sanitize_filename, parse_addr, winsizeize, hexdump

moduleName = "gh0st_decode"

def init(module_data):
    parser = OptionParser()
    parser.add_option("-s", "--savefiles", action="store_true",
                      dest="savefiles", default=False, help="save carved files")
    parser.add_option("-w", "--wsize", action="store", dest="wsize",
                      default=20, help="window size")
    parser.add_option("-v", "--verbose", action="store_true",
                      dest="verbose", default=False, help="verbosity")

    (opts, lo) = parser.parse_args(module_data['args'])

    module_data['savefiles'] = opts.savefiles
    module_data['verbose'] = opts.verbose
    module_data['wsize'] = opts.wsize
    module_data['tokens'] = {
                              '\x00': command_actived,
                              '\x01': command_list_drive,
                              '\x02': command_list_files,
                              '\x03': command_down_files,
                              '\x04': command_file_size,
                              '\x05': command_file_data,
                              '\x06': command_exception,
                              '\x07': command_continue,
                              '\x08': command_stop,
                              '\x09': command_delete_file,
                              '\x0a': command_delete_directory,
                              '\x0b': command_set_transfer_mode,
                              '\x0c': command_create_folder,
                              '\x0d': command_rename_file,
                              '\x0e': command_open_file_show,
                              '\x0f': command_open_file_hide,
                              '\x10': command_screen_spy,
                              '\x11': command_screen_reset,
                              '\x12': command_algorithm_reset,
                              '\x13': command_screen_ctrl_alt_del,
                              '\x14': command_screen_control,
                              '\x15': command_screen_block_input,
                              '\x16': command_screen_blank,
                              '\x17': command_screen_capture_layer,
                              '\x18': command_screen_get_clipboard,
                              '\x19': command_screen_set_clipboard,
                              '\x1a': command_webcam,
                              '\x1b': command_webcam_enablecompress,
                              '\x1c': command_webcam_disablecompress,
                              '\x1d': command_webcam_resize,
                              '\x1e': command_next,
                              '\x1f': command_keyboard,
                              '\x20': command_keyboard_offline,
                              '\x21': command_keyboard_clear,
                              '\x22': command_audio,
                              '\x23': command_system,
                              '\x24': command_pslist,
                              '\x25': command_wslist,
                              '\x26': command_dialupass,
                              '\x27': command_killprocess,
                              '\x28': command_shell,
                              '\x29': command_session,
                              '\x2a': command_remove,
                              '\x2b': command_down_exec,
                              '\x2c': command_update_server,
                              '\x2d': command_clean_event,
                              '\x2e': command_open_url_hide,
                              '\x2f': command_open_url_show,
                              '\x30': command_rename_remark,
                              '\x31': command_replay_heartbeat,
                              '\x64': token_auth,
                              '\x65': token_heartbeat,
                              '\x66': token_login,
                              '\x67': token_drive_list,
                              '\x68': token_file_list,
                              '\x69': token_file_size,
                              '\x6a': token_file_data,
                              '\x6b': token_transfer_finish,
                              '\x6c': token_delete_finish,
                              '\x6d': token_get_transfer_mode,
                              '\x6e': token_get_filedata,
                              '\x6f': token_createfolder_finish,
                              '\x70': token_data_continue,
                              '\x71': token_rename_finish,
                              '\x72': token_exception,
                              '\x73': token_bitmapinfo,
                              '\x74': token_firstscreen,
                              '\x75': token_nextscreen,
                              '\x76': token_clipboard_text,
                              '\x77': token_webcam_bitmapinfo,
                              '\x78': token_webcam_dib,
                              '\x79': token_audio_start,
                              '\x7a': token_audio_data,
                              '\x7b': token_keyboard_start,
                              '\x7c': token_keyboard_data,
                              '\x7d': token_pslist,
                              '\x7e': token_wslist,
                              '\x7f': token_dialupass,
                              '\x80': token_shell_start
                            }

    if module_data['savefiles']:
        chop.prnt("Carving enabled.")

    module_options = {'proto':'tcp'}

    return module_options

def taste(tcp):
    tcp.stream_data['client_buf'] = ''
    tcp.stream_data['server_buf'] = ''
    tcp.stream_data['flag'] = ''
    tcp.stream_data['shell'] = False
    tcp.stream_data['compressed_len'] = 0
    return True

def handleStream(tcp):
    #((src, sport), (dst, dport)) = tcp.addr
    data = ''

    if tcp.server.count_new > 0:
        if not tcp.stream_data['flag'] and (len(tcp.stream_data['server_buf']) + tcp.server.count_new) < tcp.module_data['wsize']:
            tcp.stream_data['server_buf'] += tcp.server.data[:tcp.server.count_new]
            #chop.tsprnt("Buffered server: %i (total: %i)." % (tcp.server.count_new, len(tcp.stream_data['server_buf'])))
            tcp.discard(tcp.server.count_new)
            return

        data = tcp.stream_data['server_buf'] + tcp.server.data[:tcp.server.count_new]
        tcp.discard(tcp.server.count_new)

        if tcp.stream_data['flag'] and len(data) < (len(tcp.stream_data['flag']) + 4):
            tcp.stream_data['server_buf'] = data
            #chop.tsprnt("%s:%i->%s:%i Data too small. Buffered server: %i (total: %i)" % (src, sport, dst, dport, tcp.server.count_new, len(data)))
            return
    elif tcp.client.count_new > 0:
        if not tcp.stream_data['flag'] and (len(tcp.stream_data['client_buf']) + tcp.client.count_new) < tcp.module_data['wsize']:
            tcp.stream_data['client_buf'] += tcp.client.data[:tcp.client.count_new]
            #chop.tsprnt("Buffered client: %i (total: %i)." % (tcp.client.count_new, len(tcp.stream_data['client_buf'])))
            tcp.discard(tcp.client.count_new)
            return

        data = tcp.stream_data['client_buf'] + tcp.client.data[:tcp.client.count_new]
        tcp.discard(tcp.client.count_new)

        if tcp.stream_data['flag'] and len(data) < (len(tcp.stream_data['flag']) + 4):
            tcp.stream_data['client_buf'] = data
            #chop.tsprnt("%s:%i->%s:%i Data too small. Buffered client: %i (total: %i)" % (src, sport, dst, dport, tcp.client.count_new, len(data)))
            return

    if tcp.stream_data['flag']:
        while data:
            #chop.tsprnt("Handling blob: %s:%i->%s:%i (%i)" % (src, sport, dst, dport, len(data)))
            if tcp.stream_data['compressed_len'] == 0:
                compressed_len = struct.unpack('<I', data[len(tcp.stream_data['flag']):len(tcp.stream_data['flag']) + 4])[0]
                tcp.stream_data['compressed_len'] = compressed_len
            else:
                compressed_len = tcp.stream_data['compressed_len']

            if len(data) < compressed_len:
                if tcp.server.count_new > 0:
                    #chop.tsprnt("LEN DATA: (%i) COMPRESSED LEN: (%i) NEW BUFFER: %i" % (len(data), compressed_len, len(tcp.stream_data['server_buf']) + len(data)))
                    tcp.stream_data['server_buf'] = data
                elif tcp.client.count_new > 0:
                    #chop.tsprnt("LEN DATA: (%i) COMPRESSED LEN: (%i) NEW BUFFER: %i" % (len(data), compressed_len, len(tcp.stream_data['client_buf']) + len(data)))
                    tcp.stream_data['client_buf'] = data
                return

            #chop.tsprnt("COMPRESSED LEN MATCH, DECODING!")
            if tcp.stream_data['zlib']:
                msg = zlib.decompress(data[len(tcp.stream_data['flag']) + 8:len(tcp.stream_data['flag']) + 8 + compressed_len])
            else:
                msg = data[len(tcp.stream_data['flag'] + 8):]
            decode(msg, tcp)
            data = data[compressed_len:]
            tcp.stream_data['compressed_len'] = 0
            if tcp.server.count_new > 0:
                tcp.stream_data['server_buf'] = ''
            elif tcp.client.count_new > 0:
                tcp.stream_data['client_buf'] = ''
    else:
        #chop.tsprnt("Finding flag: %s:%i->%s:%i (%i)" % (src, sport, dst, dport, len(data)))
        # The first gh0st message fits in a single TCP payload,
        # unless you have MTU problems.
        tcp.stream_data['flag'] = find_flag(data, tcp)
        if not tcp.stream_data['flag']:
            #chop.tsprnt("No flag found, skipping stream.")
            tcp.stop()

def find_flag(data, tcp):
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    flag = ''
    module_data = tcp.module_data

    for i in range(tcp.module_data['wsize'] - 3):
        compressed_len = struct.unpack('<I', data[i:i + 4])[0]
        if compressed_len == len(data):
            flag = data[:i]
            i += 4
            uncompressed_len = struct.unpack('<I', data[i:i + 4])[0]
            i += 4
            if module_data['verbose']:
                chop.tsprnt("Gh0st found: %s:%i->%s:%i (%i)" % (src, sport, dst, dport, compressed_len))
                chop.tsprnt("\tFlag: %s (0x%s)" % (flag, binascii.hexlify(flag)))
                chop.tsprnt("\tUncompressed length: %i" % uncompressed_len)

            zlib_hdr = struct.unpack('>H', data[i:i + 2])[0]
            if zlib_hdr == 30876: # \x78\x9c
                tcp.stream_data['zlib'] = True
                if module_data['verbose']:
                    chop.tsprnt("\tzlib header found")
                if len(data) == compressed_len:
                    msg = zlib.decompress(data[i:])
                    # Sanity check
                    if len(msg) != uncompressed_len:
                        chop.tsprnt("Uncompressed size mismatch.")
                        tcp.stop()
                        return None
            else:
                tcp.stream_data['zlib'] = False
                if module_data['verbose']:
                    chop.tsprnt("\tno zlib header found")
                msg = data[i:]

            decode(msg, tcp)
            break

    return flag

# In the gh0st world there are commands and tokens.
# Commands are sent from controller to implant.
# Tokens are sent from implant to controller.
def decode(msg, tcp):
    ((src, sport), (dst, dport)) = parse_addr(tcp)
    #chop.tsprnt("%s:%i->%s:%i" % (src, sport, dst, dport), None)

    # If this is a shell session, just dump the contents.
    if tcp.stream_data['shell'] == True:
        chop.prnt("\n%s" % msg)
        return

    # Grab the token and decode if possible.
    b = struct.unpack('c', msg[:1])[0]
    if b in tcp.module_data['tokens']:
        msg = msg[1:]
        tcp.module_data['tokens'][b](msg, tcp)
    else:
        chop.prnt("Unknown token: 0x%02x" % ord(b))
        chop.prnt("%s" % hexdump(msg))

def command_actived(msg, tcp):
    chop.prnt("COMMAND: ACTIVED")

def command_list_drive(msg, tcp):
    chop.prnt("COMMAND: LIST DRIVE")

def command_list_files(msg, tcp):
    chop.prnt("COMMAND: LIST FILES (%s)" % msg[:-1])

def command_down_files(msg, tcp):
    chop.prnt("COMMAND: DOWN FILES (%s)" % msg[:-1])

def command_file_size(msg, tcp):
    (fname, size) = get_name_and_size(msg, tcp)
    chop.prnt("COMMAND: FILE SIZE (%s: %i)" % (fname, size))

def command_file_data(msg, tcp):
    chop.prnt("COMMAND: FILE DATA (%i)" % len(msg[8:]))
    if tcp.module_data['savefiles']:
        carve_file(msg, tcp)

# These should only be sent in the case of problems with the
# controller or implant. As such, leave them in debugging mode.
def command_exception(msg, tcp):
    chop.prnt("command_exception\n%s" % hexdump(msg))

def command_continue(msg, tcp):
    # XXX: Sent with 8 bytes. The bytes are important, skip them.
    chop.prnt("COMMAND: CONTINUE")

def command_stop(msg, tcp):
    chop.prnt("COMMAND: STOP")

def command_delete_file(msg, tcp):
    chop.prnt("COMMAND: DELETE FILE (%s)" % msg[:-1])

def command_delete_directory(msg, tcp):
    chop.prnt("COMMAND: DELETE DIRECTORY (%s)" % msg[:-1])

def command_set_transfer_mode(msg, tcp):
    mode = struct.unpack('<I', msg[:4])[0]
    if mode == 0x00000000:
        msg = "NORMAL"
    elif mode == 0x00000001:
        msg = "ADDITION"
    elif mode == 0x00000002:
        msg = "ADDITION ALL"
    elif mode == 0x00000003:
        msg = "OVERWRITE"
    elif mode == 0x00000004:
        msg = "OVERWRITE ALL"
    elif mode == 0x00000005:
        msg = "JUMP"
    elif mode == 0x00000006:
        msg = "JUMP ALL"
    elif mode == 0x00000007:
        msg = "CANCEL"
    else:
        msg = "UNKNOWN"
    chop.prnt("COMMAND: SET TRANSFER MODE (%s)" % msg)

def command_create_folder(msg, tcp):
    chop.prnt("COMMAND: CREATE FOLDER (%s)" % msg[:-1])

def command_rename_file(msg, tcp):
    null = msg.find('\x00')
    chop.prnt("COMMAND: RENAME FILE (%s -> %s)" % (msg[:null], msg[null + 1:]))

def command_open_file_show(msg, tcp):
    chop.prnt("COMMAND: OPEN FILE SHOW (%s)" % msg[:-1])

def command_open_file_hide(msg, tcp):
    chop.prnt("COMMAND: OPEN FILE HIDE (%s)" % msg[:-1])

def command_screen_spy(msg, tcp):
    chop.prnt("COMMAND: SCREEN SPY")

def command_screen_reset(msg, tcp):
    b = struct.unpack('B', msg[0])[0]
    chop.prnt("COMMAND: SCREEN RESET (%i)" % b)

def command_algorithm_reset(msg, tcp):
    b = struct.unpack('B', msg[0])[0]
    chop.prnt("COMMAND: ALGORITHM RESET (%i)" % b)

def command_screen_ctrl_alt_del(msg, tcp):
    chop.prnt("COMMAND: SEND CTRL ALT DEL")

def command_screen_control(msg, tcp):
    # No need to parse this structure. It's just mouse movements
    # and button presses. They won't mean anything on their own.
    # You need the context of the screen on which they are happening.
    chop.prnt("COMMAND: SCREEN CONTROL")
    #chop.prnt("command_screen_control\n%s" % hexdump(msg))

def command_screen_block_input(msg, tcp):
    b = struct.unpack('B', msg)[0]
    if b == 0:
        status = "OFF"
    else:
        status = "ON"
    chop.prnt("COMMAND: SCREEN BLOCK INPUT (%s)" % status)

def command_screen_blank(msg, tcp):
    b = struct.unpack('B', msg)[0]
    if b == 0:
        status = "OFF"
    else:
        status = "ON"
    chop.prnt("COMMAND: SCREEN BLANK (%s)" % status)

def command_screen_capture_layer(msg, tcp):
    b = struct.unpack('B', msg)[0]
    if b == 0:
        status = "OFF"
    else:
        status = "ON"
    chop.prnt("COMMAND: SCREEN CAPTURE LAYER (%s)" % status)

def command_screen_get_clipboard(msg, tcp):
    chop.prnt("COMMAND: SCREEN GET CLIPBOARD\n%s" % msg[:-1])

def command_screen_set_clipboard(msg, tcp):
    chop.prnt("COMMAND: SCREEN SET CLIPBOARD\n%s" % msg[:-1])

# XXX
def command_webcam(msg, tcp):
    chop.prnt("COMMAND: WEBCAM")

# XXX
def command_webcam_enablecompress(msg, tcp):
    chop.prnt("command_webcam_enablecompress\n%s" % hexdump(msg))

def command_webcam_disablecompress(msg, tcp):
    chop.prnt("COMMAND: WEBCAM DISABLECOMPRESS")

# XXX
def command_webcam_resize(msg, tcp):
    chop.prnt("command_webcam_resize\n%s" % hexdump(msg))

def command_next(msg, tcp):
    chop.prnt("COMMAND: NEXT")

def command_keyboard(msg, tcp):
    chop.prnt("COMMAND: KEYBOARD")

def command_keyboard_offline(msg, tcp):
    chop.prnt("COMMAND: KEYBOARD OFFLINE")

def command_keyboard_clear(msg, tcp):
    chop.prnt("COMMAND: KEYBOARD CLEAR")

def command_audio(msg, tcp):
    chop.prnt("COMMAND: AUDIO")

def command_system(msg, tcp):
    chop.prnt("COMMAND: SYSTEM")

def command_pslist(msg, tcp):
    chop.prnt("COMMAND: PSLIST")

def command_wslist(msg, tcp):
    chop.prnt("COMMAND: WSLIST")

def command_dialupass(msg, tcp):
    chop.prnt("COMMAND: DIALUPASS")

def command_killprocess(msg, tcp):
    chop.prnt("COMMAND: KILLPROCESS (%i)" % struct.unpack('<I', msg[:4])[0])

def command_shell(msg, tcp):
    chop.prnt("COMMAND: SHELL")

def command_session(msg, tcp):
    # A one byte value indicates the kind of session control.
    # Values are documented in:
    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa376868(v=vs.85).aspx 
    # All values are OR'ed with EWX_FORCE.
    b = struct.unpack('B', msg[0])[0]
    if b == 0x04:
        t = "LOGOFF"
    elif b == 0x05:
        t = "SHUTDOWN"
    elif b == 0x06:
        t = "REBOOT"
    chop.prnt("COMMAND: SESSION (%s)" % t)

def command_remove(msg, tcp):
    chop.prnt("COMMAND: REMOVE")

def command_down_exec(msg, tcp):
    chop.prnt("COMMAND: DOWN EXEC (%s)" % msg[:-1])

def command_update_server(msg, tcp):
    chop.prnt("COMMAND: UPDATE SERVER (%s)" % msg[:-1])

def command_clean_event(msg, tcp):
    chop.prnt("COMMAND: CLEAN EVENT")

def command_open_url_hide(msg, tcp):
    chop.prnt("COMMAND: OPEN URL HIDE (%s)" % msg[:-1])

def command_open_url_show(msg, tcp):
    chop.prnt("COMMAND: OPEN URL SHOW (%s)" % msg[:-1])

# I've never been able to get this command to send.
# Leave in for debugging reasons.
def command_rename_remark(msg, tcp):
    chop.prnt("command_rename_remark\n%s" % hexdump(msg))

# This is never sent either.
# Leave in for debugging reasons.
def command_replay_heartbeat(msg, tcp):
    chop.prnt("command_replay_heartbeat\n%s" % hexdump(msg))

# This token is never sent but leave in for debugging.
def token_auth(msg, tcp):
    chop.prnt("token_auth\n%s" % hexdump(msg))

# This token is never sent but leave in for debugging.
def token_heartbeat(msg, tcp):
    chop.prnt("token_heartbeat\n%s" % hexdump(msg))

def token_login(msg, tcp):
    # XXX: FIGURE OUT WHAT THESE BYTES ARE!
    msg = msg[3:]

    # The OsVerInfoEx structure is documented at:
    # http://msdn.microsoft.com/en-us/library/windows/desktop/ms724833(v=vs.85).aspx
    (osver_size, major, minor, build) = struct.unpack('<IIII', msg[:16])
    # Grab the rest after this structure, before we start messing with
    # the buffer.
    buf = msg[osver_size:]

    # Skip over the platform ID.
    msg = msg[20:]
    null = msg.find('\x00')
    sp = msg[:null]
    if len(sp) == 0:
        sp = "No service pack"
    # The service pack string is always 128 bytes long.
    # Skip service pack major and minor (each are 2 bytes).
    msg = msg[132:]
    (suite_mask, product_type) = struct.unpack('<HB', msg[:3])
    msg = msg[4:]
    os = "UNKNOWN OS (0x%08x.0x%08x SM: 0x%04x PT: 0x%02x)" % (major, minor, suite_mask, product_type)
    if major == 0x00000005:
        if minor == 0x00000000:
            os = "Windows 2000"
        elif minor == 0x00000001:
            os = "Windows XP"
        elif minor == 0x00000002:
            if product_type == 0x01:
                os = "Windows XP"
            elif suite_mask & 0x8000:
                os = "Windows Home Server"
            else:
                os = "Windows Server 2003"
    elif major == 0x00000006:
        if minor == 0x00000000:
            if product_type == 0x01:
                os = "Windows Vista"
            else:
                os = "Windows Server 2008"
        elif minor == 0x00000001:
            if product_type == 0x01:
                os = "Windows 7"
            else:
                os = "Windows Server 2008 R2"
        elif minor == 0x00000002:
            if product_type == 0x01:
                os = "Windows 8"
            else:
                os = "Windows Server 2012"

    # A true gh0st login will have 64 bytes left at this point.
    # There are variants that alter this and add other things.
    # Catch this...
    if len(msg) != 64:
        token = "TOKEN: LOGIN (IP AND WEBCAM MAY BE WRONG)"
    else:
        token = "TOKEN: LOGIN"

    # Parse the clock speed and IP (in case it's behind a NAT).
    (clock, ip) = struct.unpack('<iI', buf[:8])
    buf = buf[8:]
    null = buf.find('\x00')
    hostname = buf[:null]
    buf = buf[50:]
    # The webcam field is a bool. In my sample this is 2 bytes. May not
    # always be true depending upon compiler.
    if struct.unpack('<H', buf[:2])[0]:
        webcam = "yes"
    else:
        webcam = "no"

    # XXX: Use socket.inet_ntoa() to convert to dotted quad.
    chop.prnt("%s: %s: %s %s - Build: %i - Clock: %i Mhz - IP: %s.%s.%s.%s Webcam: %s" % (token, hostname, os, sp, build, clock, ip & 0x000000FF, (ip & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24, webcam))

def token_drive_list(msg, tcp):
    chop.prnt("TOKEN: DRIVE LIST")
    chop.prnt("DRIVE\tTOTAL\tFREE\tFILESYSTEM\tDESCRIPTION")
    while len(msg) > 9:
        drive = struct.unpack('c', msg[0])[0]
        # Skip drive type, single byte.
        msg = msg[2:]
        (total, free) = struct.unpack('<II', msg[:8])
        msg = msg[8:]
        null = msg.find('\x00')
        desc = msg[:null]
        msg = msg[null + 1:]
        null = msg.find('\x00')
        fs = msg[:null]
        chop.prnt("%s\t%i\t%i\t%s\t%s" % (drive, total, free, fs, desc))
        msg = msg[null + 1:]

def token_file_list(msg, tcp):
    if len(msg) == 0:
        chop.prnt("TOKEN: FILE LIST (INVALID HANDLE)")
        return
    chop.prnt("TOKEN: FILE LIST")
    chop.prnt("TYPE\tNAME\tSIZE\tWRITE TIME")
    while len(msg) >= 1:
        d = struct.unpack('B', msg[1])[0]
        if d & 0x10:
            d = "DIR"
        else:
            d = "FILE"
        msg = msg[1:]
        null = msg.find('\x00')
        name = msg[:null]
        msg = msg[null + 1:]
        (hsize, lsize, wtime) = struct.unpack('<IIQ', msg[:16])
        size = winsizeize(hsize, lsize)
        msg = msg[16:]
        chop.prnt("%s\t%s\t%i\t%i" % (d, name, size, wtime))

def token_file_size(msg, tcp):
    (fname, size) = get_name_and_size(msg, tcp)
    chop.prnt("TOKEN: FILE SIZE (%s: %i)" % (fname, size))

def token_file_data(msg, tcp):
    chop.prnt("TOKEN: FILE DATA (%i)" % len(msg[8:]))
    if tcp.module_data['savefiles']:
        carve_file(msg, tcp)

def token_transfer_finish(msg, tcp):
    chop.prnt("TOKEN: TRANSFER FINISH")

def token_delete_finish(msg, tcp):
    chop.prnt("TOKEN: DELETE FINISH")

def token_get_transfer_mode(msg, tcp):
    chop.prnt("TOKEN: GET TRANSFER MODE")

# XXX: This is never sent by the implant.
# Leave it in debugging state for now.
def token_get_filedata(msg, tcp):
    chop.prnt("token_get_filedata\n%s" % hexdump(msg))

def token_createfolder_finish(msg, tcp):
    chop.prnt("TOKEN: CREATEFOLDER FINISH")

def token_data_continue(msg, tcp):
    # XXX: Sent with 8 bytes. Appear to be transfer modes. Not important.
    chop.prnt("TOKEN: DATA CONTINUE")

def token_rename_finish(msg, tcp):
    chop.prnt("TOKEN: RENAME FINISH")

def token_exception(msg, tcp):
    chop.prnt("token_exception\n%s" % hexdump(msg))

def token_bitmapinfo(msg, tcp):
    #chop.prnt("token_bitmapinfo\n%s" % hexdump(msg))
    chop.prnt("TOKEN: BITMAPINFO")

# XXX
def token_firstscreen(msg, tcp):
    #chop.prnt("token_firstscreen\n%s" % hexdump(msg))
    chop.prnt("TOKEN: FIRST SCREEN")

# XXX
def token_nextscreen(msg, tcp):
    #chop.prnt("token_nextscreen\n%s" % hexdump(msg))
    chop.prnt("TOKEN: NEXT SCREEN")

def token_clipboard_text(msg, tcp):
    chop.prnt("TOKEN: CLIPBOARD TEXT\n%s" % msg[:-1])

# XXX
def token_webcam_bitmapinfo(msg, tcp):
    #chop.prnt("token_webcam_bitmapinfo\n%s" % hexdump(msg))
    chop.prnt("TOKEN: WEBCAM BITMAP INFO")

def token_webcam_dib(msg, tcp):
    #chop.prnt("token_webcam_dib\n%s" % hexdump(msg))
    chop.prnt("TOKEN: WEBCAM DIB")

def token_audio_start(msg, tcp):
    chop.prnt("TOKEN: AUDIO START")

# XXX
def token_audio_data(msg, tcp):
    #chop.prnt("token_audio_data\n%s" % hexdump(msg))
    chop.prnt("TOKEN: AUDIO DATA")

def token_keyboard_start(msg, tcp):
    b = struct.unpack('B', msg)[0]
    if b == 0:
        status = "OFFLINE"
    else:
        status = "ONLINE"
    chop.prnt("TOKEN: KEYBOARD START (%s)" % status)

def token_keyboard_data(msg, tcp):
    chop.prnt("TOKEN: KEYBOARD DATA\n%s" % msg)

def token_pslist(msg, tcp):
    chop.prnt("TOKEN: PSLIST")
    chop.prnt("PID\tEXE\t\tPROC NAME")
    while len(msg) >= 4:
        pid = struct.unpack('<I', msg[:4])[0]
        msg = msg[4:]
        null = msg.find('\x00')
        exe = msg[:null]
        msg = msg[null + 1:]
        null = msg.find('\x00')
        name = msg[:null]
        msg = msg[null + 1:]
        chop.prnt("%i\t%s\t\t%s" % (pid, exe, name))

def token_wslist(msg, tcp):
    chop.prnt("TOKEN: WSLIST")
    chop.prnt("PID\tTITLE")
    while len(msg) >= 4:
        pid = struct.unpack('<I', msg[:4])[0]
        msg = msg[4:]
        null = msg.find('\x00')
        title = msg[:null]
        msg = msg[null + 1:]
        chop.prnt("%i\t%s" % (pid, title))

def token_dialupass(msg, tcp):
    # XXX: HANDLE!
    chop.prnt("TOKEN: DIALUPASS")

def token_shell_start(msg, tcp):
    chop.prnt("TOKEN: SHELL START")
    tcp.stream_data['shell'] = True

def get_name_and_size(msg, tcp):
    (hsize, lsize) = struct.unpack('<II', msg[:8])
    size = winsizeize(hsize, lsize)
    fname = msg[8:-1]
    if tcp.module_data['savefiles']:
        tcp.stream_data['fsize'] = size
        tcp.stream_data['fname'] = sanitize_filename(fname)
        chop.prnt(tcp.stream_data['fname'])
        tcp.stream_data['byteswritten'] = 0
    return (fname, size)

def carve_file(msg, tcp):
    if tcp.stream_data['byteswritten'] == 0:
        chop.savefile(tcp.stream_data['fname'], msg[8:])
    else:
        chop.appendfile(tcp.stream_data['fname'], msg[8:])

    tcp.stream_data['byteswritten'] += len(msg[8:])

    if tcp.stream_data['byteswritten'] < tcp.stream_data['fsize']:
        chop.prnt("Wrote %i of %i to %s" % (tcp.stream_data['byteswritten'], tcp.stream_data['fsize'], tcp.stream_data['fname']))
    elif tcp.stream_data['byteswritten'] > tcp.stream_data['fsize']:
        chop.prnt("OVERFLOW: Wrote %i of %i to %s" % (tcp.stream_data['byteswritten'], tcp.stream_data['fsize'], tcp.stream_data['fname']))
        chop.finalizefile(tcp.stream_data['fname'])
        tcp.stream_data['fname'] = ''
        tcp.stream_data['fsize'] = 0
    else:
        chop.prnt("Wrote %i of %i to %s" % (tcp.stream_data['byteswritten'], tcp.stream_data['fsize'], tcp.stream_data['fname']))
        chop.finalizefile(tcp.stream_data['fname'])
        tcp.stream_data['fname'] = ''
        tcp.stream_data['fsize'] = 0

def teardown(tcp):
    pass

def module_info():
    return "Decode and display Gh0st backdoor commands and responses"

def shutdown(module_data):
    pass
