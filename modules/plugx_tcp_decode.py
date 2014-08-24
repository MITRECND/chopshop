import sys
import struct
import binascii
import time
import re

import lznt1

from optparse import OptionParser

from struct import *


moduleName="plugx_tcp_decode"
supported_protocols = [0,1]

def module_info():
    pass

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    tcp.stream_data['client_buf'] = ''
    tcp.stream_data['server_buf'] = ''
    tcp.stream_data['flag'] = ''
    if tcp.module_data['verbose']:
        chop.tsprnt("Start Session %s:%s -> %s:%s"  % (src, sport, dst, dport))
    return True


def init(module_data):
    parser = OptionParser()

    parser.add_option("-p",
                      "--protocol",
                      action="store",
                      dest="protocol",
                      default=1,
                      type="int",
                      help="please specify the suspected protocol,"
                           " %s" % supported_protocols)
    parser.add_option("-v",
                      "--verbose",
                      action="store_true",
                      dest="verbose",
                      default=False,
                      help="warning: debug level verbosity, prints"
                           " vars used in every byte decryption")

    (opts, lo) = parser.parse_args(module_data['args'])

    module_data['verbose'] = opts.verbose

    if opts.protocol in supported_protocols:
        module_data['protocol'] = opts.protocol
    else:
        module_options['error'] = "Unsupported protocol. Supported"
                                  " protocols are %s" % supported_protocols
        return module_options

    module_data['flags'] = {
        # protocol 0 only flags:
        0x0    : "WAITING_FOR_COMMAND?",
        0x1    : "GET_MACHINE_INFO_FLAG",           #rtn machine name/identifier
        0x2    : "CHANGE_LEVEL_FLAG (keep-alive?)",
        0x3    : "START_PLUGIN_MGR_FLAG",           #select and enable plugins
        0x5    : "INSTALL_NEW_COPY_FLAG",           #install itself again
        0x6    : "SEND_NEW_SETTINGS_FLAG",          #send bot new settings
        0x7    : "SAVE_SETTINGS_TO_FILE_FLAG",      #save cur settings to file
        0x8    : "SEND_PLUGINS_INFO_FLAG",          #send C&C info about plugins
        # protocol 1 only flags:
        0x1000 : "WAITING_FOR_COMMAND?",
        0x1001 : "GET_MACHINE_INFO_FLAG",           #rtn machine name/identifier
        0x1002 : "CHANGE_LEVEL_FLAG (keep-alive?)",
        0x1003 : "START_PLUGIN_MGR_FLAG",           #select and enable plugins
        0x1005 : "INSTALL_NEW_COPY_FLAG",           #install itself again
        0x1006 : "SEND_NEW_SETTINGS_FLAG",          #send bot new settings
        0x1007 : "SAVE_SETTINGS_TO_FILE_FLAG",      #save cur settings to file
        0x1008 : "SEND_PLUGINS_INFO_FLAG",          #send C&C info about plugins
        # flags for plugins:
        # Option
        0x2000 : "LOCK_WORKSTATION_FLAG",
        0x2001 : "LOGOFF_FLAG",
        0x2002 : "SYSTEM_REBOOT_FLAG",
        0x2003 : "SYSTEM_SHUTDOWN_FLAG",
        0x2005 : "MESSAGE_BOX_FLAG",
        # Disk
        0x3000 : "GET_ATTACHED_DISKS_FLAG",
        0x3001 : "SEARCH_DIR_FOR_FILES_FLAG",
        0x3002 : "SEARCH_DIR_RECURSING_FLAG",
        0x3004 : "READ_FILE_NAME_FLAG",
        0x3005 : "READ_FILE_DATA_FLAG",
        0x3007 : "WRITE_FILE_NAME_FLAG",
        0x3008 : "WRITE_FILE_DATA_FLAG",
        0x300A : "CREATE_DIRECTORY_FLAG",
        0x300C : "CREATE_DESKTOP_EXEC_FILE_FLAG",
        0x300D : "DO_FILE_OPERATION_FLAG",
        0x300E : "GET_ENV_STRINGS_FLAG",
        # Screen
        0x4000 : "SCREEN_START_CAP_THREAD_FLAG",
        0x4004 : "SEND_MOUSE_EVENT_FLAG",
        0x4005 : "SEND_KBD_EVENT_FLAG",
        0x4006 : "SEND_CTRL_ALT_DEL_FLAG",
        # Screen
        0x4100 : "SCREEN_CAPTURE_FLAG",
        0x4101 : "SCREEN_CAPTURE_FRAME_FLAG",
        # Process
        0x5000 : "ENUM_RUNNING_PROCS_FLAG",
        0x5001 : "ENUM_RUNNING_PROC_MODULES_FLAG",
        0x5002 : "KILL_PROCESS_FLAG",
        # Service
        0x6000 : "ENUM_SERVICES_FLAG",
        0x6001 : "CHANGE_SERVICE_FLAG",
        0x6002 : "START_SERVICE_FLAG",
        0x6003 : "CONTROL_SERVICE_FLAG",
        0x6004 : "DELETE_SERVICE_FLAG",
        # Shell
        0x7002 : "START_SHELL_FLAG",
        0x7003 : "SHELL_INTERACT_FLAG",
        # Telnet
        0x7100 : "START_TELNET_FLAG",
        0x7104 : "TELNET_INTERACT_FLAG",
        # RegEdit
        0x9000 : "REG_ENUM_KEY_FLAG",
        0x9001 : "REG_OPEN_KEY_FLAG",
        0x9002 : "REG_DEL_KEY_FLAG",
        0x9003 : "REG_CREATE_KEY_FLAG",
        0x9004 : "REG_ENUM_KEY_VALUE_FLAG",
        0x9005 : "REG_CREATE_KEY_WITH_VALUE_FLAG",
        0x9006 : "REG_DEL_VALUE_FLAG",
        0x9007 : "REG_GET_OR_CREATE_VALUE_FLAG",
        # Nethood
        0xA000 : "NETHOOD_FLAG",
        # Portmap
        0xB000 : "PORTMAP_FLAG",
        # SQL
        0xC000 : "SQL_GET_DATA_SOURCE_FLAG",
        0xC001 : "SQL_GET_DRIVER_DESC_FLAG",
        0xC002 : "SQL_EXECUTE_STATEMENT_FLAG",
        # Netstat
        0xD000 : "TCPSTATE_FLAG",
        0xD001 : "UDPSTATE_FLAG",
        0xD002 : "ADD_TCPSTATE_FLAG",
        # Keylogger
        0xE000 : "KEYLOGGER_FLAG",
}

    module_options = { 'proto': 'tcp' }

    return module_options


def decrypt_packed_string(__src):
"""
takes in reassembled tcp stream.
returns decrypted headers and data
"""
    src = __src
    key = unpack("<I", __src[0:4])[0]
    if key == 0x54534f50 or key == 0x50545448:
        return src, 0xffff, ''
    #chop.tsprnt(hex(key))
    size = 16
    stage1 = decrypt(src, size, key)
    #chop.tsprnt(repr(hex(unpack("<I", stage1[0:4])[0])),
    #            repr(hex(unpack("<I", stage1[4:8])[0])),
    #            repr(hex(unpack("H",  stage1[8:10])[0])),
    #            repr(hex(unpack("H",  stage1[10:12])[0])))
    flags = unpack("<I", stage1[4:8])[0]
    #chop.tsprnt(hex(flags))
    #chop.tsprnt(repr(stage1[8:10]))

    if flags & 0x2000000:
        if tcp.module_data['verbose']:
            chop.tsprnt("do not decrypt separately")
        size = len(src)
        stage1 = decrypt(src, size, key)
        # consider removing the verbosity filter here if you're seeing the
        # "do not decrypt separately" message, but no meaningful data.
        if tcp.module_data['verbose']:
            chop.tsprnt(unpack("H",stage1[8:10])[0])
    else:
        size = len(src[16:])
        src = __src[16:]
        stage1 = stage1 + decrypt(src, size, key)

    if flags & 0x1000000:
        if tcp.module_data['verbose']:
            chop.tsprnt("do not decompress")
        return stage1, flags, ''
    else:
        if flags in module_data['flags'].keys():
            comp = stage1[16:]
            if tcp.module_data['verbose']:
                chop.tsprnt("len of payload: %d   "
                            "len in header: %d" % (len(comp),
                                                   unpack("H",stage1[8:10])[0]))
            if len(comp) == unpack("H",stage1[8:10]):
                return stage1[:16], flags, comp
            return stage1[:16], flags, comp[:unpack("H",stage1[8:10])[0]]

        decomp = ''
        #chop.tsprnt(repr(stage1[:16]),repr(stage1[16:]))

    return stage1[:16]+decomp, flags, ''

def decrypt(src, size, key):
"""
take in payload to decrypt, length of payload to decrypt, and key seed
return decrypted payload of length.
"""
    key0 = key
    key1 = key
    key2 = key
    key3 = key
    dst = b''
    i = 0

    if size > 0:
        while i < size:

            if tcp.module_data['protocol'] == 0:
                key0 = (key0 + (((key0 >> 3)&0xFFFFFFFF) - 0x11111111)&0xFFFFFFFF)&0xFFFFFFFF
                key1 = (key1 + (((key1 >> 5)&0xFFFFFFFF) - 0x22222222)&0xFFFFFFFF)&0xFFFFFFFF
                key2 = (key2 + (0x44444444 - ((key2 << 9)&0xFFFFFFFF))&0xFFFFFFFF)&0xFFFFFFFF
                key3 = (key3 + (0x33333333 - ((key3 << 7)&0xFFFFFFFF))&0xFFFFFFFF)&0xFFFFFFFF
                new_key = (((key2&0xFF) + (key3&0xFF) + (key1&0xFF) + (key0&0xFF))&0xFF)

            elif tcp.module_data['protocol'] == 1:
                key0 = (key0 + ((key0 >> 3) + 3)&0xFFFFFFFF)&0xFFFFFFFF
                key1 = (key1 + (((key1 >> 5)&0xFFFFFFFF) + 5)&0xFFFFFFFF)&0xFFFFFFFF
                key2 = (0xFFFFFF81 * (key2 & 0xFFFFFFFF)-7)&0xFFFFFFFF
                key3 = (0xFFFFFE01 * (key3 & 0xFFFFFFFF)-9)&0xFFFFFFFF
                new_key = (((key2&0xFF) + (key3&0xFF) + (key1&0xFF) + (key0&0xFF))&0xFF)

            else:
                new_key = 0xFF

            if tcp.module_data['verbose']:
                chop.tsprnt(hex(new_key),hex(key0),hex(key1),hex(key2),hex(key3))

            res = unpack("<B", src[i:i+1])[0] ^ new_key
            dst = dst + pack("<B", res)
            i = i + 1

    return dst


def parse_data(data):

    return "key:%s "
           "flag:%s "
           "szComp:%s "
           "szDeComp:%s" % (
             repr(hex(unpack("<I",  data[0:4])[0])),
             repr(hex(unpack("<I",  data[4:8])[0])),
             repr(hex(unpack("H",  data[8:10])[0])),
             repr(hex(unpack("H", data[10:12])[0]))))


def parse_and_print(data, direction):

    if not data[:6] == 'POST /'  and not data[:6] == 'HTTP/1':
        if tcp.module_data['verbose']:
            chop.tsprnt(repr(data[:16]))
    if len(data) < 16:
        #wtf, but it happens
        tcp.stream_data['%s_buf' % direction] += data
        return 0

    (decrypted, flags, comp) = decrypt_packed_string(data)
    if tcp.module_data['verbose']:
        chop.tsprnt("%s side - precrypt: %s "  % (direction,
                                                  parse_data(data))
        chop.tsprnt("%s side - postcrypt: %s " % (direction,
                                                  parse_data(decrypted))
        chop.tsprnt(comp)
    if flags != 0xffff:
        if tcp.module_data['verbose']:
            chop.tsprnt("%s decrypted header: %s   "
                        "flag: %s" % (
                            direction,
                            repr(decrypted),
                            hex(flags)))
        if comp:
            chop.tsprnt("printable chars sent to %s" % direction,
                        repr(lznt1.dCompressBuf(comp).replace("\x00","")),
                        module_data['flags'][flags])
            if tcp.module_data['verbose']:
                chop.tsprnt("full dump of data sent to %s "
                            "%s" % (direction,
                                    repr(lznt1.dCompressBuf(comp))))
    return 1

def handleStream(tcp):

    data = ''

    # collect time and IP metadata
    ((src, sport), (dst, dport)) = tcp.addr
    # handle client system packets
    if tcp.server.count_new > 0:
        data = tcp.server.data[:tcp.server.count_new]
        if not parse_and_print(data, "server"):
            return
        tcp.discard(tcp.server.count_new)
    # handle server system packets
    if tcp.client.count_new > 0:
        data = tcp.client.data[:tcp.client.count_new]
        if not parse_and_print(data, "client"):
            return
        tcp.discard(tcp.client.count_new)

    if tcp.stream_data['flag']:
        while data:
            # placeholder for code to parse/print data more meaningfully based
            # on flags
            break
    return


def shutdown(module_data):
    return

def teardown(tcp):
#    chop.tsprnt(hex(tcp.stream_data['flag']))
#    chop.tsprnt(hexlify(tcp.stream_data['server_buf']))
    return

