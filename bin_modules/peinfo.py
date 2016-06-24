# ChopShop specific code falls under the following license:
#
# Copyright (c) 2016 The MITRE Corporation. All rights reserved.
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
#
# Some code taken from CRITs (https://github.com/crits/crits_services)
# peinfo service which falls under the following license:
# The MIT License (MIT)
#
# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
#
# Approved for Public Release; Distribution Unlimited 14-1511
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import division

import pefile
import binascii
import bitstring
import bz2
import hashlib
import string
import struct

from ChopBinary import ChopBinary

from time import localtime, strftime

moduleName='peinfo'
moduleVersion = '0.1'
minimumChopLib = '5.0'

def module_info():
    return 'Process a PE using the pefile Python library.'

def init(module_data):
    # Currently returns nothing
    # This could return registered types, e.g., this module only handles 'pdf' type, if useful?
    return {}

# data is a ChopBinary type
# contains module_data which is the module-specific data
def handleData(data):
    # Default return of None won't call children
    # Return an instance of ChopBinary to send downstream
    # e.g.,:
    cb = ChopBinary()
    cb.data = data.data
    cb.metadata['filename'] = 'foobarfoo'

    try:
        pe = pefile.PE(data=cb.data)
    except pefile.PEFormatError as e:
        chop.prnt("An error occurred: %s" % e)
        return

    cb.metadata['sections'] = get_sections(pe)
    cb.metadata['pehash'] = get_pehash(pe)

    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        cb.metadata['resources'] = dump_resource_data("ROOT",
                                                      pe.DIRECTORY_ENTRY_RESOURCE,
                                                      pe)

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        cb.metadata['imports'] = get_imports(pe)
    else:
        cb.metadata['imports'] = None

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        cb.metadata['exports'] = get_exports(pe)
    else:
        cb.metadata['exports'] = None

    if hasattr(pe, 'VS_VERSIONINFO'):
        cb.metadata['version_info'] = get_version_info(pe)
    else:
        cb.metadata['version_info'] = None

    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        cb.metadata['debug_info'] = get_debug_info(pe)
    else:
        cb.metadata['debug_info'] = None

    if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        cb.metadata['tls_info'] = get_tls_info(pe)
    else:
        cb.metadata['tls_info'] = None

    if callable(getattr(pe, 'get_imphash', None)):
        cb.metadata['imphash'] = pe.get_imphash()
    else:
        cb.metadata['imphash'] = None

    cb.metadata['timestamp'] = get_timestamp(pe)
    cb.metadata['rich_header'] = get_rich_header(pe)

    chop.prnt(cb.metadata)

    return cb

def shutdown(module_data):
    pass

# http://www.ntcore.com/files/richsign.htm
def get_rich_header(pe):
    result = {}
    rich_hdr = pe.parse_rich_header()
    if not rich_hdr:
        return
    data = {"raw": str(rich_hdr['values'])}
    result['checksum'] =  (hex(rich_hdr['checksum']), data)

    # Generate a signature of the block. Need to apply checksum
    # appropriately. The hash here is sha256 because others are using
    # that here.
    #
    # Most of this code was taken from pefile but modified to work
    # on the start and checksum blocks.
    try:
        rich_data = pe.get_data(0x80, 0x80)
        if len(rich_data) != 0x80:
            return result
        data = list(struct.unpack("<32I", rich_data))
    except pefile.PEFormatError:
        return result

    checksum = data[1]
    headervalues = []

    for i in xrange(len(data) // 2):
        if data[2 * i] == 0x68636952: # Rich
            if data[2 * i + 1] != checksum:
                chop.prnt('Rich Header corrupted', Exception)
            break
        headervalues += [data[2 * i] ^ checksum, data[2 * i + 1] ^ checksum]

    sha_256 = hashlib.sha256()
    for hv in headervalues:
        sha_256.update(struct.pack('<I', hv))
    result['sha_256'] = sha_256.hexdigest()
    return result

def dump_resource_data(name, dir, pe):
    results = []
    for i in dir.entries:
        try:
            if hasattr(i, 'data'):
                x = i.data
                rva = x.struct.OffsetToData
                size = x.struct.Size
                data = pe.get_memory_mapped_image()[rva:rva + size]
                if not data:
                    data = ""
                result = {
                        "resource_type": x.struct.name.decode('UTF-8', errors='replace') ,
                        "resource_id": i.id,
                        "language": x.lang,
                        "sub_language": x.sublang,
                        "address": hex(x.struct.OffsetToData),
                        "size": len(data),
                        "md5": hashlib.md5(data).hexdigest(),
                        "name": x.struct.name,
                }
                results.append(result)
            if hasattr(i, "directory"):
                results += dump_resource_data(name + "_%s" % i.name,
                                            i.directory, pe)
        except Exception as e:
            chop.prnt("Resource directory entry", e)
            continue
    return results

def get_sections(pe):
    results = []
    for section in pe.sections:
        try:
            section_name = section.Name.decode('UTF-8', errors='replace')
            if section_name == "":
                section_name = "NULL"
            data = {
                "virt_address": hex(section.VirtualAddress),
                "virt_size": section.Misc_VirtualSize,
                "size": section.SizeOfRawData,
                "md5": section.get_hash_md5(),
                "entropy": section.get_entropy(),
                "name": section_name,
            }
            results.append( data)
        except Exception as e:
            chop.prnt("section info", e)
            continue
    return results

def get_imports(pe):
    results = []
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name
                else:
                    name = "%s#%s" % (entry.dll, imp.ordinal)
                data = {
                    "dll": "%s" % entry.dll,
                    "ordinal": "%s" % imp.ordinal,
                    "name": name,
                }
                results.append(data)
    except Exception as e:
        chop.prnt("imports", e)
        return results

    return results

def get_exports(pe):
    results = []
    try:
        for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            data = {"rva_offset": hex(pe.OPTIONAL_HEADER.ImageBase
                                    + entry.address)}
            data['ename'] = 'NULL'
            if entry.name:
                data['ename'] = entry.name
            results.append(data)
    except Exception as e:
        chop.prnt("exports", e)
        return results

    return results

def get_timestamp(pe):
    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        time_string = strftime('%Y-%m-%d %H:%M:%S', localtime(timestamp))
        data = {"raw": timestamp,
                "timestamp": time_string}
        return data
    except Exception as e:
        chop.prnt("timestamp", e)
        return {}

def get_debug_info(pe):
    # woe is pefile when it comes to debug entries
    # we're mostly interested in codeview stuctures, namely NB10 and RSDS
    results = []
    try:
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            dbg_path = ""
            if hasattr(dbg.struct, "Type"):
                result = {
                        'MajorVersion': dbg.struct.MajorVersion,
                        'MinorVersion': dbg.struct.MinorVersion,
                        'PointerToRawData': hex(dbg.struct.PointerToRawData),
                        'SizeOfData': dbg.struct.SizeOfData,
                        'TimeDateStamp': dbg.struct.TimeDateStamp,
                        'TimeDateString': strftime('%Y-%m-%d %H:%M:%S', localtime(dbg.struct.TimeDateStamp)),
                        'Type': dbg.struct.Type,
                        'subtype': 'pe_debug',
                }
                # type 0x2 is codeview, though not any specific version
                # for other types we don't parse them yet
                # but sounds like a great project for an enterprising CRITs coder...
                if dbg.struct.Type == 0x2:
                    debug_offset = dbg.struct.PointerToRawData
                    debug_size = dbg.struct.SizeOfData
                    # ok, this probably isn't right, fix me
                    if debug_size < 0x200 and debug_size > 0:
                        # there might be a better way than __data__ in pefile to get the raw data
                        # i think that get_data uses RVA's, which this requires physical address
                        debug_data = pe.__data__[debug_offset:debug_offset + debug_size]
                        # now we need to check the codeview version,
                        # http://www.debuginfo.com/articles/debuginfomatch.html
                        # as far as I can tell the gold is in RSDS and NB10
                        if debug_data[:4] == "RSDS":
                            result.update({
                                'DebugSig': debug_data[0x00:0x04],
                                'DebugGUID': binascii.hexlify(debug_data[0x04:0x14]),
                                'DebugAge': struct.unpack('I', debug_data[0x14:0x18])[0],
                            })
                            if dbg.struct.SizeOfData > 0x18:
                                dbg_path = debug_data[0x18:dbg.struct.SizeOfData - 1].decode('UTF-8', errors='replace')
                                result.update({
                                    'DebugPath': "%s" % dbg_path,
                                    'result': "%s" % dbg_path,
                                })
                        if debug_data[:4] == "NB10":
                            result.update({
                                'DebugSig': debug_data[0x00:0x04],
                                'DebugTime': struct.unpack('I', debug_data[0x08:0x0c])[0],
                                'DebugAge': struct.unpack('I', debug_data[0x0c:0x10])[0],
                            })
                            if dbg.struct.SizeOfData > 0x10:
                                dbg_path = debug_data[0x10:dbg.struct.SizeOfData - 1].decode('UTF-8', errors='replace')
                                result.update({
                                    'DebugPath': "%s" % dbg_path,
                                    'result': "%s" % dbg_path,
                                })
            results.append(result)
    except Exception as e:
        chop.prnt("could not extract debug info", e)
        return results

    return results

def get_version_info(pe):
    results = []
    if hasattr(pe, 'FileInfo'):
        try:
            for entry in pe.FileInfo:
                if hasattr(entry, 'StringTable'):
                    for st_entry in entry.StringTable:
                        for str_entry in st_entry.entries.items():
                            try:
                                value = str_entry[1].encode('ascii')
                                result = {
                                    'key':      str_entry[0],
                                    'value':    value,
                                }
                            except:
                                value = str_entry[1].encode('ascii', errors='ignore')
                                raw = binascii.hexlify(str_entry[1].encode('utf-8'))
                                result = {
                                    'key':      str_entry[0],
                                    'value':    value,
                                    'raw':      raw,
                                    'name': str_entry[0] + ': ' + value[:255],
                                }
                            results.append(result)
                elif hasattr(entry, 'Var'):
                    for var_entry in entry.Var:
                        if hasattr(var_entry, 'entry'):
                            for key in var_entry.entry.keys():
                                try:
                                    value = var_entry.entry[key].encode('ascii')
                                    result = {
                                        'key':      key,
                                        'value':    value,
                                    }
                                except:
                                    value = var_entry.entry[key].encode('ascii', errors='ignore')
                                    raw = binascii.hexlify(var_entry.entry[key])
                                    result = {
                                        'key':      key,
                                        'value':    value,
                                        'raw':      raw,
                                        'name': key + ': ' + value,
                                    }
                                results.append(result)
        except Exception as e:
            chop.prnt("version info", e)
            return results

    return results

def get_tls_info(pe):
    results = []
    results.append("TLS callback table listed at 0x%08x" % pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
    callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

    # read the array of TLS callbacks until we hit a NULL ptr (end of array)
    idx = 0
    callback_functions = [ ]
    while pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0):
        callback_functions.append(pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0))
        idx += 1

    # if we start with a NULL ptr, then there are no callback functions
    if idx == 0:
        results.append("No TLS callback functions supported")
    else:
        for idx, va in enumerate(callback_functions):
            va_string = "0x%08x" % va
            results.append("TLS callback function at %s" % va_string)
            data = {'Callback Function': idx,
                    'va_string': va_string}
            results.append(data)
    return results

def get_pehash(exe):
    results = {}
    #image characteristics
    img_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Characteristics))
    #pad to 16 bits
    img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
    img_chars_xor = img_chars[0:7] ^ img_chars[8:15]

    #start to build pehash
    pehash_bin = bitstring.BitArray(img_chars_xor)

    #subsystem -
    sub_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Machine))
    #pad to 16 bits
    sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
    sub_chars_xor = sub_chars[0:7] ^ sub_chars[8:15]
    pehash_bin.append(sub_chars_xor)

    #Stack Commit Size
    stk_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfStackCommit))
    stk_size_bits = string.zfill(stk_size.bin, 32)
    #now xor the bits
    stk_size = bitstring.BitArray(bin=stk_size_bits)
    stk_size_xor = stk_size[8:15] ^ stk_size[16:23] ^ stk_size[24:31]
    #pad to 8 bits
    stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
    pehash_bin.append(stk_size_xor)

    #Heap Commit Size
    hp_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfHeapCommit))
    hp_size_bits = string.zfill(hp_size.bin, 32)
    #now xor the bits
    hp_size = bitstring.BitArray(bin=hp_size_bits)
    hp_size_xor = hp_size[8:15] ^ hp_size[16:23] ^ hp_size[24:31]
    #pad to 8 bits
    hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
    pehash_bin.append(hp_size_xor)

    #Section chars
    for section in exe.sections:
        #virutal address
        sect_va =  bitstring.BitArray(hex(section.VirtualAddress))
        sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
        pehash_bin.append(sect_va)

        #rawsize
        sect_rs =  bitstring.BitArray(hex(section.SizeOfRawData))
        sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
        sect_rs_bits = string.zfill(sect_rs.bin, 32)
        sect_rs = bitstring.BitArray(bin=sect_rs_bits)
        sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
        sect_rs_bits = sect_rs[8:31]
        pehash_bin.append(sect_rs_bits)

        #section chars
        sect_chars =  bitstring.BitArray(hex(section.Characteristics))
        sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
        sect_chars_xor = sect_chars[16:23] ^ sect_chars[24:31]
        pehash_bin.append(sect_chars_xor)

        #entropy calulation
        address = section.VirtualAddress
        size = section.SizeOfRawData
        raw = exe.write()[address+size:]
        if size == 0:
            kolmog = bitstring.BitArray(float=1, length=32)
            pehash_bin.append(kolmog[0:7])
            continue
        bz2_raw = bz2.compress(raw)
        bz2_size = len(bz2_raw)
        #k = round(bz2_size / size, 5)
        k = bz2_size / size
        kolmog = bitstring.BitArray(float=k, length=32)
        pehash_bin.append(kolmog[0:7])

    m = hashlib.sha1()
    m.update(pehash_bin.tobytes())
    output = m.hexdigest()
    results['PEhash value'] = output
    return results
