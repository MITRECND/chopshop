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

from optparse import OptionParser
import struct
from ChopProtocol import ChopProtocol

moduleName="icmp"
moduleVersion="0.1"
minimumChopLib="4.0"

class icmp_message:
    pass

def module_info():
    return "Processes IP data and returns 'icmp' data"

def init(module_data):
    module_options = { 'proto': [{'ip': 'icmp'}]}

    return module_options

def handlePacket(ip):
    if ip.protocol != 1:
        return None

    #Okay so we have traffic labeled as ICMP
    icmp = ChopProtocol('icmp')
    ip_offset = 4 * ip.ihl
    icmp_raw = ip.raw[ip_offset:] #separate the icmp data
    header = struct.unpack('<BBH', icmp_raw[0:4])

    #Since this doesn't fit a client server model
    #Created a new 'data' field in the ChopProtocol object
    #Note that the _clone method in ChopProtocol uses deepcopy
    #so we should be okay
    icmp.data = icmp_message()
    icmp.data.type = header[0]
    icmp.data.code = header[1]
    icmp.data.checksum = header[2]
    icmp.data.raw = icmp_raw
    
    return icmp

def shutdown(module_data):
    return

