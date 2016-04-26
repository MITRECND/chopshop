#!/usr/bin/env python

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

import sys
import os
import imp
import nids
import shlex
import traceback
from threading import Thread
from threading import Lock
from multiprocessing import Process, Manager, Queue as mQueue
import Queue
import time
import copy

import struct
import socket

import ChopShopDebug as CSD
from ChopProtocol import ChopProtocol


tcp_modules = []
ip_modules = []
udp_modules = []
all_modules = []

ptimestamp = 0
metadata = {}

class udpdata:
    def __init__(self):
        self.sval = False
    def stop(self):
        self.sval = True

class tcpdata:
    def __init__(self):
        self.dval = 0
        self.sval = False
    def discard(self,dv):
        self.dval = dv
    def stop(self):
        self.sval = True

class ipdata:
    def __init__(self):
        pass

class hstream:
    pass

class stream_meta:
    def __init__(self,of=0,os=0):
        self.stream_data = {}
        self.offset_client = of
        self.offset_server = os


def process_ip_data(ip):
    iplocal = ipdata()

    data = struct.unpack('<BBHHHBBH', ip[0:12])
    iplocal.version = data[0] >> 4
    iplocal.ihl = data[0] & 0x0f # 0b1111
    iplocal.dscp = data[1] >> 2
    iplocal.ecn = data[1] & 0x03 # 0b0011
    iplocal.length = data[2]
    iplocal.identification = data[3]
    iplocal.flags = data[4] >> 13
    iplocal.frag_offset = data[4] & 0x1fff # 0b0001111111111111
    iplocal.ttl = data[5]
    iplocal.protocol = data[6]
    iplocal.checksum = data[7]
    iplocal.src = socket.inet_ntoa(ip[12:16])
    iplocal.dst = socket.inet_ntoa(ip[16:20])
    iplocal.raw = ip

    iplocal.addr = ((iplocal.src, ''), (iplocal.dst, ''))

    return iplocal


# Differences between UDP and TCP:
#
# There is no discard function for udp objects.
#
# In UDP we don't have the concept of client and server objects.
# We can't possibly know which is which.
#
# We don't have the concept of states, though we implement our own
# crude taste functionality anyways.
#
# Because of the lack of states, calling stop() causes that entire
# quad-tuple to be ignored. This can have unintended consequences so
# be careful.
#
# Because of the lack of states there is no teardown() for UDP. We can't
# possibly know this is the last UDP packet for that tuple.
def copy_udp_data(addr, data, ip):
    udplocal = udpdata()
    udplocal.addr = addr
    udplocal.data = data
    udplocal.ip = ip
    return udplocal

def copy_tcp_data(tcp,offset_info,client_direction):
    tcplocal = tcpdata()
    tcplocal.addr = tcp.addr
    tcplocal.nids_state = tcp.nids_state
    tcplocal.client = hstream()
    tcplocal.server = hstream()


    tcplocal.client.state = tcp.client.state
    tcplocal.client.data = tcp.client.data[offset_info.offset_client:]
    tcplocal.client.urgdata = tcp.client.urgdata
    tcplocal.client.count = tcp.client.count
    tcplocal.client.offset = tcp.client.offset + offset_info.offset_client
    tcplocal.client.count_new = tcp.client.count_new
    tcplocal.client.count_new_urg = tcp.client.count_new_urg

    tcplocal.server.state = tcp.server.state
    tcplocal.server.data = tcp.server.data[offset_info.offset_server:]
    tcplocal.server.urgdata = tcp.server.urgdata
    tcplocal.server.count = tcp.server.count
    tcplocal.server.offset = tcp.server.offset + offset_info.offset_server
    tcplocal.server.count_new = tcp.server.count_new
    tcplocal.server.count_new_urg = tcp.server.count_new_urg


    if client_direction:
        tcplocal.dval = tcplocal.client.count_new
    else:
        tcplocal.dval = tcplocal.server.count_new

    return tcplocal

class ChopCore(Thread):
    def __init__(self,options, module_list, chp, chophelper):
        Thread.__init__(self)
        self.options = options
        self.module_list = module_list
        self.chophelper = chophelper
        self.stopped = False
        self.complete = False
        self.abort = False

        global chop
        chop = chp

    def stop(self):
        self.complete = True
        self.stopped = True

    def iscomplete(self):
        return self.complete

    def getptime(self):
        global ptimestamp
        return ptimestamp

    def getmeta(self):
        global metadata
        return metadata

    def prep_modules(self):
        self.chophelper.set_core(self)
        modules = self.module_list
        for module in modules:
            code = module.code
            code.chop = self.chophelper.setup_module(code.moduleName)

    def run(self):
        global chop
        #Initialize modules to be run
        options = self.options
        modules = self.module_list#module_list
        module_options = {}

        chop.prettyprnt("RED", "Initializing Modules ...")

        for module in modules:
            name = module.name
            arguments = module.arguments #shlex.split(module[1])
            code = module.code #module[0]
            #Create module_data for all modules
            module.module_data = {'args': arguments}
            module.streaminfo = {}

            chop.prettyprnt("CYAN", "\tInitializing module '" + name + "'")
            try:
                module_options = code.init(module.module_data)
            except Exception, e:
                chop.prnt("Error Initializing Module", code.moduleName + ":", e)
                self.complete = True
                return

            if 'error' in module_options:
                chop.prettyprnt("GREEN", "\t\t%s init failure: %s" % (code.moduleName, module_options['error']))
                continue

            if module.legacy:
                if module_options['proto'] == 'tcp' :
                    tcp_modules.append(module)
                    all_modules.append(module)
                    module.streaminfo['tcp'] = {}
                elif module_options['proto'] == 'ip' :
                    ip_modules.append(module)
                    all_modules.append(module)
                    module.streaminfo['ip'] = {}
                elif module_options['proto'] == 'udp' :
                    udp_modules.append(module)
                    all_modules.append(module)
                    module.streaminfo['udp'] = {}
                else:
                    chop.prnt("Undefined Module Type\n")
                    self.complete = True
                    return
            else:
                all_modules.append(module)
                #Proto is an array of dictionaries
                if not isinstance(module_options['proto'], list): #Malformed
                    chop.prnt("%s has malformed proto list" % module.code.moduleName)
                    self.complete = True
                    return

                for proto in module_options['proto']:
                    #Right now (4.0) each dictionary only has one key
                    #This might change in the future but should be easy
                    #since it's already a separate dictionary
                    if type(proto) is not dict:
                        chop.prnt("%s has malformed proto list" % module.code.moduleName)
                        self.complete = True
                        return
 
                    for input in proto.keys():
                        if input not in module.inputs:
                            module.inputs[input] = []

                        if proto[input] != '':
                            module.inputs[input].append(proto[input])
                            module.outputs.append(proto[input])

                        #Initialize the streaminfo array by type
                        if input != 'any' and input != 'ip':
                            module.streaminfo[input] = {}

                        if input == 'tcp':
                            tcp_modules.append(module)
                        elif input == 'udp':
                            udp_modules.append(module)
                        elif input == 'ip':
                            ip_modules.append(module)
                        elif input == 'any': #Special input that catches all non-core types
                            #Initialize the streaminfo for all parents of the 'any' module
                            if not len(module.parents):
                                chop.prettyprnt("GREEN", "WARNING: No Parent for %s to provide data" % (module.code.moduleName))
                            else:
                                for parent in module.parents:
                                    for output in parent.outputs:
                                        module.streaminfo[output] = {}
                        else: # non-core types, e.g., 'http' or 'dns'
                            if len(module.parents): #Make sure parents give it what it wants
                                for parent in module.parents:
                                    if input not in parent.outputs:
                                        chop.prettyprnt("GREEN", "WARNING: Parent to %s not providing %s data" % (module.code.moduleName, input))
                            else:
                                chop.prettyprnt("GREEN", "WARNING: No Parent for %s providing %s data" % (module.code.moduleName, input))


        if not all_modules:
            chop.prnt("No modules")
            self.complete = True
            return

        chop.prettyprnt("RED", "Running Modules ...")

        #Actually run the modules
        if options['interface']:
            nids.param("scan_num_hosts",0)
            nids.param("device",options['interface'])
            if options['bpf'] is not None:
                nids.param("pcap_filter", options['bpf'])

            try:
                nids.init()
            except Exception, e:
                chop.prnt("Error initting on interface: ", e)
                self.complete = True
                return

            nids.chksum_ctl([('0.0.0.0/0',False),])
            nids.register_tcp(handleTcpStreams)
            nids.register_udp(handleUdpDatagrams)
            nids.register_ip(handleIpPackets)

            while(True): #This overall while prevents exceptions from halting the processing of packets
                if self.stopped:
                    break
                try:
                    while not self.stopped:
                        nids.next()
                        time.sleep(.001) #XXX is this enough or too much?
                except Exception, e:
                    chop.prnt("Error processing packets", e)
                    #no need to exit
        else:
            if options['filename'] is "":
                chop.prnt("Empty Filename")
                self.complete = True
                return

            nids.param("scan_num_hosts",0)
            nids.param("filename",options['filename'])
            if options['bpf'] is not None:
                nids.param("pcap_filter", options['bpf'])

            try:
                nids.init()
            except Exception, e:
                self.complete = True
                chop.prnt("Error initting: ", e)
                return

            nids.chksum_ctl([('0.0.0.0/0',False),])
            nids.register_tcp(handleTcpStreams)
            nids.register_udp(handleUdpDatagrams)
            nids.register_ip(handleIpPackets)

            while(not self.stopped): #This overall while prevents exceptions from halting the long running reading
                try:
                    if options['longrun']: #long running don't stop until the proces is killed externally
                        while not self.stopped:
                            if not nids.next():
                                if self.abort: #exit if sigabrt if no other data
                                    break
                                time.sleep(.001)
                    else:
                        while not self.stopped and nids.next():
                            pass
                    self.stopped = True #Force it to true and exit
                except Exception, e:
                    chop.prnt("Error processing packets", e)
                    if not options['longrun']:
                        self.stopped = True #Force it to true and exit

        chop.prettyprnt("RED", "Shutting Down Modules ...")

        #Call modules shutdown functions to do last-minute actions
        for module in all_modules:
            try:
                chop.prettyprnt("CYAN","\tShutting Down " + module.code.moduleName)
                module.code.shutdown(module.module_data)
            except Exception,e:
                pass

        chop.prettyprnt("RED", "Module Shutdown Complete ...")
        self.complete = True

def handleIpPackets(pkt):
    global timestamp
    global metadata
    global once

    ptimestamp = nids.get_pkt_ts()


    if len(pkt) >= 20:#packets should have at least a 20 byte header
                      #nids should take care of this, but better safe than sorry, I guess
        ip = process_ip_data(pkt)

        metadata['proto'] = 'ip'
        metadata['time'] = ptimestamp
        metadata['addr'] = { 'src': ip.src,
                             'dst': ip.dst,
                             'dport': '',
                             'sport': ''
                            }

        for module in ip_modules:
            code = module.code
            #TODO do we need a shallow or deep copy?
            ipd = copy.copy(ip)        
            ipd.timestamp = ptimestamp
            ipd.module_data = module.module_data

            try:
                output = code.handlePacket(ipd)
            except Exception, e:
                exc = traceback.format_exc()
                chop.prettyprnt("YELLOW", "Exception in module %s -- Traceback: \n%s" % (code.moduleName, exc))
                sys.exit(-1)

            module.module_data = ipd.module_data

            #Handle Children
            if not module.legacy:
                if output is not None:
                    ipd.unique = ipd.src + "-" + ipd.dst
                    ipd.type = 'ip'
                    handleChildren(module, ipd, output)


            del ipd            


    else: #some error?
        chop.prnt("Malformed ip data received from nids ... skipping")

def handleUdpDatagrams(addr, data, ip):
    global ptimestamp
    global metadata
    ptimestamp = nids.get_pkt_ts()
    ((src,sport),(dst,dport)) = addr
    if src < dst:
        f_string = src + ":" + str(sport) + "-" + dst + ":" + str(dport)
    else:
        f_string = dst + ":" + str(dport) + "-" + src + ":" + str(sport)


    metadata['proto'] = 'udp'
    metadata['time'] = ptimestamp
    metadata['addr'] = { 'src' : src,
                         'dst' : dst,
                         'sport' : sport,
                         'dport' : dport
                       }

    stopped = False
    for module in udp_modules:
        code = module.code
        if f_string in module.streaminfo['udp'] and module.streaminfo['udp'][f_string] == None:
            # This module called udp.stop() for this f_string
            continue

        # Create new udp object
        udpd = copy_udp_data(addr, data, ip)
        udpd.timestamp = ptimestamp
        udpd.module_data = module.module_data

        if f_string not in module.streaminfo['udp']:
            # First time this module has seen this f_string.
            # Create a new stream_data object. Will save it later.
            module.streaminfo['udp'][f_string] = stream_meta()
            udpd.stream_data = stream_meta().stream_data
        else:
            udpd.stream_data = module.streaminfo['udp'][f_string].stream_data

        try:
            output = code.handleDatagram(udpd)
        except Exception, e:
            exc = traceback.format_exc()
            chop.prettyprnt("YELLOW", "Exception in module %s -- Traceback: \n%s" % (code.moduleName, exc))
            sys.exit(-1)

        #Have to copy the information back now
        module.module_data = udpd.module_data

        #Handle Children
        if not module.legacy:
            if output is not None:
                udpd.unique = f_string
                udpd.type = "udp"
                handleChildren(module, udpd, output) 

        if udpd.sval: #we were told by this module to stop collecting
            del udpd
            module.streaminfo['udp'][f_string] = None
            stopped = True
            continue
        #else we continue on since this module is still collecting
        module.streaminfo['udp'][f_string].stream_data = udpd.stream_data
        del udpd

def handleTcpStreams(tcp):
    end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)
    client_direction = False
    if tcp.server.count_new == 0:
        smallest_discard = tcp.client.count_new
        client_direction = True
    else:
        smallest_discard = tcp.server.count_new

    global ptimestamp
    global metadata
    ptimestamp = nids.get_pkt_ts()
    ((src,sport),(dst,dport)) = tcp.addr
    f_string = src + ":" + str(sport) + "-" + dst + ":" + str(dport)

    metadata['proto'] = 'tcp'
    metadata['time'] = ptimestamp
    metadata['addr'] = { 'src' : src,
                         'dst' : dst,
                         'sport' : sport,
                         'dport' : dport
                       }

    if tcp.nids_state == nids.NIDS_JUST_EST: #Implement tasting
        for module in tcp_modules:
            code = module.code
            collecting = False
            try:
                temp_info = stream_meta(0,0)

                tcpd = copy_tcp_data(tcp,temp_info,0)
                tcpd.timestamp = ptimestamp
                tcpd.module_data = module.module_data
                #Create a temporary stream_data in case the module needs it -- it'll be saved if the module decides to collect
                tcpd.stream_data = stream_meta().stream_data #Yes I could probably do = {} but this is more descriptive
                collecting = code.taste(tcpd)

            except Exception, e:
                chop.prettyprnt("YELLOW", "Module %s error in taste function: %s" % (code.moduleName, str(e)))
                sys.exit(-1)

            module.module_data = tcpd.module_data

            if collecting:
                module.streaminfo['tcp'][f_string] = stream_meta() 
                module.streaminfo['tcp'][f_string].stream_data = tcpd.stream_data
                tcp.client.collect = 1
                tcp.server.collect = 1

            del tcpd


    elif tcp.nids_state == nids.NIDS_DATA:#Implement data processing portion
        stopped = False
        for module in tcp_modules:
            code = module.code
            if f_string in module.streaminfo['tcp']: #If this module is collecting on this stream

                #Create a copy of the data customized for this module
                tcpd = copy_tcp_data(tcp, module.streaminfo['tcp'][f_string], client_direction) 
                tcpd.timestamp = ptimestamp
                tcpd.stream_data = module.streaminfo['tcp'][f_string].stream_data
                tcpd.module_data = module.module_data


                try:
                    output = code.handleStream(tcpd)
                except Exception, e:
                    exc = traceback.format_exc()
                    chop.prettyprnt("YELLOW", "Exception in module %s -- Traceback: \n%s" % (code.moduleName, exc))
                    sys.exit(1)

                #Have to copy the information back now
                module.module_data = tcpd.module_data


                if not module.legacy:
                    if output is not None:
                        tcpd.unique = f_string
                        tcpd.type = "tcp"
                        handleChildren(module, tcpd, output)

                if tcpd.sval: #we were told by this module to stop collecting
                    del tcpd
                    del module.streaminfo['tcp'][f_string]
                    stopped = True

                    #TODO check for potential over deletion? -- Also should we be deleting children here?
                    #TODO add deletion sequence from teardown below for children
                    continue
                #else we continue on since this module is still collecting
                module.streaminfo['tcp'][f_string].stream_data = tcpd.stream_data
                module.streaminfo['tcp'][f_string].last_discard = tcpd.dval

                if tcpd.dval < smallest_discard:
                    smallest_discard = tcpd.dval

                del tcpd


        #TODO collapse this with the lower for loop
        #Cleanup in case no more modules are collecting on this stream
        if stopped:
            found = False
            for module in tcp_modules:
                if f_string in module.streaminfo['tcp']:
                    found = True
                    continue

            if not found:
                tcp.client.collect = 0
                tcp.server.collect = 0


        for module in tcp_modules:
            code = module.code
            if f_string in module.streaminfo['tcp']:
                if module.streaminfo['tcp'][f_string].last_discard > smallest_discard:
                    diff = module.streaminfo['tcp'][f_string].last_discard - smallest_discard
                    if client_direction:
                        module.streaminfo['tcp'][f_string].offset_client += diff
                    else:
                        module.streaminfo['tcp'][f_string].offset_server += diff

        tcp.discard(smallest_discard)


    elif tcp.nids_state in end_states: #Teardown portion of code
        for module in tcp_modules:
            code = module.code
            if f_string in module.streaminfo['tcp']:
                try:
                    tcpd = copy_tcp_data(tcp, module.streaminfo['tcp'][f_string], client_direction) 
                    tcpd.timestamp = ptimestamp
                    tcpd.stream_data = module.streaminfo['tcp'][f_string].stream_data
                    tcpd.module_data = module.module_data
                    try:
                        output = code.teardown(tcpd)
                    except Exception, e:
                        output = None
                        exc = traceback.format_exc()
                        chop.prettyprnt("YELLOW", "Exception in module %s -- Traceback: \n%s" % (code.moduleName, exc))

                    if not module.legacy:
                        if output is not None:
                            if isinstance(output, ChopProtocol):
                                output._teardown = True
                            elif isinstance(output, list):
                                for o in output:
                                    if isinstance(o, ChopProtocol):
                                        o._teardown = True
                            tcpd.unique = f_string
                            tcpd.type = 'tcp'
                            handleChildren(module, tcpd, output)

                        
                except Exception, e:
                    exc = traceback.format_exc()
                    chop.prettyprnt("YELLOW", "Exception in module %s -- Traceback: \n%s" % (code.moduleName, exc))


                #delete the entry in the streaminfo dict
                del tcpd
                del module.streaminfo['tcp'][f_string]

                #TODO check for potential over deletion?
                if not module.legacy:
                    for outtype in module.inputs['tcp']: #For every output from tcp
                        for child in module.children:
                            if outtype not in child.inputs: #Check if this child accepts this type
                                continue
                            #This assumes unique has not been changed in the child
                            if f_string in child.streaminfo[outtype]:
                                del child.streaminfo[outtype][f_string]


def handleProtocol(module, protocol, pp): #pp is parent protocol
    code = module.code

    #unique should be set for all parents, including the standard tcp/udp types
    if protocol.unique is None:
        protocol.unique = pp.unique

    try:
        #If this excepts it's probably because protocol.type is not in streaminfo which should
        #have been created earlier -- this is an error on the part of the module author then

        #Initialize the object -- the pp.unique parent dictionary should have been initialized by parent function
        if protocol.unique not in module.streaminfo[protocol.type]:
            module.streaminfo[protocol.type][protocol.unique] = stream_meta()

        if module.streaminfo[protocol.type][protocol.unique] is None: #module has called stop
            return

        protocol.stream_data = module.streaminfo[protocol.type][protocol.unique].stream_data

    except KeyError, e:
        chop.prettyprnt("YELLOW", "Error attempting to lookup stream_data")
        sys.exit(1)
    except Exception, e:
        chop.prettyprnt("YELLOW", "Error attempting to set stream_data: %s" % str(e))
        sys.exit(1)

    #Add module_data to protocol object
    protocol.module_data = module.module_data

    #Elements that are common between tcp/udp and ChopProtocol
    if protocol.addr is None:
        protocol.setAddr(pp.addr)

    if protocol.timestamp is None:
        protocol.setTimeStamp(pp.timestamp)


    #TODO figure out if this is necessary and remove if not
    if isinstance(pp, ChopProtocol): #This is a 3rd level module (parent is not tcp or udp)
        pass
    else: #This is a 2nd level module (parent is tcp or udp)
        pass


    try:
        output = code.handleProtocol(protocol) 
    except Exception, e:
        exc = traceback.format_exc()
        chop.prettyprnt("YELLOW", "Exception in module %s -- Traceback: \n%s" % (code.moduleName, exc))
        sys.exit(1)


    #Copy it back just in case
    module.module_data = protocol.module_data


    #Handle any potential children
    if output is not None:
        handleChildren(module, protocol, output)

    if protocol.sval:
        module.streaminfo[protocol.type][protocol.unique] = None
        #Reset sval so it doesn't affect other children
        protocol.sval = False
        return

    module.streaminfo[protocol.type][protocol.unique].stream_data = protocol.stream_data

def teardownProtocol(module, protocol, pp):
    code = module.code

    #unique should be set for all parents, including the standard tcp/udp types
    if protocol.unique is None:
        protocol.unique = pp.unique

    try:
        #If this excepts it's probably because protocol.type is not in streaminfo which should
        #have been created earlier -- this is an error on the part of the module author then

        #Initialize the object -- the pp.unique parent dictionary should have been initialized by parent function
        if protocol.unique not in module.streaminfo[protocol.type]:
            module.streaminfo[protocol.type][protocol.unique] = stream_meta()

        if module.streaminfo[protocol.type][protocol.unique] is None: #module has called stop
            return

        protocol.stream_data = module.streaminfo[protocol.type][protocol.unique].stream_data

    except KeyError, e:
        chop.prettyprnt("YELLOW", "Error attempting to lookup stream_data")
        sys.exit(1)
    except Exception, e:
        chop.prettyprnt("YELLOW", "Error attempting to set stream_data: %s" % str(e))
        sys.exit(1)

    #Add module_data to protocol object
    protocol.module_data = module.module_data

    #Elements that are common between tcp/udp and ChopProtocol
    if protocol.addr is None:
        protocol.setAddr(pp.addr)

    if protocol.timestamp is None:
        protocol.setTimeStamp(pp.timestamp)


    try:
        try:
            code.teardownProtocol
        except AttributeError, e:
            return
        else:
            output = code.teardownProtocol(protocol) 
    except Exception, e:
        exc = traceback.format_exc()
        chop.prettyprnt("YELLOW", "Exception in module %s -- Traceback: \n%s" % (code.moduleName, exc))
        sys.exit(1)


    #Copy it back just in case
    module.module_data = protocol.module_data


    #Handle any potential children
    if output is not None:
        if isinstance(output, ChopProtocol):
            output._teardown = True
        elif isinstance(output, list):
            for o in output:
                if isinstance(o, ChopProtocol):
                    o._teardown = True

        handleChildren(module, protocol, output)

    #TODO delete this since this is torn down?
    module.streaminfo[protocol.type][protocol.unique].stream_data = protocol.stream_data


def handleChildren(module, protocol, output):
    #Handle any potential children
    code = module.code
    if isinstance(output, ChopProtocol):
        output = [output]
    elif not isinstance(output, list):
        chop.prettyprnt("YELLOW", "Module %s returned an invalid type" % code.moduleName)
        sys.exit(1)

    for outp in output:
        if not isinstance(outp, ChopProtocol):
            chop.prettyprnt("YELLOW", "Module %s returned an invalid type" % code.moduleName)
            sys.exit(1)

        if outp.type not in module.inputs[protocol.type]:
            chop.prettyprnt("YELLOW", "Module %s returning unregistered type %s" % (code.moduleName, outp.type))
            sys.exit(1)

        for child in module.children:
            if outp.type in child.inputs or 'any' in child.inputs:
                #This ensure each child gets a copy that it can muck with
                child_copy = outp._clone() 
                if outp._teardown:
                    teardownProtocol(child, child_copy, protocol)
                else:
                    handleProtocol(child, child_copy, protocol)
