#!/usr/bin/env python

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


import ChopShopDebug as CSD

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

class hstream:
    pass

class stream_meta:
    def __init__(self,of=0,os=0):
        self.stream_data = {}
        self.offset_client = of
        self.offset_server = os

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
            module = module[0]
            module.chop = self.chophelper.setup_module(module.moduleName)

    def run(self):
        global chop
        #Initialize modules to be run
        options = self.options
        modules = self.module_list#module_list
        module_options = {}

        chop.prettyprnt("RED", "Initializing Modules ...")

        for module in modules:
            name = module[2]
            arguments = shlex.split(module[1])
            module = module[0]
            #Create module_data for all modules
            module.module_data = {'args':arguments}
            module.streaminfo = {}

            chop.prettyprnt("CYAN", "\tInitializing module '" + name + "'")
            try:
                module_options = module.init(module.module_data)
            except Exception, e:
                chop.prnt("Error Initializing Module", module.moduleName + ":", e)
                self.complete = True
                return

            if 'error' in module_options:
                chop.prettyprnt("GREEN", "\t\t%s init failure: %s" % (module.moduleName, module_options['error']))
                continue

            if module_options['proto'] == 'tcp' :
                tcp_modules.append(module)
                all_modules.append(module)
            elif module_options['proto'] == 'ip' :
                ip_modules.append(module)
                all_modules.append(module)
            elif module_options['proto'] == 'udp' :
                udp_modules.append(module)
                all_modules.append(module)
            else:
                chop.prnt("Undefined Module Type\n")
                self.complete = True
                return

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

            while(True): #This overall while prevents exceptions from halting the long running reading
                if self.stopped:
                    break
                try:
                    if options['longrun']: #long running don't stop until the proces is killed externally
                        while not self.stopped:
                            if not nids.next():
                                time.sleep(.001)
                    else:
                        while not self.stopped and nids.next():
                            pass
                        self.stopped = True #Force it to true and exit
                except Exception, e:
                    if not options['longrun']:
                        self.stopped = True #Force it to true and exit
                    chop.prnt("Error processing packets", e)


        chop.prettyprnt("RED", "Shutting Down Modules ...")

        #Call modules shutdown functions to do last-minute actions
        for module in all_modules:
            try:
                chop.prettyprnt("CYAN","\tShutting Down " + module.moduleName)
                module.shutdown(module.module_data)
            except Exception,e:
                pass

        chop.prettyprnt("RED", "Module Shutdown Complete ...")
        self.complete = True

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
        if f_string in module.streaminfo and module.streaminfo[f_string] == None:
            # This module called udp.stop() for this f_string
            continue

        # Create new udp object
        udpd = copy_udp_data(addr, data, ip)
        udpd.timestamp = ptimestamp
        udpd.module_data = module.module_data

        if f_string not in module.streaminfo:
            # First time this module has seen this f_string.
            # Create a new stream_data object. Will save it later.
            module.streaminfo[f_string] = stream_meta()
            udpd.stream_data = stream_meta().stream_data
        else:
            udpd.stream_data = module.streaminfo[f_string].stream_data

        try:
            module.handleDatagram(udpd)
        except Exception, e:
            exc = traceback.format_exc()
            chop.prettyprnt("YELLOW", "Exception in module %s -- Traceback: \n%s" % (module.moduleName, exc))
            sys.exit(-1)

        #Have to copy the information back now
        module.module_data = udpd.module_data

        if udpd.sval: #we were told by this module to stop collecting
            del udpd
            module.streaminfo[f_string] = None
            stopped = True
            continue
        #else we continue on since this module is still collecting
        module.streaminfo[f_string].stream_data = udpd.stream_data
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
            collecting = False
            try:
                temp_info = stream_meta(0,0)

                tcpd = copy_tcp_data(tcp,temp_info,0)
                tcpd.timestamp = ptimestamp
                tcpd.module_data = module.module_data
                #Create a temporary stream_data in case the module needs it -- it'll be saved if the module decides to collect
                tcpd.stream_data = stream_meta().stream_data #Yes I could probably do = {} but this is more descriptive
                collecting = module.taste(tcpd)

            except Exception, e:
                chop.prettyprnt("YELLOW", "Module %s error in taste function: %s" % (module.moduleName, str(e)))
                sys.exit(-1)

            module.module_data = tcpd.module_data

            if collecting:
                module.streaminfo[f_string] = stream_meta()
                module.streaminfo[f_string].stream_data = tcpd.stream_data
                tcp.client.collect = 1
                tcp.server.collect = 1

            del tcpd


    elif tcp.nids_state == nids.NIDS_DATA:#Implement data processing portion
        stopped = False
        for module in tcp_modules:
            if f_string in module.streaminfo: #If this module is collecting on this stream

                #Create a copy of the data customized for this module
                tcpd = copy_tcp_data(tcp,module.streaminfo[f_string],client_direction)
                tcpd.timestamp = ptimestamp
                tcpd.stream_data = module.streaminfo[f_string].stream_data
                tcpd.module_data = module.module_data


                try:
                    module.handleStream(tcpd)
                except Exception, e:
                    exc = traceback.format_exc()
                    chop.prettyprnt("YELLOW", "Exception in module %s -- Traceback: \n%s" % (module.moduleName, exc))
                    sys.exit(-1)

                #Have to copy the information back now
                module.module_data = tcpd.module_data

                if tcpd.sval: #we were told by this module to stop collecting
                    del tcpd
                    del module.streaminfo[f_string]
                    stopped = True
                    continue
                #else we continue on since this module is still collecting
                module.streaminfo[f_string].stream_data = tcpd.stream_data
                module.streaminfo[f_string].last_discard = tcpd.dval

                if tcpd.dval < smallest_discard:
                    smallest_discard = tcpd.dval

                del tcpd


        #TODO collapse this with the lower for loop
        #Cleanup in case no more modules are collecting on this stream
        if stopped:
            found = False
            for module in tcp_modules:
                if f_string in module.streaminfo:
                    found = True
                    continue

            if not found:
                tcp.client.collect = 0
                tcp.server.collect = 0


        for module in tcp_modules:
            if f_string in module.streaminfo:
                if module.streaminfo[f_string].last_discard > smallest_discard:
                    diff = module.streaminfo[f_string].last_discard - smallest_discard
                    if client_direction:
                        module.streaminfo[f_string].offset_client += diff
                    else:
                        module.streaminfo[f_string].offset_server += diff

        tcp.discard(smallest_discard)


    elif tcp.nids_state in end_states: #Teardown portion of code
        for module in tcp_modules:
            if f_string in module.streaminfo:
                try:
                    tcpd = copy_tcp_data(tcp,module.streaminfo[f_string],client_direction)
                    tcpd.timestamp = ptimestamp
                    tcpd.stream_data = module.streaminfo[f_string].stream_data
                    tcpd.module_data = module.module_data
                    module.teardown(tcpd)
                except Exception, e:
                    exc = traceback.format_exc()
                    chop.prettyprnt("YELLOW", "Exception in module %s -- Traceback: \n%s" % (module.moduleName, exc))

                #delete the entry in the streaminfo dict
                del tcpd
                del module.streaminfo[f_string]


