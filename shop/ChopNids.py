#!/usr/bin/env python

# Copyright (c) 2012 The MITRE Corporation. All rights reserved.
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
import signal
import os
import tempfile
import imp
import nids
import fileinput
import fcntl
import string
import gc
import shlex
import traceback
from optparse import OptionParser
from threading import Thread
from threading import Lock
import threading
from multiprocessing import Process, Manager, Queue as mQueue
import Queue
import time

from ChopHelper import CoreCommander

import ChopShopDebug as CSD

tcp_modules = []
ip_modules = []
udp_modules = []
all_modules = []

ptimestamp = 0

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
    def __init__(self,options, module_list):
        Thread.__init__(self)
        self.options = options
        self.module_list = module_list

        self.stopped = False
        self.complete = False

    def stop(self):
        self.complete = True
        self.stopped = True

    def iscomplete(self):
        return self.complete

    def getptime(self):
        global ptimestamp
        return ptimestamp

    def prep_modules(self):
        modules = self.module_list
        for module in modules:
            module = module[0]
            module.chop = corecommand.setup_module(module.moduleName)

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

            #Setup queue, panel and chop command for the module
            #XXX
            #module.chop = outcommand.setup_window(module.moduleName)

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
        if options.interface:
            nids.param("scan_num_hosts",0)
            nids.param("device",options.interface)
            try:
                nids.init()
            except Exception, e:
                chop.prnt("Error initting: ", e) 
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
            if options.filename is "":
                chop.prnt("Empty Filename")
                self.complete = True
                return

            nids.param("scan_num_hosts",0)
            nids.param("filename",options.filename)

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
                    if options.longrun: #long running don't stop until the proces is killed externally
                        while not self.stopped:
                            if not nids.next():
                                time.sleep(.001)
                    else:
                        while not self.stopped and nids.next(): 
                            pass
                        self.stopped = True #Force it to true and exit
                except Exception, e:
                    if not options.longrun:
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

        chop.prettyprnt("RED", "Shutdown Complete ... ChopShop Processes finished")
        self.complete = True

def handleUdpDatagrams(addr, data, ip):
    global ptimestamp
    ptimestamp = nids.get_pkt_ts()
    ((src,sport),(dst,dport)) = addr
    if src < dst:
        f_string = src + ":" + str(sport) + "-" + dst + ":" + str(dport)
    else:
        f_string = dst + ":" + str(dport) + "-" + src + ":" + str(sport)

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
    ptimestamp = nids.get_pkt_ts()
    ((src,sport),(dst,dport)) = tcp.addr
    f_string = src + ":" + str(sport) + "-" + dst + ":" + str(dport)



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


def loadModules(name, path):
    try:
        (file, pathname, description) = imp.find_module(name, [path])
        loaded_mod = imp.load_module(name, file, pathname, description)
    except Exception, e:
        traceback.print_exc()
        print "Exception:" , e
        sys.exit("Error loading module '" + name + "'")

    return loaded_mod


def __core_runner_(iq, oq, dq):
    os.setpgrp()
    global inq
    global outq
    global corecommand

    inq = iq
    outq = oq

    corecommand = CoreCommander(inq, outq, dq)

    options = None
    module_list = []
    ccore = None
    mod_dir = None

    while (True):
        try:
            data = inq.get(True, .1)
        except Queue.Empty, e:
            continue


        if data[0] == 'opt':
            options = data[1]

            #Set up the module directory and the external libraries directory
            mod_dir = options.mod_dir
            ext_dir = options.ext_dir
            if options.base_dir:
                base_dir = os.path.realpath(options.base_dir)
                mod_dir = base_dir + '/modules/'
                ext_dir = base_dir + '/ext_libs/'
            sys.path.append(os.path.realpath(ext_dir))
        elif data[0] == 'load_mod':
            args = data[1]
            mods = args[0].split(';')
            for mod in mods:
                mod = mod.strip()
                sindex = mod.find(' ')
                if sindex != -1:
                    modl = []
                    modl.append(loadModules(mod[0:sindex],mod_dir))
                    modl.append(mod[sindex + 1:])
                    modl.append(mod[0:sindex])
                    module_list.append(modl)
                else:
                    modl = []
                    modl.append(loadModules(mod,mod_dir))
                    modl.append("")
                    modl.append(mod)
                    module_list.append(modl)
            if len(module_list) == 0:
                outq.put('zero')
            else:
                outq.put('fini')
        elif data[0] == 'mod_info':
            for mod in module_list:
                print mod[0].moduleName + ":",
                try:
                    mod[0].module_info()
                    sys.stdout.write("\n")
                except Exception, e:
                    print "Missing module information for %s" % mod[2]
                    sys.stdout.write("\n")
                try:
                    sys.argv[0] = mod[0].moduleName
                    mod[0].init({'args': ['-h']})
                except SystemExit, e:
                    pass
                sys.stdout.write("\n") 
            outq.put('fini')
            return
        elif data[0] == 'cont':
            break
        elif data[0] == 'exit':
            return

    try:
        f = open('/dev/null', 'w')
        os.dup2(f.fileno(), 1)
        g = open('/dev/null', 'r')
        os.dup2(g.fileno(), 0)
    except:
        CSD.debug_out("Error assigning dev/null as output\n")

    corecommand.setup_var(options)
    #Setup main and debug handlers
    ccore = ChopCore(options, module_list)

    global chop
    #Setups up main/debug panels/windows and also informs other side that we're ready
    #to setup module windows/panels
    chop = corecommand.setup_modules_begin(ccore)

    #setup ccore Core
    #Sets up 'chop' class and windows/panels
    ccore.prep_modules()

    #Inform other side we're done setting up modules
    corecommand.setup_modules_end()


    while (True):
        if ccore.complete:
            break

        try:
            data = inq.get(True, .1)
        except Queue.Empty, e:
            continue

        if data[0] == 'msg':
            chop.prettyprnt(data[1], data[2])
        elif data[0] == 'start':
            ccore.start()
        elif data[0] == 'stop':
            ccore.stop()
            break

    ccore.join()
    corecommand.join()

