#! /usr/bin/python

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

#shop/ChopSuture


import sys
import os
import struct
import time

	

class Suture:
    def __init__(self,files,verbose, output):
        self.filelist = []
        self.verbose = verbose
        self.outfile = None
        self.output = output
        self.halt = False
        self.first = False
        self.linktype = -1
        self.native = None


        for file in files:
            file = file.rstrip()
            self.filelist.append(file)

        if self.output != '-': #outputting to a file
            if verbose:
                vstring = "Writing to file: " + self.output + "\n"
                sys.stderr.write(vstring)

    
    def stop(self):
        self.halt = True
    
    def process_file(self, file):
        if self.halt: #Stop processing 
            return
        swap_bytes = False
        if self.verbose:
            vstring = "Reading file " + file + "\n"
            sys.stderr.write(vstring)

        infile = open(file,'rb')

        indata = ""
        
        #Read in Global Header - 24 bytes
        hdrinfo = infile.read(24)
        if len(hdrinfo) != 24:
            if self.verbose:
                vstring = "Skipping file " + file + " due to small header\n"
                sys.stderr.write(vstring)
            infile.close()
            return
        #Figure out what endian this file's headers are in
        #Try out little endian
        mn_little = struct.unpack('<I',hdrinfo[0:4])[0]

        if mn_little == 0xa1b2c3d4: #It's little endian
            file_order = '<'
        elif mn_little == 0xd4c3b2a1: #it's big endian
            file_order = '>'
        else: # It's neither
            if self.verbose:
                vstring = "Skipping file " + file + ". Appears to not be pcap\n"
                sys.stderr.write(vstring)
            infile.close()
            return

        if self.native == None: #first file
            self.native = file_order
        else: #we need to see if subsequent fields need to be switched
            if self.native != file_order: #the order of the file is not the order of the first file
                swap_bytes = True #we'll have to swap the packet header fields for subsequent packets


        #Check the link layer type and skip the file if not the same
        hdr_nw = struct.unpack( file_order + 'I',hdrinfo[20:24])[0]

        if not self.first:
            self.first = True
            indata = hdrinfo
            self.linktype = hdr_nw
        else:
            if hdr_nw != self.linktype:
                if self.verbose:
                    vstring = "Skipping file " + file + " due to link type\n"
                    sys.stderr.write(vstring)
                infile.close()
                return 

        #For Reference
        #hdr_mn = struct.unpack('I',hdrinfo[0:4])[0]
        #hdr_vs = struct.unpack('I',hdrinfo[4:8])[0]
        #hdr_tz = struct.unpack('I',hdrinfo[8:12])[0]
        #hdr_sf = struct.unpack('I',hdrinfo[12:16])[0]
        #hdr_sl = struct.unpack('I',hdrinfo[16:20])[0]
        #hdr_nw = struct.unpack('I',hdrinfo[20:24])[0]

        try:
            if self.output == '-':
                sys.stdout.write(indata)
            else:
                self.outfile.write(indata)
        except Exception, e:
            if self.verbose:
                vstring = "Exception writing header: %s\n" % str(e)
                sys.stderr.write(vstring)
            sys.exit(-1)

        #Now let's process each packet in the file
        while True:
            #First read in the packet header - 16 bytes
            phdr = infile.read(16)
            if len(phdr) < 16:
                break

            #Let's get the header into the same endian the first file was using
            if swap_bytes:
                nhdr = self.swapbytes(phdr[0:4]) + self.swapbytes(phdr[4:8]) + self.swapbytes(phdr[8:12]) + self.swapbytes(phdr[12:16])
                phdr = nhdr

            #After we swap bytes the header should be in our "native" order

            phd_inc = struct.unpack(self.native + 'I',phdr[8:12])[0]

            #For Reference
            #phd_tss = struct.unpack('I',phdr[0:4])[0]
            #phd_tsu = struct.unpack('I',phdr[4:8])[0]
            #phd_inc = struct.unpack('I',phdr[8:12])[0]
            #phd_orl = struct.unpack('I',phdr[12:16])[0]

            pdata = infile.read(phd_inc)
            #If there's not enough data in the file then more than likely this pcap is truncated
            if len(pdata) < phd_inc:
                break

            indata = (phdr + pdata)

            try:
                if self.output == '-':
                    sys.stdout.write(indata)
                else:
                    self.outfile.write(indata)
            except Exception, e:
                if self.verbose:
                    vstring = "Exception writing header: %s\n" % str(e)
                    sys.stderr.write(vstring)
                infile.close()
                sys.exit(-1)

        infile.close()

    def process_files(self):
        if self.output != '-':
            self.outfile = open(self.output,'w')

        for file in self.filelist:
            self.process_file(file)

        if self.output != '-':
            self.outfile.close


    def prepare_bunch(self):
        if self.output != '-':
            self.outfile = open(self.output, 'w')

    def process_bunch(self, filelist):
        for file in filelist:
            file = file.rstrip()
            self.process_file(file) 


    def end_bunch(self):
        if self.output != '-':
            self.outfile.close


    def swapbytes(self, byte_arr):
        #we're swapping endians, easiest way is to unpack in any endian
        #and repack with the opposite endian -- assumed 4 bytes

        temp = struct.unpack('>I',byte_arr)[0]
        out = struct.pack('<I',temp)

        return out

