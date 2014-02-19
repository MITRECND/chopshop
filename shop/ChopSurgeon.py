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

#shop/ChopSurgeon


import sys
import os
import time
import tempfile
from multiprocessing import Process, Queue
from ChopSuture import Suture

import ChopShopDebug as CSD

class Surgeon:
    def __init__(self, files, long = False):
        self.files = files
        self.fifo = None
        self.tdir = None
        self.fname = None
        self.long = long
        self.tosurgeon = Queue()

    def __del__(self):
        self.cleanup_fifo()
        try:
            self.tosurgeon.close()
        except:
            pass

    def create_fifo(self):
        self.tdir = tempfile.mkdtemp()
        self.fname = os.path.join(self.tdir, 'chopfifo')

        try:
            os.mkfifo(self.fname)
        except OSError, e:
            print "Unable to create fifo: " + str(e)
            sys.exit(-1)

       
        return self.fname 

    def cleanup_fifo(self):
        if self.fifo is not None:
            self.fifo.close()
        if self.fname is not None:
            os.remove(self.fname)
        if self.tdir is not None:
            os.rmdir(self.tdir)


    def stop(self):
        #Forcefully Terminate since otherwise this might hang unnecessarily
        try:
            self.tosurgeon.put('kill')
            self.p.terminate()
            self.p.join()
        except Exception, e:
            pass

    def abort(self):
        try:
            self.tosurgeon.put('abort')
        except Exception, e:
            pass

    def operate(self, flist = False):
        if flist:
            self.p = Process(target=self.__surgeon_proc_list_, args = (self.files[0], self.fname, self.long, self.tosurgeon,)) 
        else:
            self.p = Process(target=self.__surgeon_proc_, args = (self.files, self.fname,))
        self.p.start()

    def __surgeon_proc_(self, files, fname):
        os.setpgrp()
        suture = Suture(files, False, fname)
        suture.process_files()

    def __surgeon_proc_list_(self, file, fname, long, inq):
        os.setpgrp()
        self.stopread = False
        self.long = long

        try:
            flist = open(file, 'r')
        except:
            return

        suture = Suture([], False, fname)
        suture.prepare_bunch()
        while(not self.stopread):
            files = []
            while(True):
                data = None
                try:
                    data = inq.get(True, .01)
                except Queue.Empty:
                    pass

                if data == 'abort':
                    self.long = False
                elif data == 'kill':
                    self.stopread = True

                line = flist.readline()
                if line == "":
                    break
                files.append(line[0:-1])

            if len(files) > 0:
                suture.process_bunch(files)

            if not self.long:
                break
            time.sleep(.1)

        flist.close()
        suture.end_bunch()
