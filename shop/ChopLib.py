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


VERSION = 3.0

import sys
import os
import imp
import traceback
from threading import Thread, Lock

CHOPSHOP_WD = os.path.realpath(os.path.dirname(sys.argv[0]))

sys.path.append(CHOPSHOP_WD + '/shop')

from ChopNids import ChopCore
from ChopHelper import ChopHelper 
from ChopSurgeon import Surgeon
from ChopException import ChopLibException


class ChopLib(Thread):
    def __init__(self):
        Thread.__init__(self)
        global CHOPSHOP_WD

        pyversion = sys.version_info
        pyversion = float(str(pyversion[0]) + "." + str(pyversion[1]))

        if pyversion < 2.6:
            raise ChopLibException("Minimum Python Version 2.6 Required")

        global Queue
        global Process
        from multiprocessing import Process, Queue
        from Queue import Empty
        Queue.Empty = Empty #I'd prefer to keep this scoped to Queue

        self.options = { 'mod_dir': CHOPSHOP_WD + '/modules/',
                         'ext_dir': CHOPSHOP_WD + '/ext_libs/',
                         'base_dir': None,
                         'filename': '',
                         'filelist': None,
                         'aslist': False,
                         'longrun': False,
                         'interface': '',
                         'modinfo': False,
                         'GMT': False,
                         'savefiles': False, #Should ChopShop handle the saving of files?
                         'text': False,
                         'jsonout': False,
                         'savedir': '/tmp/',
                         'modules': ''
                       }

        self.stopped = False


        #Setup Interaction Queues
        self.tocaller = Queue() #output directly to caller
        self.fromnids = Queue() #input queue from nids process
        self.tonids = Queue() #output queue to nids process

        #Start up Process 2 (Nids Process)
        self.nidsp = Process(target=self.__nids_core_runner_, args=(self.tonids, self.fromnids, self.tocaller))
        self.nidsp.daemon = True
        self.nidsp.start()

        self.chop = None

    @property
    def mod_dir(self):
        """Directory to load modules from."""
        return self.options['mod_dir']

    @mod_dir.setter
    def mod_dir(self, v):
        self.options['mod_dir'] = v

    @property
    def ext_dir(self):
        """Directory to load external libraries from."""
        return self.options['ext_dir']

    @ext_dir.setter
    def ext_dir(self, v):
        self.options['ext_dir'] = v

    @property
    def base_dir(self):
        """Base directory to load modules and external libraries."""
        return self.options['base_dir']

    @base_dir.setter
    def base_dir(self, v):
        self.options['base_dir'] = v

    @property
    def filename(self):
        """input pcap file."""
        return self.options['filename']

    @filename.setter
    def filename(self, v):
        self.options['filename'] = v

    @property
    def filelist(self):
        """list of files to process"""
        return self.options['filelist']

    @filelist.setter
    def filelist(self, v):
        self.options['filelist'] = v

    @property
    def aslist(self):
        """Treat filename as a file containing a list of files."""
        return self.options['aslist']

    @aslist.setter
    def aslist(self, v):
        self.options['aslist'] = v

    @property
    def longrun(self):
        """Read from filename forever even if there's no more pcap data."""
        return self.options['longrun']

    @longrun.setter
    def longrun(self, v):
        self.options['longrun'] = v

    @property
    def interface(self):
        """interface to listen on."""
        return self.options['interface']

    @interface.setter
    def interface(self, v):
        self.options['interface'] = v

    @property
    def modinfo(self):
        """print information about module(s) and exit."""
        return self.options['modinfo']

    @modinfo.setter
    def modinfo(self, v):
        self.options['modinfo'] = v

    @property
    def GMT(self):
        """timestamps in GMT (tsprnt and tsprettyprnt only)."""
        return self.options['GMT']

    @GMT.setter
    def GMT(self, v):
        self.options['GMT'] = v

    @property
    def savefiles(self):
        """Handle the saving of files. """
        return self.options['savefiles']

    @savefiles.setter
    def savefiles(self, v):
        self.options['savefiles'] = v

    @property
    def text(self):
        """Handle text/printable output. """
        return self.options['text']

    @text.setter
    def text(self, v):
        self.options['text'] = v

    @property
    def jsonout(self):
        """Handle JSON Data (chop.json)."""
        return self.options['jsonout']

    @jsonout.setter
    def jsonout(self, v):
        self.options['jsonout'] = v

    @property
    def savedir(self):
        """Location to save carved files."""
        return self.options['savedir']

    @savedir.setter
    def savedir(self, v):
        self.options['savedir'] = v

    @property
    def modules(self):
        """String of Modules to execute"""
        return self.options['modules']

    @modules.setter
    def modules(self, v):
        self.options['modules'] = v


    def get_message_queue(self):
        return self.tocaller

    def get_stop_fn(self):
        return self.stop
       
    def version(self):
        global VERSION
        return VERSION 

    def stop(self):
        self.stopped = True

    def setup_local_chop(self, name = "ChopShop"):
        #This allows Process 1 to access Chops, note that it has
        #a hardcoded id of -1 since otherwise it might overlap
        #with the other chops
        chophelper = ChopHelper(self.tocaller, self.options)
        self.chop = chophelper.setup_module(name, -1)
        


    def run(self):
        surgeon = None

        if not self.options['modinfo']: #No point in doing surgery if it's modinfo
            # Figure out where we're reading packets from
            if not self.options['interface']:
                if not self.options['filename']:
                    if not self.options['filelist']:
                        raise ChopLibException("No input specified")
                    else:
                        surgeon = Surgeon(self.options['filelist'])
                        self.options['filename'] = surgeon.create_fifo()
                        surgeon.operate()
                else:
                    if not os.path.exists(self.options['filename']):
                        #print "Unable to find file '%s'" % self.options['filename']
                        raise ChopLibException("Unable to find file '%s'" % self.options['filename'])
                        #sys.exit(-1)

                    if self.options['aslist']:
                        #input file is a listing of files to process
                        surgeon = Surgeon([self.options['filename']], self.options['longrun'])
                        self.options['filename'] = surgeon.create_fifo()
                        #TODO operate right away or later?
                        surgeon.operate(True)

        #Send options to Process 2 and tell it to setup
        self.tonids.put(['init', self.options])
        #Wait for a reponse
        resp = self.fromnids.get()
        if resp != 'ok':
            raise ChopLibException(resp)

        if self.options['modinfo']:
            self.tonids.put(['mod_info'])
            resp = self.fromnids.get() #really just to make sure the functions finish
            #Process 2 will quit after doing its job

            #Inform caller that the process is done
            message = { 'type' : 'ctrl',
                        'data' : {'msg'  : 'finished'}
                      }
            
            self.tocaller.put(message)

            #Surgeon should not be invoked son only need
            #to cleanup nidsp
            self.nidsp.join()
            return

        else:
            self.tonids.put(['cont'])

        
        #Processing loop
        while True:
            try:
                data = self.fromnids.get(True, .1)
            except Queue.Empty, e:
                if not self.nidsp.is_alive():
                    break

                if self.stopped:
                    self.nidsp.terminate()                
                continue

            if data[0] == "stop": 
                #Send the message to caller that we need to stop
                message = { 'type' : 'ctrl',
                            'data' : {'msg'  : 'stop'}
                          }
                self.tocaller.put(message)

                self.nidsp.join(1)

                #Force Terminate if nids process is non-compliant
                if self.nidsp.is_alive():
                    self.nidsp.terminate()
                break

            time.sleep(.1)

        ###Teardown of the program
        #Join with Surgeon
        if surgeon is not None:
            surgeon.stop()
    
        #Join with Nids Process
        self.nidsp.join()

        #Inform caller that we are now finished
        message = { 'type' : 'ctrl',
                    'data' : {'msg'  : 'finished'}
                  }
        
        self.tocaller.put(message)


    #This must be torn down safely after who need it have cleaned up
    def finish(self):
        if self.nidsp.is_alive():
            self.nidsp.terminate()
        self.nidsp.join(.1)

        try:
            self.tonids.close()
            self.fromnids.close()
            self.tocaller.close()
        except:
            pass 


#######Process 2 Functions######

    def __loadModules_(self, name, path):
        try:
            (file, pathname, description) = imp.find_module(name, [path])
            loaded_mod = imp.load_module(name, file, pathname, description)
        except Exception, e:
            tb = traceback.format_exc()
            raise Exception(tb)

        return loaded_mod


    #Process 2 "main" process
    def __nids_core_runner_(self, inq, outq, dataq, autostart = True):
        #Note that even though this is within the class it is being used irrespective
        #of the Process 1 class, so 'self' is never used for data

        #Responsible for creating "chop" classes and
        #keeping track of the individual output handlers
        chophelper = None
        chop = None

        options = None
        module_list = []
        ccore = None
        mod_dir = None

        #Initialization
        while (True):
            try:
                data = inq.get(True, .1)
            except Queue.Empty, e:
                continue

            if data[0] == 'init':

                try:
                    f = open('/dev/null', 'w')
                    os.dup2(f.fileno(), 1)
                    g = open('/dev/null', 'r')
                    os.dup2(g.fileno(), 0)
                except:
                    outq.put("Unable to assign /dev/null as stdin/stdout")
                    sys.exit(-1)

                options = data[1]

                #Set up the module directory and the external libraries directory
                if options['base_dir'] is not None:
                    base_dir = os.path.realpath(options['base_dir'])
                    mod_dir = base_dir + "/modules/" 
                    ext_dir = base_dir + "/ext_libs" 
                else:
                    mod_dir = options['mod_dir'] 
                    ext_dir = options['ext_dir']

                sys.path.append(os.path.realpath(ext_dir))

                #Setup the chophelper 
                chophelper = ChopHelper(dataq, options)
                chop = chophelper.setup_main()

                #Setup the modules
                args = options['modules']
                mods = args.split(';')
                try:
                    for mod in mods:
                        mod = mod.strip()
                        sindex = mod.find(' ')
                        if sindex != -1:
                            modl = []
                            modl.append(self.__loadModules_(mod[0:sindex],mod_dir))
                            modl.append(mod[sindex + 1:])
                            modl.append(mod[0:sindex])
                            module_list.append(modl)
                        else:
                            modl = []
                            modl.append(self.__loadModules_(mod,mod_dir))
                            modl.append("")
                            modl.append(mod)
                            module_list.append(modl)
                except Exception, e:
                    outq.put(e)
                    sys.exit(-1)

                if len(module_list) == 0:
                    outq.put('Zero Length Module List')
                    sys.exit(-1)


                #It got this far, everything should be okay
                outq.put('ok')

            elif data[0] == 'mod_info':
                #Hijack stdout to support modules that use print
                from cStringIO import StringIO
                orig_stdout = sys.stdout #We don't know what the original stdout might have been (__stdout__)
                                         #Although it should be /dev/null
                sys.stdout = strbuff = StringIO()

                for mod in module_list:
                    modinf = mod[0].moduleName + ":"
                    modtxt = None
                    try:
                        modtxt = mod[0].module_info() 
                        if modtxt is not None:
                            modtxt = modtxt + "\n"
                        else:
                            modtxt = strbuff.getvalue()
                            if modtxt is not None:
                                modtxt = modtxt + "\n"
                    except Exception, e:
                        modtxt = "Missing module information for %s\n" % mod[2]

                    try:
                        sys.argv[0] = mod[0].moduleName
                        mod[0].init({'args': ['-h']})
                    except SystemExit, e:
                        #OptParse will except as it ends
                        modtxt = modtxt + strbuff.getvalue() + "\n"
                        pass

                    chop.prnt(modinf, modtxt)

                #Restore stdout
                sys.stdout = orig_stdout 
        

                outq.put('fini')
                sys.exit(0) 

            elif data[0] == 'cont':
                break
            else: 
                #FIXME custom exception?
                raise Exception("Unknown message")


        chop.prettyprnt("RED", "Starting the ChopShop")

        #Initialize the ChopShop Core
        ccore = ChopCore(options, module_list, chop, chophelper)

        #Setup Core and its modules
        ccore.prep_modules()

        
        if autostart:
            ccore.start()

        while (True):
            if ccore.complete:
                break

            try:
                data = inq.get(True, .1)
            except Queue.Empty, e:
                continue

            if data[0] == 'start':
                ccore.start()
            elif data[0] == 'stop':
                ccore.stop()

        ccore.join()

        chop.prettyprnt("RED", "ChopShop Complete")



