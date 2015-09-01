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


VERSION = 4.3 

import ConfigParser
import sys
import os
import imp
import traceback
import time
from threading import Thread, Lock
import re
from cStringIO import StringIO


from ChopGV import CHOPSHOP_WD
from ChopNids import ChopCore
from ChopHelper import ChopHelper
from ChopSurgeon import Surgeon
from ChopException import ChopLibException
from ChopGrammar import ChopGrammar


DEFAULT_MODULE_DIRECTORY = CHOPSHOP_WD + '/modules/'
DEFAULT_EXTLIB_DIRECTORY = CHOPSHOP_WD + '/ext_libs/'
"""
    ChopLib is the core functionality of ChopShop. It provides a library interface to the processing side of chopshop
    Any output/UI functionality has been extracted and is not done by this class. ChopLib will output all output onto queue
    which can be used by the calling party to display information to the user
"""

class ChopLib(Thread):
    daemon = True
    def __init__(self):
        Thread.__init__(self, name = 'ChopLib')
        global DEFAULT_MODULE_DIRECTORY
        global DEFAULT_EXTLIB_DIRECTORY

        pyversion = sys.version_info
        pyversion = float(str(pyversion[0]) + "." + str(pyversion[1]))

        if pyversion < 2.6:
            raise ChopLibException("Minimum Python Version 2.6 Required")

        global Queue
        global Process
        from multiprocessing import Process, Queue
        from Queue import Empty
        Queue.Empty = Empty #I'd prefer to keep this scoped to Queue

        self.options = { 'mod_dir': [DEFAULT_MODULE_DIRECTORY],
                         'ext_dir': [DEFAULT_EXTLIB_DIRECTORY],
                         'base_dir': None,
                         'filename': '',
                         'filelist': None,
                         'bpf': None,
                         'aslist': False,
                         'longrun': False,
                         'interface': '',
                         'modinfo': False,
                         'modtree': False,
                         'GMT': False,
                         'savefiles': False, #Should ChopShop handle the saving of files?
                         'text': False,
                         'pyobjout': False,
                         'jsonout': False,
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
        self.surgeon = None

        self.kill_lock = Lock()

    @property
    def mod_dir(self):
        """Directory to load modules from."""
        return self.options['mod_dir']

    @mod_dir.setter
    def mod_dir(self, v):
        if isinstance(v, basestring):
            self.options['mod_dir'] = [v]
        else:
            self.options['mod_dir'] = v

    @property
    def ext_dir(self):
        """Directory to load external libraries from."""
        return self.options['ext_dir']

    @ext_dir.setter
    def ext_dir(self, v):
        if isinstance(v, basestring):
            self.options['ext_dir'] = [v]
        else:
            self.options['ext_dir'] = v

    @property
    def base_dir(self):
        """Base directory to load modules and external libraries."""
        return self.options['base_dir']

    @base_dir.setter
    def base_dir(self, v):
        if isinstance(v, basestring):
            self.options['base_dir'] = [v]
        else:
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
    def modtree(self):
        """print information about module tree and exit."""
        return self.options['modtree']

    @modtree.setter
    def modtree(self, v):
        self.options['modtree'] = v

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
    def pyobjout(self):
        """Handle raw python objects"""
        return self.options['pyobjout']

    @pyobjout.setter
    def pyobjout(self, v):
        self.options['pyobjout'] = v

    @property
    def jsonout(self):
        """Handle JSON Data (chop.json)."""
        return self.options['jsonout']

    @jsonout.setter
    def jsonout(self, v):
        self.options['jsonout'] = v

    @property
    def modules(self):
        """String of Modules to execute"""
        return self.options['modules']

    @modules.setter
    def modules(self, v):
        self.options['modules'] = v

    @property
    def bpf(self):
        """BPF string to pass to Nids"""
        return self.options['bpf']

    @bpf.setter
    def bpf(self, v):
        self.options['bpf'] = v

    def get_message_queue(self):
        return self.tocaller

    def get_stop_fn(self):
        return self.stop

    def version(self):
        global VERSION
        return VERSION

    def abort(self):
        self.tonids.put(['abort'])
        self.surgeon.abort()

    def stop(self):
        self.stopped = True
        if self.surgeon:
            self.surgeon.stop()

    def setup_local_chop(self, name = "ChopShop", pid = -1):
        #This allows Process 1 to access Chops, note that it has
        #a hardcoded id of -1 since otherwise it might overlap
        #with the other chops, only use a custom id if you know
        #what you're doing
        chophelper = ChopHelper(self.tocaller, self.options)
        self.chop = chophelper.setup_module(name, pid)

    def send_finished_msg(self, data = {}, stop_seq = False):
        message = { 'type' : 'ctrl',
                    'data' : {'msg' : 'finished',
                              'status': 'ok' #default to ok
                            }
                  }

        for key,val in data.iteritems():
            message['data'][key] = val

        self.kill_lock.acquire()
        try:
            self.tocaller.put(message)

            if stop_seq:
                self.tonids.put(['stop'])
                self.nidsp.join()
        except AttributeError:
            pass
        finally:
            self.kill_lock.release()

    def run(self):
        if not self.options['modinfo'] and not self.options['modtree']: #No point in doing surgery if it's modinfo or modtree
            # Figure out where we're reading packets from
            if not self.options['interface']:
                if not self.options['filename']:
                    if not self.options['filelist']:
                        self.send_finished_msg({'status':'error','errors': 'No input Specified'}, True)
                        return
                    else:
                        self.surgeon = Surgeon(self.options['filelist'])
                        self.options['filename'] = self.surgeon.create_fifo()
                        self.surgeon.operate()
                else:
                    if not os.path.exists(self.options['filename']):
                        self.send_finished_msg({'status':'error','errors':"Unable to find file '%s'" % self.options['filename']}, True)
                        return

                    if self.options['aslist']:
                        #input file is a listing of files to process
                        self.surgeon = Surgeon([self.options['filename']], self.options['longrun'])
                        self.options['filename'] = self.surgeon.create_fifo()
                        #TODO operate right away or later?
                        self.surgeon.operate(True)

        #Send options to Process 2 and tell it to setup
        self.kill_lock.acquire()
        try:
            self.tonids.put(['init', self.options])
        except AttributeError:
            #usually means tonids is None
            #possibly being killed?
            pass
        except Exception, e:
            raise ChopLibException(e)
        finally:
            self.kill_lock.release()

        #Wait for a reponse
        self.kill_lock.acquire()
        try:
            resp = self.fromnids.get()
        except AttributeError:
            resp = "notok" #probably means fromnids is None, which should only happen when being killed
        except Exception, e:
            raise ChopLibException(e)
        finally:
            self.kill_lock.release()

        if resp != 'ok':
            self.send_finished_msg({'status':'error','errors':resp}, True)
            return

        if self.options['modinfo']:
            self.kill_lock.acquire()
            try:
                self.tonids.put(['mod_info'])
                resp = self.fromnids.get() #really just to make sure the functions finish
            except AttributeError:
                pass
            finally:
                self.kill_lock.release()

            #Process 2 will quit after doing its job

            #Inform caller that the process is done
            self.send_finished_msg()
            #Surgeon should not be invoked so only need
            #to cleanup nidsp
            self.nidsp.join()
            return
        elif self.options['modtree']:
            self.kill_lock.acquire()
            try:
                self.tonids.put(['mod_tree'])
                resp = self.fromnids.get()
            except AttributeError:
                pass
            finally:
                self.kill_lock.release()

            self.send_finished_msg()
            self.nidsp.join()
            return
        else:
            self.kill_lock.acquire()
            try:
                self.tonids.put(['cont'])
            except AttributeError:
                pass
            except Exception, e:
                raise ChopLibException(e)
            finally:
                self.kill_lock.release()

        #Processing loop
        while True:
            self.kill_lock.acquire()
            try:
                data = self.fromnids.get(True, .1)
            except Queue.Empty, e:
                if not self.nidsp.is_alive():
                    break
                if self.stopped:
                    self.nidsp.terminate()
                continue
            except AttributeError:
                break
            finally:
                self.kill_lock.release()

            if data[0] == "stop":
                #Send the message to caller that we need to stop
                message = { 'type' : 'ctrl',
                            'data' : {'msg'  : 'stop'}
                          }
                self.kill_lock.acquire()
                try:
                    self.tocaller.put(message)
                finally:
                    self.kill_lock.release()

                self.nidsp.join(1)
                #Force Terminate if nids process is non-compliant
                if self.nidsp.is_alive():
                    self.nidsp.terminate()
                break

            time.sleep(.1)

        ###Teardown of the program
        #Join with Surgeon
        if self.surgeon is not None:
            self.surgeon.stop()

        #Join with Nids Process
        self.nidsp.join()

        #Inform caller that we are now finished
        self.send_finished_msg()

    #This must be torn down safely after who need it have cleaned up
    def finish(self):
        self.kill_lock.acquire()
        try:
            self.stop()
            if self.nidsp.is_alive():
                self.nidsp.terminate()
            self.nidsp.join(.1)

            try:
                self.tonids.close()
                self.fromnids.close()
                self.tocaller.close()

                self.tonids = None
                self.fromnids = None
                self.tocaller = None
                time.sleep(.1)

            except:
                pass
        finally:
            self.kill_lock.release()


#######Process 2 Functions######

    def __loadModules_(self, name, path):
        try:
            (file, pathname, description) = imp.find_module(name, path)
            loaded_mod = imp.load_module(name, file, pathname, description)
        except Exception, e:
            tb = traceback.format_exc()
            raise Exception(tb)

        return loaded_mod


    #Process 2 "main" process
    def __nids_core_runner_(self, inq, outq, dataq, autostart = True):
        #Note that even though this is within the class it is being used irrespective
        #of the Process 1 class, so 'self' is never used for data

        os.setpgrp()

        #Responsible for creating "chop" classes and
        #keeping track of the individual output handlers
        chophelper = None
        chop = None

        options = None
        module_list = []
        ccore = None
        mod_dir = []
        ext_dir = []
        chopgram = None
        abort = False

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
                    for base in options['base_dir']:
                        real_base = os.path.realpath(base)
                        mod_dir.append(real_base + "/modules/")
                        ext_dir.append(real_base + "/ext_libs")
                else:
                    mod_dir = options['mod_dir']
                    ext_dir = options['ext_dir']

                for ed_path in ext_dir:
                    sys.path.append(os.path.realpath(ed_path))

                #Setup the chophelper
                chophelper = ChopHelper(dataq, options)
                chop = chophelper.setup_main()

                #Setup the modules
                chopgram = ChopGrammar()
                try:
                    all_modules = chopgram.parseGrammar(options['modules'])
                except Exception, e:
                    outq.put(traceback.format_exc())
                    sys.exit(1)


                if len(all_modules) == 0:
                    outq.put('Zero Length Module List')
                    sys.exit(1)

                try:
                    for mod in all_modules:
                        mod.code = self.__loadModules_(mod.name, mod_dir)
                        minchop = '0'
                        try:
                            mod_version = mod.code.moduleVersion
                            minchop = mod.code.minimumChopLib

                        except: #Legacy Module
                            mod.legacy = True
                            chop.prnt("Warning Legacy Module %s!" % mod.code.moduleName)
                    
                        try:
                            #TODO more robust version checking
                            if str(minchop) > str(VERSION):
                                raise Exception("Module requires ChopLib Version %s or greater" % minchop)
                        except Exception, e:
                            outq.put(e.args)
                            sys.exit(1)

                except Exception, e:
                    outq.put(e)
                    sys.exit(1)

                module_list = all_modules

                #It got this far, everything should be okay
                outq.put('ok')

            elif data[0] == 'mod_info':
                #Hijack stdout to support modules that use print
                orig_stdout = sys.stdout #We don't know what the original stdout might have been (__stdout__)
                                         #Although it should be /dev/null
                for mod in module_list:
                    try:
                        modinf = "%s (%s) -- requires ChopLib %s or greater:\n" % (mod.code.moduleName, mod.code.moduleVersion, mod.code.minimumChopLib)
                    except:
                        modinf = "%s (Legacy Module) -- pre ChopLib 4.0:\n" % mod.code.moduleName

                    modtxt = None

                    try:
                        modtxt = mod.code.module_info()
                        if modtxt is not None:
                            modtxt = modtxt + "\n"
                        else:
                            raise Exception
                    except Exception, e:
                        modtxt = "Missing module information for %s\n" % mod.name

                    sys.stdout = strbuff = StringIO()

                    try:
                        #Instantiate a dummy 'chop' accessor for each module in case
                        #they use it in init
                        mod.code.chop = chophelper.setup_dummy()
                        sys.argv[0] = mod.code.moduleName
                        mod.code.init({'args': ['-h']})
                    except SystemExit, e:
                        #OptParse will except as it ends
                        modtxt = modtxt + strbuff.getvalue() 
                        pass

                    #Close and free contents
                    strbuff.close()

                    chop.prnt("%s%s----------\n" % (modinf, modtxt))

                #Restore stdout
                sys.stdout = orig_stdout
                outq.put('fini')
                sys.exit(0)

            elif data[0] == 'mod_tree':
                tree = chopgram.get_tree()
                chop.prnt(tree)


                outq.put('fini')
                sys.exit(0)
            elif data[0] == 'cont':
                break
            elif data[0] == 'stop': #Some error must have occurred
                sys.exit(0)
            elif data[0] == 'abort': #Process any data we have
                abort = True
                break
            else:
                #FIXME custom exception?
                raise Exception("Unknown message")


        chop.prettyprnt("RED", "Starting ChopShop (Created by MITRE)")

        #Initialize the ChopShop Core
        ccore = ChopCore(options, module_list, chop, chophelper)

        #Setup Core and its modules
        ccore.prep_modules()


        if autostart:
            ccore.start()

        #If received abort during init, this is true
        ccore.abort = abort

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
            elif data[0] == 'abort':
                ccore.abort = True

        ccore.join()

        chop.prettyprnt("RED", "ChopShop Complete")



