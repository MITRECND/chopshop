#!/usr/bin/env python

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


import sys
import os
import imp
import traceback
import time
from threading import Thread, Lock
import re
from cStringIO import StringIO
import Queue

from ChopGV import CHOPSHOP_WD
from ChopHelper import ChopHelper
from ChopException import BinLibException
from ChopGrammar import ChopGrammar
from ChopBinary import ChopBinary
from ChopLib import VERSION


DEFAULT_BMODULE_DIRECTORY = CHOPSHOP_WD + "/bin_modules/"
DEFAULT_EXTLIB_DIRECTORY = CHOPSHOP_WD + '/ext_libs/'

class ChopBin(Thread):
    def __init__(self):
        Thread.__init__(self, name = 'ChopBin')
        global DEFAULT_MODULE_DIRECTORY
        global DEFAULT_EXTLIB_DIRECTORY

        self.options = { 'bmod_dir': [DEFAULT_BMODULE_DIRECTORY],
                         'ext_dir': [DEFAULT_EXTLIB_DIRECTORY],
                         'base_dir': None,
                         'filename': '',
                         'filelist': None,
                         'modinfo': False,
                         'modtree': False,
                         'GMT': False,
                         'savefiles': False, #Should BinShop handle the saving of files?
                         'text': False,
                         'pyobjout': False,
                         'jsonout': False,
                         'modules': ''
                       }

        self.stopped = False

        #Setup Interaction Queues
        self.tocaller = Queue.Queue() #output directly to caller

        self.chop = None

    @property
    def bmod_dir(self):
        """Directory to load modules from."""
        return self.options['bmod_dir']

    @bmod_dir.setter
    def bmod_dir(self, v):
        if isinstance(v, basestring):
            self.options['bmod_dir'] = [v]
        else:
            self.options['bmod_dir'] = v

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
        """input data file."""
        return self.options['filename']

    @filename.setter
    def filename(self, v):
        self.options['filename'] = v

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

    def get_message_queue(self):
        return self.tocaller

    def get_stop_fn(self):
        return self.stop

    def version(self):
        return VERSION

    def abort(self):
        pass

    def stop(self):
        self.stopped = True

    def setup_local_chop(self, name = "BinShop", pid = -1):
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

        message['data'].update(**data)

        try:
            self.tocaller.put(message)
        except AttributeError:
            pass

    def run(self):
        if not self.options['modinfo'] and not self.options['modtree']:
            if not self.options['filename']:
                self.send_finished_msg({'status':'error','errors': 'No input Specified'}, True)
                return

            if not os.path.exists(self.options['filename']):
                self.send_finished_msg({'status':'error','errors':"Unable to find file '%s'" % self.options['filename']}, True)
                return

        options = self.options
        module_list = []
        entry_modules = []
        bmod_dir = []
        ext_dir = []
        autostart = True
        abort = False

        # Initialize stuff
        #Setup the chophelper
        chophelper = ChopHelper(self.tocaller, options)
        chop = chophelper.setup_main()

        #Setup the modules
        chopgram = ChopGrammar()

        """
        try:
            f = open('/dev/null', 'w')
            os.dup2(f.fileno(), 1)
            g = open('/dev/null', 'r')
            os.dup2(g.fileno(), 0)
        except:
            chop.prnt("Unable to assign /dev/null as stdin/stdout")
            self.send_finished_msg()
        """

        #Set up the module directory and the external libraries directory
        if options['base_dir'] is not None:
            for base in options['base_dir']:
                real_base = os.path.realpath(base)
                bmod_dir.append(real_base + "/bin_modules")
                ext_dir.append(real_base + "/ext_libs")
        else:
            bmod_dir = options['bmod_dir']
            ext_dir = options['ext_dir']

        for ed_path in ext_dir:
            sys.path.append(os.path.realpath(ed_path))

        try:
            all_modules = chopgram.parseGrammar(options['modules'])
            top_modules = chopgram.top_modules
        except Exception, e:
            chop.prnt(traceback.format_exc())
            self.send_finished_msg()


        if len(all_modules) == 0:
            chop.prnt('Zero Length Module List')
            self.send_finished_msg()

        try:
            for mod in all_modules:
                mod.code = self.__loadModules_(mod.name, bmod_dir)
                mod.binary = True
                minchop = '0'
                try:
                    mod_version = mod.code.moduleVersion
                    minlib = mod.code.minimumChopLib
                except Exception as e:
                    chop.prnt(e.args)
                    self.send_finished_msg()
            
                try:
                    #TODO more robust version checking
                    if str(minlib) > str(VERSION):
                        raise Exception("Module requires ChopLib Version %s or greater" % minlib)
                except Exception as  e:
                    chop.prnt(e.args)
                    self.send_finished_msg()

        except Exception, e:
            chop.prnt(str(e))
            self.send_finished_msg()

        module_list = all_modules
        entry_modules = top_modules

        if self.options['modinfo']:
            #Hijack stdout to support modules that use print
            orig_stdout = sys.stdout #We don't know what the original stdout might have been (__stdout__)
                                     #Although it should be /dev/null
            for mod in module_list:
                modinf = "%s (%s) -- requires ChopLib %s or greater:\n" % (mod.code.moduleName, mod.code.moduleVersion, mod.code.minimumChopLib)

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

                #Close and free contents
                strbuff.close()
                chop.prnt("%s%s----------\n" % (modinf, modtxt))

            #Restore stdout
            sys.stdout = orig_stdout
            self.send_finished_msg()
            return

        elif self.options['modtree']:
            tree = chopgram.get_tree()
            chop.prnt(tree)
            self.send_finished_msg()
            return

        chop.prettyprnt("RED", "Starting BinShop (Created by MITRE)")

        bcore = BinStream(options, module_list, entry_modules, chop, chophelper)

        #Setup Core and its modules
        bcore.prep_modules()
        bcore.start()
        bcore.abort = abort

        while (True):
            if bcore.complete:
                break
            time.sleep(.1)

        bcore.join()

        chop.prettyprnt("RED", "BinShop Complete")

        #Inform caller that we are now finished
        self.send_finished_msg()

    #This must be torn down safely after who need it have cleaned up
    def finish(self):
        self.stop()
        try:
            self.tocaller.close()
            self.tocaller = None
            time.sleep(.1)
        except:
            pass


    def __loadModules_(self, name, path):
        try:
            (file, pathname, description) = imp.find_module(name, path)
            loaded_mod = imp.load_module(name, file, pathname, description)
        except Exception, e:
            tb = traceback.format_exc()
            raise Exception(tb)

        return loaded_mod


class BinStream(Thread):
    def __init__(self, options, module_list, entry_modules, chp, chophelper):
        Thread.__init__(self)
        self.options = options
        self.module_list = module_list
        self.entry_modules = entry_modules
        self.chophelper = chophelper
        self.stopped = False
        self.complete = False
        self.abort = False

        global chop
        chop = chp

    def prep_modules(self):
        self.chophelper.set_core(self)
        modules = self.module_list
        for module in modules:
            code = module.code
            code.chop = self.chophelper.setup_module(code.moduleName)

    def getmeta(self):
        return {}

    def run(self):
        global chop
        #Initialize modules to be run
        options = self.options
        chop.prettyprnt("RED", "Initializing Modules ...")

        for module in self.module_list:
            name = module.name
            arguments = module.arguments
            code = module.code
            #Create module_data for all modules
            module.module_data = {'args': arguments}

            chop.prettyprnt("CYAN", "\tInitializing module (binary) '" + name + "'")
            try:
                module_options = code.init(module.module_data)
            except Exception as e:
                chop.prnt("Error Initializing Module (binary)", code.moduleName + ":", e)
                self.complete = True
                return

            if 'error' in module_options:
                chop.prettyprnt("GREEN", "\t\t%s init failure: %s" % (code.moduleName, module_options['error']))
                continue

        if options['filename'] is "":
            chop.prnt("Empty Filename")
            self.complete = True
            return

        # Read file data in
        with open(options['filename']) as f:
            rawData = f.read()
            dat = ChopBinary()
            dat.data = rawData
            dat.metadata['filename'] = options['filename']

        for module in self.entry_modules:
            mdata = dat._clone()
            handleBinary(module, mdata)

        chop.prettyprnt("RED", "Shutting Down Modules ...")

        #Call modules shutdown functions to do last-minute actions
        for module in self.module_list:
            try:
                chop.prettyprnt("CYAN","\tShutting Down (binary) " + module.code.moduleName)
                module.code.shutdown(module.module_data)
            except Exception,e:
                pass

        chop.prettyprnt("RED", "Module Shutdown Complete ...")
        self.complete = True


def handleBinary(module, cdata):
    code = module.code
    cdata.module_data = module.module_data
    try:
        output = code.handleData(cdata)
    except Exception as e:
        exc = traceback.format_exc()
        chop.prettyprnt("YELLOW", "Exception in module %s -- Traceback: \n%s" % (code.moduleName, exc))
        return

    module.module_data = cdata.module_data

    if output is not None:
        handleBinaryChildren(module, output)

def handleBinaryChildren(module, output):
    code = module.code
    if isinstance(output, ChopBinary):
        output = [output]
    elif not isinstance(output, list):
        chop.prettyprnt("YELLOW", "Module %s returned an invalid type" % code.moduleName)
        return

    for outp in output:
        if not isinstance(outp, ChopBinary):
            chop.prettyprnt("YELLOW", "Module %s returned an invalid type" % code.moduleName)
            return

        # Add Type checking?

        for child in module.children:
            child_copy = outp._clone()
            handleBinary(child, child_copy)
