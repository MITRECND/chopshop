#! /usr/bin/env python

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
from threading import Thread, Lock
import Queue

from ChopException import * 
from ChopUiStd import *
import ChopShopDebug as CSD

"""
    ChopUi is the ui library interface to allow for automated data output from ChopLib
    It relies on a queue of information that it can use and parse to determine where output needs to go
    ChopUi instatiates a class for every output capability. For example, output to stdout is handled by ChopStdout
    which is located in ChopUiStd. This allows for the usage of output capabilites to be modular. If for example,
    you would like to replace the Stdout functionality, but do not want to rewrite this library, you can pass in the class
    you would like to replace stdout with and ChopUi will use that instead
"""

class ChopUi(Thread):
    def __init__(self):
        Thread.__init__(self, name = 'ChopUi')


        self.options = { 'stdout'   : False,
                         'gui'      : False,
                         'fileout'  : False,
                         'filedir'  : None,
                         'savedir'  : None,
                         'savefiles': False,
                         'jsonout'  : False,
                         'jsondir'  : None,
                         'pyobjout' : False
                       }

        self.stopped = False
        self.isrunning = False
        self.message_queue = None
        self.lib_stop_fn = None
        self.stdclass = None
        self.uiclass = None
        self.fileoclass = None
        self.jsonclass = None
        self.filesclass = None
        self.pyobjclass = None

    @property
    def stdout(self):
        """Output to stdout"""
        return self.options['stdout']

    @stdout.setter
    def stdout(self, v):
        self.options['stdout'] = v

    @property
    def pyobjout(self):
        return self.options['pyobjout']

    @pyobjout.setter
    def pyobjout(self, v):
        self.options['pyobjout'] = v

    @property
    def gui(self):
        """Output to a gui"""
        return self.options['gui']

    @gui.setter
    def gui(self, v):
        self.options['gui'] = v

    @property
    def fileout(self):
        """Output to files"""
        return self.options['fileout']

    @fileout.setter
    def fileout(self, v):
        self.options['fileout'] = v

    @property
    def filedir(self):
        """Directory format string to save files to"""
        return self.options['filedir']

    @filedir.setter
    def filedir(self, v):
        self.options['filedir'] = v


    @property
    def savedir(self):
        """Directory format string to save output files to"""
        return self.options['savedir']

    @savedir.setter
    def savedir(self, v):
        self.options['savedir'] = v


    @property
    def savefiles(self):
        """Handle the saving of files"""
        return self.options['savefiles']

    @savefiles.setter
    def savefiles(self, v):
        self.options['savefiles'] = v

    @property
    def jsonout(self):
        """Handle the output of JSON data"""
        return self.options['jsonout']

    @jsonout.setter
    def jsonout(self, v):
        self.options['jsonout'] = v

    @property
    def jsondir(self):
        """Directory format string to save json to"""
        return self.options['jsondir']

    @jsondir.setter
    def jsondir(self, v):
        self.options['jsondir'] = v

    def set_message_queue(self, message_queue):
        self.message_queue = message_queue

    def set_library_stop_fn(self, lib_stop_fn):
        self.lib_stop_fn = lib_stop_fn

    def bind(self, cl_instance):
        #TODO exception
        self.set_message_queue(cl_instance.get_message_queue())
        self.set_library_stop_fn(cl_instance.get_stop_fn())

    def stop(self):
        CSD.debug_out("ChopUi stop called\n")
        self.stopped = True
        #if self.lib_stop_fn is not None:
        #    self.lib_stop_fn()

    def run(self):
        try:
            if self.options['stdout'] == True:
                self.stdclass = ChopStdout(self.stop, self.lib_stop_fn)
                #Assign the default stdout handler
            elif self.options['stdout'] != False:
                self.stdclass = self.options['stdout'](self.stop, self.lib_stop_fn)
                #Override the default handler with this one

            if self.options['gui'] == True:
                self.uiclass = ChopGui(self.stop, self.lib_stop_fn)
            elif self.options['gui'] != False:
                self.uiclass = self.options['gui'](self.stop, self.lib_stop_fn)

            if self.options['fileout'] == True:
                self.fileoclass = ChopFileout(self.stop, self.lib_stop_fn, format_string = self.options['filedir'])
            elif self.options['fileout'] != False:
                self.fileoclass = self.options['fileout'](self.stop, self.lib_stop_fn, format_string = self.options['filedir'])

            if self.options['jsonout'] == True:
                self.jsonclass = ChopJson(self.stop, self.lib_stop_fn, format_string = self.options['jsondir'])
            elif self.options['jsonout'] != False:
                self.jsonclass = self.options['jsonout'](self.stop, self.lib_stop_fn, format_string = self.options['jsondir'])

            if self.options['savefiles'] == True:
                self.filesclass = ChopFilesave(self.stop, self.lib_stop_fn, format_string = self.options['savedir'])
            elif self.options['savefiles'] != False:
                self.filesclass = self.options['savefiles'](self.stop, self.lib_stop_fn, format_string = self.options['savedir'])

            if self.options['pyobjout'] == True:
                self.pyobjclass = None #No default handler Should throw exception
            elif self.options['pyobjout'] != False:
                self.pyobjclass = self.options['pyobjout'](self.stop, self.lib_stop_fn)
        except Exception, e:
            raise ChopUiException(e)

        while not self.stopped:

            try:
                message = self.message_queue.get(True, .1)
            except Queue.Empty, e:
                continue


            try:
                if message['type'] == 'ctrl':
                    try:
                        if self.stdclass is not None:
                            self.stdclass.handle_ctrl(message)
                    except Exception, e:
                        raise ChopUiStdOutException(e)
                    try:
                        if self.uiclass is not None:
                            self.uiclass.handle_ctrl(message)
                    except Exception, e:
                        raise ChopUiGuiException(e)
                    try:
                        if self.fileoclass is not None:
                            self.fileoclass.handle_ctrl(message)
                    except Exception, e:
                        raise ChopUiFileOutException(e)
                    try:
                        if self.jsonclass is not None:
                            self.jsonclass.handle_ctrl(message)
                    except Exception, e:
                        raise ChopUiJsonException(e)
                    try:
                        if self.filesclass is not None:
                            self.filesclass.handle_ctrl(message)
                    except Exception, e:
                        raise ChopUiFileSaveException(e)
                    try:
                        if self.pyobjclass is not None:
                            self.pyobjclass.handle_ctrl(message)
                    except Exception, e:
                        raise ChopUiPyObjException(e)

                    #The GUI is the only thing that doesn't care if the core is no
                    #longer running
                    if message['data']['msg'] == 'finished' and self.uiclass is None:
                        self.stop()
                        continue

            except ChopUiException:
                raise
            except Exception, e:
                raise ChopUiException(e)

            try:
                if message['type'] == 'text':
                    try:
                        if self.stdclass is not None:
                            self.stdclass.handle_message(message)
                    except Exception, e:
                        raise ChopUiStdOutException(e)
                    try:
                        if self.uiclass is not None:
                            self.uiclass.handle_message(message)
                    except Exception, e:
                        raise ChopUiGuiException(e)
                    try:
                        if self.fileoclass is not None:
                            self.fileoclass.handle_message(message)
                    except Exception, e:
                        raise ChopUiFileOutException(e)

                if message['type'] == 'json':
                    try:
                        if self.jsonclass is not None:  
                            self.jsonclass.handle_message(message)
                    except Exception, e:
                        raise ChopUiJsonException(e)
                
                if message['type'] == 'filedata':
                    try:
                        if self.filesclass is not None:
                            self.filesclass.handle_message(message) 
                    except Exception, e:
                        raise ChopUiFileSaveException(e)

                if message['type'] == 'pyobj':
                    try:
                        if self.pyobjclass is not None:
                            self.pyobjclass.handle_message(message)
                    except Exception, e:
                        raise ChopUiPyObjException(e)

            except ChopUiException:
                raise
            except Exception, e:
                raise ChopUiException(e)

        if self.stdclass is not None:
            self.stdclass.stop()
        if self.uiclass is not None:
            self.uiclass.stop()
        if self.fileoclass is not None:
            self.fileoclass.stop()
        if self.jsonclass is not None:
            self.jsonclass.stop()
        if self.filesclass is not None:
            self.filesclass.stop()
        if self.pyobjclass is not None:
            self.pyobjclass.stop()

