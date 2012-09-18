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

#shop/ChopHelper

import sys
import os
import time
import json
from datetime import datetime

from threading import Thread
from threading import Lock
import Queue

from multiprocessing import Queue as mQueue

from ChopShopUI import ChopUI

import ChopShopDebug as CSD

"""
        __parse_filepath__ parses a pseudo format-string passed on the commandline to figure out
        what the output filepath should be. It currently support the following variables:

        %N - The name of the module
        %T - The current unix timestamp
        %% - A literal '%'

        This function, when given a path string will replace any variables with the current local value
        and create a static path string that can be used to create a file or directory to output data

        For example if the user passes in "output/%N/%T.txt" and the name of the module is "foobar"
        and the current timestamp is 123456789 the resultant output would be:

        "output/foobar/123456789.txt"

        Or if used with the save file functionality if the user passes in "/tmp/%N/" and the module is named "foobar"
        the output directory would be:

        "/tmp/foobar/"

        It takes an optional fname paramter which is the literal filename to append to the crafted filepath
"""


def __parse_filepath__(format, modname, fname = None): #the format, the module name, the requested filename
    default_path = "./" #default to local working directory
    default_filename = modname + "-" + str(int(time.time())) + ".txt"

    filename = ""

    if format == "": #If they passed in an empty string use defaults
        #default filename
        filename = default_path
        if fname is None:
            filename += default_filename

    else:#let's go through the format and craft the path
        start = 0
        while True:
            #ind is the index where we find '%'
            ind = format.find('%',start)

            if ind == -1: #no ind found, just copy the rest of the string
                filename += format[start:]
                break

            #copy everything before the % straight in
            filename += format[start:ind]

            #Now let's process the flag if there is one
            if (ind + 1) > (len(format) - 1): #the % is the last element
                return None #improper formatting so let's return None
            else:
                flag = format[ind + 1]# the next character is the flag
                if flag == 'N':
                    filename += modname
                elif flag == 'T':
                    filename += str(int(time.time()))
                elif flag == '%':
                    filename += '%' #put in a literal %
                else:
                    return None #unknown or unsupported flag

            #move past the % and the flag
            start = ind + 2

        #if passed in an explicit filename concat it with what we've crafted
        #XXX Should we worry about directory traversal?
        if fname is not None:
            if filename[-1] != '/': #add a slash to the filepath if not already there
                filename += '/'
            filename += fname
   
    return filename 


#XXX Add the capability to disable the creation of directories (or the flipside
#### don't create by default and add the capability to create)

def __get_open_file__(modname, format, create, fname=None, mode = 'w'):
    filename = __parse_filepath__(format, modname, fname)
    fdval = None
    error = ""

    if create:
        dname = os.path.dirname(filename)
        if dname and not os.path.exists(dname):
            try:
                os.makedirs(dname, 0775)
            except Exception, e:
                error = "Directory Creation Error: %s " % e
    
    try:
        fd = open(filename, mode)
        fdval = fd
    except IOError, e:
        if error == "":
            error = "File Creation Error: %s " % e

    return (fdval,error)

"""
    The chops class is the interface for ChopShop and modules to send output properly. Each module is given a reference
    to it's own chops class called "chop" -- this allows them to use function calls like chop.prnt("foo") in their module
    without having to do too much else to send output to the proper channel based on the user's settings

    chops provides four (4) main "channels" of output currently, which are:
    
    1. prnt -- basic print functionality, "print" is a keyword in python and so could not be reused
        should accept the same syntax as a call to print
        depending on what the user has set (out to stdout, out to ui, etc.) this function will route the output to the
        desired location
    2. debug -- like prnt but handles debug output
        same syntax as print but routes the output to either stderr, or to a debug specific window/file
    3. json -- json output to file
        outputs json data to a json specific file
        a module can specify a custom json encoder by calling set_custom_json_encoder and passing a function
    4. output files -- allow a module writer to output files carved from their module in a respectable manner, the following
       commands are avaialble:
        savefile -- save carved or other files from within a module, takes a filename, the data, and an optional "finalize" variable (default True)
        if finalize is set to false, chops will keep the file open, otherwise will close the file, also note that this will open the file
        with the 'w' flag so it will overwrite existing files
        appendfile -- same as savefile except it opens files in 'a' mode which will not overwrite existing files, also defaults its 'finalize'
        to False, so it keeps the handle open until explicitly closed
        finalizefile -- given a filename will close the handle to it (if open). If the file is not open, this is a noop

"""


class chops:
    GMT = False

    def __init__(self, outq, name, dbq, dataq, index, core = None):
        self.outq = outq
        self.name = name
        self.dbq =  dbq
        self.dataq = dataq
        self.index = index
        self.core = core
        self.cls = None
        self.tsformatshort = False


    def tsprnt(self, *fmtstring):
        self.tsprettyprnt(None, *fmtstring)

    def tsprettyprnt(self, color, *fmtstring):
        if self.core is not None:
            ptime = ""
            ts = self.core.getptime()
            if self.GMT:
                fmt = "%Y-%m-%d %H:%M:%S +0000"
                ts = time.gmtime(ts)
            else:
                fmt = "%Y-%m-%d %H:%M:%S %Z"
                ts = time.localtime(ts)

            if self.tsformatshort:
                ptime = "[%02d:%02d:%02d]" % (ts[3], ts[4], ts[5])
            else:
                ptime = time.strftime(fmt, ts).rstrip()
                ptime = "[%s] " % (str(ptime))
            fmtstring = (ptime,) + fmtstring

        self.prettyprnt(color, *fmtstring)

    def prnt(self, *fmtstring):
        self.prettyprnt(None, *fmtstring)

    def prettyprnt(self, color, *fmtstring):
        if not self.outq:
            CSD.debug_out("No outq for " + self.name + "\n")
            return

        mystring = ''

        supress = False 
        extents = None 
        if fmtstring[-1] is None:
            extents = -1
            supress = True

        for strn in fmtstring[0:extents]:
            strn = str(strn)
            if mystring != '':
                mystring += ' '
            mystring += strn

        tosend = ["text", mystring, supress, color]
        self.outq.put(tosend)

        tosendm = [self.index, "text", mystring, supress, color] 
        self.dataq.put(tosendm)

    def savefile(self, filename, data, finalize = True):
        if not self.outq:
            CSD.debug_out("No outq for " + self.name + "\n")
            return

        tosend = ["savefile", filename, data, 'w', finalize]
        self.outq.put(tosend)

    def appendfile(self, filename, data, finalize = False):
        if not self.outq:
            CSD.debug_out("No outq for " + self.name + "\n")
            return

        tosend = ["savefile", filename, data, 'a', finalize]
        self.outq.put(tosend)

    def finalizefile(self, filename):
        self.appendfile(filename, "", True)

    def json(self, obj):
        if not self.outq:
            CSD.debug_out("No outq for " + self.name + "\n")
            return

        tosend = ["json", obj, self.cls]
        self.outq.put(tosend)

    def debug(self, *fmtstring):
        if not self.dbq:
            return

        mystring = ''
        for strn in fmtstring:
            strn = str(strn)
            if mystring != '':
                mystring += ' '
            mystring += strn

        ptime = ""
        if self.core is not None:
            ptime = "[%s] -- " %  datetime.fromtimestamp(self.core.getptime()).strftime("%Y-%m-%d %H:%M:%S %z").rstrip()

        mystring = self.name + " -- " + ptime + mystring
        tosend = ["dbg", mystring, False, None] #set "supress" to false, color to None
        self.dbq.put(tosend)

        tosendm = [-1, "dbg", mystring, False, None]
        self.dataq.put(tosendm)

    def set_custom_json_encoder(self, cls):
        self.cls = cls

    def set_ts_format_short(self, on = False):
        self.tsformatshort = on



#PROCESS 2 Functions
"""
    The CoreCommander is the main interface to the ChopShop secondary process and allows it to communicate with
    it's sister class, the UiCommander. It abstracts most of the gritty details to 
    minimize modifications to ChopShop itself. It is the only class that the ChopShop secondary process needs to know 
    about (directly) from this file.

    There are a bunch of functions that need to be called to properly setup CoreCommander (and in a recommended order):

    setup_var -- sets up variables and system setting based on the configuration received from the optparser
                 should be called after optparser has been called to parse arguments

    setup_windows -- coordiation function that talks to CoreCommander to set up ui panels if needed

    get_chop -- used to get an instance of "chops" (above), should only, ideally, be used by main function


    setup_modules_begin -- used to sync with primary process to create windows


    setup_module -- used to set up a window, including creating a queue and gui panel (if enabled)
                    will return an instance of "chops" created for this module
    
    setup_modules_end -- used to sync with primary process and inform it that window creation is done
    
    join -- stops and cleans up any threads -- waits for the gui to exit

   
    All other functions are used internally and should not be called externally 

    setup_main -- sets up the main and debug (if enabled) queues and gui panels (if enabled)
"""

class CoreCommander:
    def __init__(self, inq, outq, dataq):
        self.inq = inq
        self.outq = outq
        self.dataq = dataq
        self.options = None
        self.dbgid = -1
        self.filelock = None
        self.to_outs = None
        self.formats = None
        self.outlist = []
        self.helpers = []
        self.core = None

    def setup_var(self, options):
        self.options = options
        self.filelock = Lock()
        chops.GMT = self.options.GMT

    def setup_main(self):
        self.to_outs = self.inq.get()[1]
        self.formats = self.inq.get()[1]

        index = self.__add_queue_("ChopShop")

        if self.options.debug:
            self.dbgid = self.__add_queue_("Debug")

        #return index
        return self.get_chop(index, "ChopShop")

    def get_chop(self, index, name):
        return chops(self.__get_outq_for_(index), name, self.__get_dbq_(), self.dataq, index, self.core)

    def setup_modules_begin(self, core):
        self.core = core
        self.outq.put(["ready"])
        return self.setup_main()

    def setup_modules_end(self):
        self.outq.put(["fini"])

    def setup_module(self, name): #setup_window
        index = self.__add_queue_(name)
        chop = self.get_chop(index, name)
        return chop


    def join(self):
        for helper in self.helpers:
            helper.stop()
            helper.join()


    ### Internal Functions ###

    def __add_queue_(self, name):
        self.outq.put(["window", name])
        self.outlist.append(Queue.Queue())
        index = len(self.outlist) - 1
        
        t = CoreHelper(index, self.outlist[index], self.dataq, self.to_outs, name, self.filelock, self.formats)
        self.helpers.append(t)
        t.setDaemon(True)
        t.start()

        return index

    def __get_outq_for_(self,index):
        if index > (len(self.outlist) - 1) or index < 0:
            return None 
        else:
            return self.outlist[index]

    def __get_dbq_(self):
        if self.options.debug:
            return self.__get_outq_for_(self.dbgid)
        else:
            return None

"""
    The CoreHelper class is a helper thread created to handle every module's output (incl the chopshop core)
    Every module, including the chopshop core gets its own helper thread, the only exception to this is 
    that debug gets a dedicated helper. This class should never be seen by the outside world and is 
    managed by the CoreCommander. Note that the CoreCommander only handles output to files and other output
    that is not UI related

"""        

class CoreHelper(Thread):
    def __init__(self, id, queue, dataq, to_outs, name, filelock, formats):
        Thread.__init__(self)
        self.id = id
        self.queue = queue
        self.dataq = dataq
        self.to_outs = to_outs
        self.name = name
        self.formats = formats
        self.stopped = False
        self.filelock = filelock
        self.fd = None
        self.jd = None
        self.savedfiles = {}

    def __del__(self):
        #clean up any open files
        if self.fd is not None:
            self.fd.close()

        if self.jd is not None:
            self.jd.close()

        for v in self.savedfiles.values():
            v.close()

    def notify_error(self, message):
        tosend = [0, "text", message, False, "YELLOW"]
        self.dataq.put(tosend)

    def stop(self):
        self.stopped = True

    def handle_json(self, data, custom_encoder):
        if self.to_outs.has_key('to_json') and self.to_outs['to_json']:
            error = ""
            if self.jd is None:
                self.filelock.acquire()
                try:
                    (self.jd, error) = __get_open_file__(self.name,self.formats['jsonformat'],True)
                finally:
                    self.filelock.release()

            #Just in case file creation failed
            if self.jd is not None:
                try:
                    if custom_encoder is not None:
                        jdout = json.dumps(data, cls=custom_encoder)
                    else:
                        jdout = json.dumps(data)
                    self.jd.write(jdout + "\n")
                except Exception, e:
                    self.notify_error("\tError converting data to json: %s" % str(e))
                finally:
                    self.jd.flush()
            else:
                self.notify_error("\tUnable to open/create JSON file: %s \n\t\t%s" % (self.name, error))

    def handle_savefile(self, filename, data, mode, finalize):
        if self.to_outs.has_key('savedir') and self.to_outs['savedir']:
            error = ""
            if data != "": #No point in opening or checking for the file if there's no data to write
                if not self.savedfiles.has_key(filename):
                    self.filelock.acquire()
                    try:
                        (self.savedfiles[filename], error) = __get_open_file__(self.name, self.formats['savedir'], True, filename, mode)
                    finally:
                        self.filelock.release()

                if self.savedfiles[filename] is None:
                    self.notify_error("\tUnable to open/create file: %s \n\t\t%s" % (filename, error))
                    del self.savedfiles[filename]
                    return

                self.savedfiles[filename].write(data)
                self.savedfiles[filename].flush()

            if finalize and self.savedfiles.has_key(filename) :
                self.savedfiles[filename].close()
                del self.savedfiles[filename]

    def handle_text_dbg(self, type, data, supress, color):
        if self.to_outs.has_key('to_file') and self.to_outs['to_file']:
            error = ""
            if self.fd is None:
                self.filelock.acquire()
                try:
                    (self.fd, error) = __get_open_file__(self.name,self.formats['fileformat'],True)
                finally:
                    self.filelock.release()

            if self.fd is not None:
                newline = "\n"
                if supress:
                    newline = ""
                self.fd.write(data + newline)
                self.fd.flush()
            else:
                self.notify_error("\tUnable to open/create output file: %s \n\t\t%s" % (self.name, error))

    def run(self):
        try:
            while not self.stopped or not self.queue.empty():
                try:
                    #get will wait .1 seconds before throwing an exception
                    outargs = self.queue.get(True, .1)
                    outtype = outargs[0]
                    outdata = outargs[1]
                except Exception, e: #get throws an exception if it reached the time and didn't get anything
                    continue

                ###Handle calls to chop.json
                if outtype == "json":
                    self.handle_json(outdata,outargs[2]) #outargs[2] is the custom encoder
                    continue

                ###Handle calls to chop.savefile
                if outtype == "savefile":
                    # outargs[2] is data
                    # outargs[3] is mode
                    # outargs[4] is finalize
                    self.handle_savefile(outdata, outargs[2], outargs[3], outargs[4])
                    continue

                ###Handle calls to chop.prnt and chop.debug
                ###Below are for text and dbg types
                #outargs[2] is supress
                #outargs[3] is color
                self.handle_text_dbg(outtype,outdata, outargs[2], outargs[3]) 
        except:
                CSD.debug_out("Exception in CoreHelper\n")
                raise


#PROCESS 1 Functions        
"""
    The UiCommander is the main interface to ChopShop that gives it access to ui capabilities.
    It is the sister class to CoreCommander and it abstracts most of the gritty details to 
    minimize modifications to ChopShop itself. It is the only class that ChopShop needs to know 
    about (directly) from this file.

    There are a bunch of functions that need to be called to properly setup UiCommander (and in a recommended order):

    setup_opts -- sets up the options that need to be added to the optparser
    setup_var -- sets up variables and system setting based on the configuration received from the optparser
                 should be called after optparser has been called to parse arguments

    setup_gui -- sets up the gui if enabled

    setup_windows -- coordiation function that talks to CoreCommander to set up ui panels if needed

    get_chop -- used to get an instance of "chops" (above), should only, ideally, be used by main function

    setup_window -- used to set up a window, including creating a queue and gui panel (if enabled)
                    will return an instance of "chops" created for this module
    
    start_gui -- starts the gui

    stop_gui -- stops the gui forecfully

    join -- stops and cleans up any threads -- waits for the gui to exit

   
    All other functions are used internally and should not be called externally 

    setup_main -- sets up the main and debug (if enabled) queues and gui panels (if enabled)
"""

class UiCommander:
    def __init__(self, inq, outq, dataq):
        self.inq = inq
        self.outq = outq
        self.dataq = dataq
        self.helpers = []
        self.panellist = []
        self.to_outs = {}
        self.dbgid = -1
        self.cui = None
        self.formats = {}

    def setup_opts(self,optparser):
    
        optparser.add_option("-g", "--gui", action="store_true", dest="gui",
            default=False,help="Enable ChopShop Gui")
        optparser.add_option("-D", "--debug", action="store_true", dest="debug",
            default=False,help="Enable Debug")
        optparser.add_option("-S", "--stdout", action="store_true", dest="stdout",
            default=False,help="Explicitly enable output to stdout")
        optparser.add_option("-F", "--fileout", action="store", dest="fileout", type="string",
            default=None, help="Enable File Output")
        optparser.add_option("-s", "--savedir", action="store", dest="savedir", type="string",
            default="/tmp", help="Location to save carved files")
        optparser.add_option("-J", "--jsonout", action="store", dest="jsonout", type="string",
            default=None, help="Enable JSON Output")

    def setup_var(self,options):
        status = ""

        if not options.gui and options.fileout is None and not options.stdout:
            self.to_outs['to_stdout'] = True
            status += "\tDefaulted to stdout output\n"

        if options.stdout:
            self.to_outs['to_stdout'] = True
            status += "\tEnabled stdout output\n"

        if options.gui:
            self.to_outs['to_ui'] = True
            status += "\tEnabled ui output\n"

        if options.fileout is not None:
            if options.fileout[0] == '-':
                print("Ambiguous file format: '" + options.fileout + "' -- please fix and run again\n")
                sys.exit(-1)
            else:
                if __parse_filepath__(options.fileout, "placeholder") is None:
                    print("Invalid syntax for file output\n")
                    sys.exit(-1)
                else:
                    status += "\tEnabled file output to '" + options.fileout + "'\n"
                    self.to_outs['to_file'] = True
                    self.formats['fileformat'] = options.fileout 


        if options.jsonout is not None:
            if options.jsonout[0] == '-':
                print("Ambigous json format: '" + options.jsonout + "' -- please fix and run again\n")
                sys.exit(-1)
            else:
                status += "\tEnabled json output to '" + options.jsonout + "'\n"
                self.to_outs['to_json'] = True
                self.formats['jsonformat'] = options.jsonout

                if __parse_filepath__(options.jsonout, "placeholder") is None:
                    print("Invalid syntax for json output\n")
                    sys.exit(-1)

        #Check the format of savedir
        if options.savedir[0] == '-':
            print("Ambigous savedir format: '" + options.savedir + "' -- please fix and run again\n")
            sys.exit(-1)
        else:
            status += "\tSet file save directory to '" + options.savedir + "'\n"
            self.to_outs['savedir'] = True
            self.formats['savedir'] = options.savedir

            if __parse_filepath__(options.savedir, "placeholder") is None:
                print("Invalid syntax for savedir\n")
                sys.exit(-1)

        #Save the options we got for later use and create a printlock
        self.options = options
        self.printlock =  Lock()

        #-1 removes the last \n since chop.print adds a \n
        return status[:-1]
        
    def setup_gui(self):
        if self.options.gui:
            self.cui = ChopUI()
            self.cui.setup_core_ref(self.inq)

    def setup_windows(self):
        data = self.inq.get()
        if data[0] != "ready":
            pass

        self.outq.put(['to_outs', self.to_outs])
        self.outq.put(['formats', self.formats])

        self.uihelper = UiHelper(self.dataq, self.to_outs, self.printlock, self.panellist)
        self.uihelper.setDaemon(True)
        self.uihelper.start()

        while (True):
            data = self.inq.get()

            if data[0] == "window":
                self.setup_window(data[1])
            elif data[0] == "fini":
                break
        self.uihelper.set_dbgid(self.dbgid)

    def setup_window(self, name):
        self.__add_panel_(name)

    def start_gui(self):
        if self.options.gui:
            self.cui.go()

    def stop_gui(self):
        if self.options.gui:
            self.cui.stop()

    def join(self):
        if self.options.gui:
            self.cui.join()
        self.uihelper.stop()
        self.uihelper.join()


    ### Internal Functions ###

    def __add_panel_(self, name):
        mypan = None

        if self.options.gui:
            mypan = self.cui.new_panel(name)

        self.panellist.append(mypan)

        if name == "Debug":
            self.dbgid = len(self.panellist) - 1

"""
    The UiHelper thread is a solitary thread that is launched when setting up chopshop. It runs
    in the primary process and handles any output that needs to be sent to stdout/stderr or the UI
    Relies on a multiprocessing Queue which is fed by the secondary Process

"""
class UiHelper(Thread):
    def __init__(self, dataq, to_outs, printlock, panellist):
        Thread.__init__(self)
        self.dataq = dataq
        self.to_outs = to_outs
        self.printlock = printlock
        self.panellist = panellist
        self.stopped = False
        self.dbgid = -1

    def set_dbgid(self, id):
        self.dbgid = id

    def stop(self):
        self.stopped = True

    def handle_text_dbg(self, type, panid, data, supress, color):
        if self.to_outs.has_key('to_stdout') and self.to_outs['to_stdout']:
            if type ==  "dbg" :
                try:
                    sys.stderr.write(data + "\n")
                    sys.stderr.flush()
                except:
                    pass 
            else:
                self.printlock.acquire()
                try:
                    if supress:
                        print data,
                    else:
                        print data
                finally:
                    self.printlock.release()

        if self.to_outs.has_key('to_ui') and self.to_outs['to_ui']:
            if not self.panellist[panid]:
                pass
            else:
                newline = "\n"
                if supress:
                    newline = ""

                self.panellist[panid].add_data(data + newline, color)

    def run(self):
        try:
            while not self.stopped or not self.dataq.empty():
                try:
                    #get will wait .1 seconds before throwing an exception
                    outargs = self.dataq.get(True, .1)
                    outpan =  outargs[0]
                    outtype = outargs[1]
                    outdata = outargs[2]
                except Queue.Empty, e:
                    continue
                except Exception, e:
                    CSD.debug_out("UiHelper Exception %s\n" % str(e))

                ###Handle calls to chop.prnt and chop.debug
                ###Below are for text and dbg types
                #outargs[2] is supress
                #outargs[3] is color
                if outpan == -1:
                    outpan = self.dbgid
                self.handle_text_dbg(outtype, outpan, outdata, outargs[3], outargs[4])
        except:
            CSD.debug_out("Exception in UiHelper\n")
            raise
