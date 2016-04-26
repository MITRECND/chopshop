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


import time
import os
import sys
import errno

import ChopShopDebug as CSD
from ChopException import ChopLibException

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


class ChopStdout:

    prepend_module_name     = False
    prepend_proto           = False
    prepend_address         = False

    def __init__(self, ui_stop_fn = None, lib_stop_fn = None):
        self.ui_stop_fn = ui_stop_fn
        self.lib_stop_fn = lib_stop_fn
        self.broken_pipe = False

    def handle_message(self, message):
        outstring = ""
        
        if self.prepend_module_name:
            outstring = outstring + message['module'] + " "

        if self.prepend_proto and message['proto'] != '':
            outstring = outstring + message['proto'] + " "

        if self.prepend_address and message['addr']['src'] != '':
            outstring = outstring + message['addr']['src'] + ":" + message['addr']['sport'] + "->" + message['addr']['dst'] + ":" + message['addr']['dport'] + " "

        outstring = outstring + message['data']['data']
        suppress = message['data']['suppress']
        try:
            if suppress:
                sys.stdout.write(outstring + " ")
            else:
                sys.stdout.write(outstring + "\n")
        except IOError as e:
            if e.errno == errno.EPIPE: # If it's a broken pipe attempt to inform the user, only once
                if not self.broken_pipe:
                    self.broken_pipe = True
                    try:
                        sys.stderr.write("IOError in ChopStdout! Broken Pipe Writing to stdout ... ChopShop Exiting\n")
                    except:
                        pass
                    try:
                        self.lib_stop_fn()
                    except:
                        pass
                    try:
                        self.ui_stop_fn()
                    except:
                        pass
            else: # Other IOError?
                raise

    def handle_ctrl(self, message):
        if message['data']['msg'] == 'finished' and message['data']['status'] == 'error':
            print message['data']['errors']
            raise ChopLibException("Error Shown Above")

    def stop(self):
        pass

class ChopGui:
    def __init__(self, ui_stop_fn = None, lib_stop_fn = None):
        from ChopShopCurses import ChopShopCurses

        self.cui = ChopShopCurses(ui_stop_fn, lib_stop_fn)
        self.cui.go()

    def handle_message(self, message):
        if message['data']['suppress']:
            newline = ""
        else:
            newline = "\n"

        self.cui.add_data(message['id'], message['data']['data'] + newline, message['data']['color'])         

    def handle_ctrl(self, message):
        if message['data']['msg'] == 'addmod':
            self.cui.add_panel(message['data']['id'],message['data']['name'])

        if message['data']['msg'] == 'finished' and message['data']['status'] == 'error':
            self.stop()
            raise ChopLibException(message['data']['errors'])
    
    def stop(self):
        CSD.debug_out("ChopGui stop called\n")
        self.cui.stop()
        self.cui.join()

class ChopFileout:
    
    format_string = None

    def __init__(self, ui_stop_fn = None, lib_stop_fn = None, format_string = None):
        self.filelist = {}
        if format_string is not None:
            self.format_string = format_string

        if format_string[0] == '-':
            raise Exception("Ambiguous file format: '" + format_string + "' -- please fix and run again\n")
        
        if __parse_filepath__(format_string, "placeholder") is None:
            raise Exception("Invald syntax for file output\n")
        
         
    def handle_message(self, message):
        if message['id'] not in self.filelist:
            (fd, error) = __get_open_file__(message['module'], self.format_string, True)
            if fd is not None:
                self.filelist[message['id']] = fd
            else:
                #TODO exception
                pass

        self.filelist[message['id']].write(message['data']['data'])
        if not message['data']['suppress']:
            self.filelist[message['id']].write("\n")
        self.filelist[message['id']].flush()

    def handle_ctrl(self, message):
        pass

    def stop(self):
        pass

class ChopJson:

    format_string = None

    def __init__(self, ui_stop_fn = None, lib_stop_fn = None, format_string = None):
        self.filelist = {}
        if format_string is not None:
            self.format_string = format_string

        if format_string[0] == '-':
            raise Exception("Ambiguous file format: '" + format_string + "' -- please fix and run again\n")
        
        if __parse_filepath__(format_string, "placeholder") is None:
            raise Exception("Invald syntax for json output\n")

        pass

    def handle_message(self, message):
        if message['id'] not in self.filelist: #not already created
            (jd,error) = __get_open_file__(message['module'], self.format_string, True)
            if jd is not None:
                self.filelist[message['id']] = jd
            else:
                #TODO except or otherwise?
                pass

        self.filelist[message['id']].write(message['data']['data'] + "\n")
        self.filelist[message['id']].flush()

    def handle_ctrl(self, message):
        pass

    def stop(self):
        #Cleanup and close any files
        for j,k in self.filelist.iteritems():
            k.close()

class ChopFilesave:
    def __init__(self, ui_stop_fn = None, lib_stop_fn = None, format_string = None):
        self.format_string = format_string
        self.savedfiles = {}
        
        if format_string[0] == '-':
            raise Exception("Ambiguous file format: '" + format_string + "' -- please fix and run again\n")
        
        if __parse_filepath__(format_string, "placeholder") is None:
            raise Exception("Invald syntax for savedir\n")

        pass
   
    def handle_message(self, message):
        filename = message['data']['filename']

        if message['data']['data'] != "":
            #Only if there's data to write
            if not self.savedfiles.has_key(filename):
                try:
                    (self.savedfiles[filename], error) = __get_open_file__(message['module'], self.format_string,
                                                                            True, filename, 
                                                                            message['data']['mode'])

                finally:
                    pass

            if self.savedfiles[filename] is None:
                #TODO error
                del self.savedfiles[filename]
                return
                #pass

            self.savedfiles[filename].write(message['data']['data'])
            self.savedfiles[filename].flush()

        if message['data']['finalize'] and self.savedfiles.has_key(filename):
            self.savedfiles[filename].close()
            del self.savedfiles[filename]
            

    def handle_ctrl(self, message):
        pass

    def stop(self):
        for j,k in self.savedfiles.iteritems():
            k.close()
