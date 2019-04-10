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

# shop/ChopHelper

import sys
import os
import time
import json
from datetime import datetime

from threading import Thread
from threading import Lock
import Queue

# from multiprocessing import Queue as mQueue
import ChopShopDebug as CSD


class chops:
    """
    The chops class is the interface for ChopShop and modules to send output
    properly. Each module is given a reference to it's own chops class called
    "chop" -- this allows them to use function calls like chop.prnt("foo")
    in their module without having to do too much else to send output to the
    proper channel based on the user's settings

    chops provides four (4) main "channels" of output currently, which are:

    1. prnt
            Basic print functionality, "print" is a keyword in python 2.x and
            so could not be reused. Should accept the same syntax as a call
            to print depending on what the user has set (out to stdout, out
            to ui, etc.) this function will route the output to the desired
            location

    2. debug (DEPRECATED)
            No one was using this, so this has been deprecated

    3. json
            Json output to file, outputs json data to a json specific file. A
            module can specify a custom json encoder by calling
            set_custom_json_encoder and passing a function

    4. output files
            Allow a module writer to output files carved from their module in
            a respectable manner, the following commands are avaialble:

            savefile
                Save carved or other files from within a module, takes a
                filename, the data, and an optional "finalize" variable
                (default True) if finalize is set to false, chops will keep
                the file open, otherwise will close the file, also note that
                this will open the file with the 'w' flag so it will overwrite
                existing files
            appendfile
                Same as savefile except it opens files in 'a' mode which will
                not overwrite existing files, also defaults its 'finalize' to
                False, so it keeps the handle open until explicitly closed
            finalizefile
                Given a filename will close the handle to it (if open). If the
                file is not open, this is a noop

    """

    GMT = False
    to_outs = None

    def __init__(self, id, name, dataq, core=None):
        self.id = id
        self.name = name
        self.dataq = dataq
        self.core = core
        self.cls = None
        self.tsformatshort = False

    def debug(self, *fmtstring):
        self.prnt(*fmtstring)

    def tsprnt(self, *fmtstring):
        self.tsprettyprnt(None, *fmtstring)

    def tsprettyprnt(self, color, *fmtstring):
        if self.to_outs['text']:
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
        if self.to_outs['text']:
            mystring = u''

            supress = False
            extents = None

            if len(fmtstring) > 0 and fmtstring[-1] is None:
                extents = -1
                supress = True

            for (counter, strn) in enumerate(fmtstring[0:extents]):
                if not isinstance(strn, unicode):
                    try:
                        strn = unicode(strn)
                    except Exception as e:
                        pass

                if counter > 0:
                    mystring += ' '

                try:
                    mystring = "%s%s" % (mystring, strn)
                except Exception as e:
                    raise TypeError("Unable to create string from inputs")

            message = self.__get_message_template__()
            message['type'] = 'text'
            message['data'] = {'data': mystring,
                               'suppress': supress,
                               'color': color}

            self.dataq.put(message)

    def savefile(self, filename, data, finalize=True, prepend_timestamp=False):
        if prepend_timestamp:
            if self.core is not None:
                ts = self.core.getptime()
                if self.GMT:
                    fmt = "%Y%m%d%H%M%SZ"
                    ts = time.gmtime(ts)
                else:
                    fmt = "%Y%m%d%H%M%S%Z"
                    ts = time.localtime(ts)
                filename = "%s-%s" % (time.strftime(fmt, ts).strip(), filename)
        self.appendfile(filename, data, finalize, 'w')
        return filename

    # mode should not be used by chop users --
    # it is meant to be used by savefile
    def appendfile(self, filename, data, finalize=False, mode='a'):
        if self.to_outs['savefiles']:
            message = self.__get_message_template__()
            message['type'] = 'filedata'
            message['data'] = {'filename': filename,
                               'data': data,
                               'mode': mode,
                               'finalize': finalize}

            self.dataq.put(message)

    def finalizefile(self, filename):
        if self.to_outs['savefiles']:
            self.appendfile(filename, "", True)

    def tsjson(self, obj, key='timestamp'):
        if self.core is not None:
            ptime = ""
            ts = self.core.getptime()
            if self.GMT:
                fmt = "%Y-%m-%d %H:%M:%S +0000"
                ts = time.gmtime(ts)
            else:
                fmt = "%Y-%m-%d %H:%M:%S %Z"
                ts = time.localtime(ts)

            ptime = time.strftime(fmt, ts).rstrip()
            obj[key] = ptime

        self.json(obj)

    def json(self, obj):
        if self.to_outs['json']:

            try:
                if self.cls is not None:
                    jdout = json.dumps(obj, cls=self.cls)
                else:
                    jdout = json.dumps(obj)
            except Exception, e:
                msg = "FATAL ERROR in chop.json"
                if self.cls is not None:
                    msg = msg + " with custom json encoder"
                self.prettyprnt("RED", msg, e)
                return  # don't put anything onto the queue

            message = self.__get_message_template__()
            message['type'] = 'json'
            message['data'] = {'data': jdout}

            self.dataq.put(message)

    def pyobj(self, obj):
        if self.to_outs['pyobj']:
            message = self.__get_message_template__()
            message['type'] = 'pyobj'
            message['data'] = obj

            try:
                self.dataq.put(message)
            except Exception, e:
                msg = "FATAL ERROR in chop.pyobj"
                self.prettyprnt("RED", msg, e)

    def pyjson(self, obj):
        self.pyobj(obj)
        self.json(obj)

    def set_custom_json_encoder(self, cls):
        self.cls = cls

    def set_ts_format_short(self, on=False):
        self.tsformatshort = on

    def __get_message_template__(self):
        message = {'module': self.name,
                   'id': self.id,
                   'time': '',
                   'addr': {'src': '',
                            'dst': '',
                            'sport': '',
                            'dport': ''},
                   'proto': ''}

        if self.core is not None:
            metadata = self.core.getmeta()

            if 'proto' in metadata:
                # if proto is in metadata it was filled out
                message['proto'] = metadata['proto']
                message['time'] = metadata['time']
                message['addr'] = {'src': metadata['addr']['src'],
                                   'dst': metadata['addr']['dst'],
                                   'sport': metadata['addr']['sport'],
                                   'dport': metadata['addr']['dport']}
        return message


class ChopHelper:
    """
     ChopHelper keeps track of all of the "chops" instances and provides an
     easy to use interface to obtain an instance. It also informs the caller
     that a new module has been added
    """
    def __init__(self, tocaller, options):
        self.tocaller = tocaller
        self.to_outs = {'text': False,
                        'json': False,
                        'savefiles': False,
                        'pyobj': False}
        self.choplist = []
        self.core = None

        if options['text']:
            self.to_outs['text'] = True

        if options['jsonout']:
            self.to_outs['json'] = True

        if options['savefiles']:
            self.to_outs['savefiles'] = True

        if options['pyobjout']:
            self.to_outs['pyobj'] = True

        chops.GMT = options['GMT']
        chops.to_outs = self.to_outs

    # TODO add capability to modify to_outs on the fly

    def set_core(self, core):
        self.core = core

    def setup_main(self):
        return self.setup_module("ChopShop")

    def setup_module(self, name, id=0):
        if id == 0:
            id = len(self.choplist)

        chop = chops(id, name, self.tocaller, self.core)
        self.choplist.append({'chop': chop, 'id': id})

        # Inform the caller that we are adding a module
        message = {'type': 'ctrl',
                   'data': {'msg': 'addmod',
                            'name': name,
                            'id': id}}

        self.tocaller.put(message)
        return chop

    def setup_dummy(self):
        chop = chops(-1, 'dummy', self.tocaller, self.core)
        chop.to_outs = {'text': False,
                        'json': False,
                        'savefiles': False,
                        'pyobj': False}
        return chop
