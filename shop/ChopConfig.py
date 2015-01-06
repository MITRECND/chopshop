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


import ConfigParser
import sys
import os

from pprint import pformat

from ChopException import ChopConfigException
from ChopGV import CHOPSHOP_WD

"""
    ChopConfig handles parsing configuration options which can be leveraged by
    different parts of ChopShop.
"""

DEFAULT_MODULE_DIRECTORY = CHOPSHOP_WD + '/modules/'
DEFAULT_EXTLIB_DIRECTORY = CHOPSHOP_WD + '/ext_libs/'

class ChopOption(object):
    def __init__(self, type, parent = None, default = None):
        self.type = type
        self.parent = parent
        self.value = default 

class ChopConfig(object):


    def __init__(self):
        self.options = {
                            #Config related options
                            'configfile' :  ChopOption('string'),
                            'saveconfig' :  ChopOption('string'),

                            #ChopLib options
                            'mod_dir' :     ChopOption('list', 'Directories'),
                            'ext_dir' :     ChopOption('list', 'Directories'),
                            'base_dir' :    ChopOption('list', 'Directories'), 
                            'filename' :    ChopOption('string', 'General'),
                            'filelist' :    ChopOption('string', 'General'),
                            'bpf' :         ChopOption('string', 'General'),
                            'aslist' :      ChopOption('bool', 'General'),
                            'longrun' :     ChopOption('bool', 'General'),
                            'interface' :   ChopOption('string', 'General'),
                            'modinfo' :     ChopOption('bool', 'General'),
                            'modtree' :     ChopOption('bool', 'General'),
                            'GMT' :         ChopOption('bool', 'General'),
                            'text' :        ChopOption('bool', 'General'),
                            'modules' :     ChopOption('string', 'General'),

                            #Shared options
                            'savedir' :     ChopOption('string', 'Directories'),
                            'jsonout' :     ChopOption('string', 'General'),
                            'pyobjout' :    ChopOption('bool', 'General'),

                            #UI options
                            'stdout' :      ChopOption('bool', 'General'),
                            'gui' :         ChopOption('bool', 'General'),
                            'fileout' :     ChopOption('string', 'General'),
                            'host' :        ChopOption('string', 'General'),
                            'port' :        ChopOption('int', 'General'),
                       }

    @property
    def configfile(self):
        return self.options['configfile'].value

    @configfile.setter
    def configfile(self, v):
        self.options['configfile'].value = v

    @property
    def mod_dir(self):
        """Directory to load modules from."""
        return self.options['mod_dir'].value

    @mod_dir.setter
    def mod_dir(self, v):
        self.options['mod_dir'].value = v

    @property
    def ext_dir(self):
        """Directory to load external libraries from."""
        return self.options['ext_dir'].value

    @ext_dir.setter
    def ext_dir(self, v):
        self.options['ext_dir'].value = v

    @property
    def base_dir(self):
        """Base directory to load modules and external libraries."""
        return self.options['base_dir'].value

    @base_dir.setter
    def base_dir(self, v):
        self.options['base_dir'].value = v

    @property
    def filename(self):
        """input pcap file."""
        return self.options['filename'].value

    @filename.setter
    def filename(self, v):
        self.options['filename'].value = v

    @property
    def filelist(self):
        """list of files to process"""
        return self.options['filelist'].value

    @filelist.setter
    def filelist(self, v):
        self.options['filelist'].value = v

    @property
    def aslist(self):
        """Treat filename as a file containing a list of files."""
        return self.options['aslist'].value

    @aslist.setter
    def aslist(self, v):
        self.options['aslist'].value = v

    @property
    def longrun(self):
        """Read from filename forever even if there's no more pcap data."""
        return self.options['longrun'].value

    @longrun.setter
    def longrun(self, v):
        self.options['longrun'].value = v

    @property
    def interface(self):
        """interface to listen on."""
        return self.options['interface'].value

    @interface.setter
    def interface(self, v):
        self.options['interface'].value = v

    @property
    def modinfo(self):
        """print information about module(s) and exit."""
        return self.options['modinfo'].value

    @modinfo.setter
    def modinfo(self, v):
        self.options['modinfo'].value = v

    @property
    def modtree(self):
        """print information about module tree and exit."""
        return self.options['modtree'].value

    @modtree.setter
    def modtree(self, v):
        self.options['modtree'].value = v

    @property
    def GMT(self):
        """timestamps in GMT (tsprnt and tsprettyprnt only)."""
        return self.options['GMT'].value

    @GMT.setter
    def GMT(self, v):
        self.options['GMT'].value = v

    @property
    def text(self):
        """Handle text/printable output. """
        return self.options['text'].value

    @text.setter
    def text(self, v):
        self.options['text'].value = v

    @property
    def pyobjout(self):
        """Handle raw python objects"""
        return self.options['pyobjout'].value

    @pyobjout.setter
    def pyobjout(self, v):
        self.options['pyobjout'].value = v

    @property
    def jsonout(self):
        """Handle JSON Data (chop.json)."""
        return self.options['jsonout'].value

    @jsonout.setter
    def jsonout(self, v):
        self.options['jsonout'].value = v

    @property
    def savedir(self):
        """Location to save carved files."""
        return self.options['savedir'].value

    @savedir.setter
    def savedir(self, v):
        self.options['savedir'].value = v

    @property
    def modules(self):
        """String of Modules to execute"""
        return self.options['modules'].value

    @modules.setter
    def modules(self, v):
        self.options['modules'].value = v

    @property
    def bpf(self):
        """BPF string to pass to Nids"""
        return self.options['bpf'].value

    @bpf.setter
    def bpf(self, v):
        self.options['bpf'].value = v

    @property
    def stdout(self):
        return self.options['stdout'].value

    @stdout.setter
    def stdout(self, v):
        self.options['stdout'].value = v

    @property
    def gui(self):
        return self.options['gui'].value

    @gui.setter
    def gui(self, v):
        self.options['gui'].value = v

    @property
    def fileout(self):
        return self.options['fileout'].value

    @fileout.setter
    def fileout(self, v):
        self.options['fileout'].value = v

    @property
    def host(self):
        return self.options['host'].value

    @host.setter
    def host(self, v):
        self.options['host'].value = v

    @property
    def port(self):
        return self.options['port'].value

    @port.setter
    def port(self, v):
        self.options['port'].value = v


    def __str__(self):
        flat  = {}
        for key in self.options.keys():
            flat[key] = self.options[key].value
        return pformat(flat)


    def parse_opts(self, options, args=[]):
        global CHOPSHOP_WD
        global DEFAULT_MODULE_DIRECTORY
        global DEFAULT_EXTLIB_DIRECTORY

        #Parse config file first
        if options.configfile:
            self.parse_config(options.configfile)

        #Commandline options should override config file options
        for opt, val in options.__dict__.items():
            if opt in self.options and val is not None:
                self.options[opt].value = val
        
        if self.base_dir is not None and CHOPSHOP_WD not in self.base_dir:
            self.base_dir.append(CHOPSHOP_WD)

        if self.mod_dir is not None and DEFAULT_MODULE_DIRECTORY not in self.mod_dir:
            self.mod_dir.append(DEFAULT_MODULE_DIRECTORY)
        elif self.base_dir is None and self.mod_dir is None:
            self.mod_dir = [DEFAULT_MODULE_DIRECTORY]

        if self.ext_dir is not None and DEFAULT_EXTLIB_DIRECTORY not in self.ext_dir:
            self.ext_dir.append(DEFAULT_EXTLIB_DIRECTORY)
        elif self.base_dir is None and self.ext_dir is None:
            self.ext_dir = [DEFAULT_EXTLIB_DIRECTORY]

        if len(args) <= 0 and not options.configfile and not options.saveconfig:
            raise ChopConfigException("Module List Required")
        elif len(args) == 1:
            self.modules = args[0]
        elif len(args) > 1:
            if len(args[0]) > 0 and args[0] != 'None':
                self.bpf = args[0]

            if args[1] == 'None':
                raise ChopConfigException("module list required")
            elif len(args[1]) > 0:
                self.modules = args[1]

        return


    def parse_config(self, configfile):
        if not os.path.exists(configfile):
            raise ChopConfigException("could not find configuration file: %s" % configfile)
        cfg = ConfigParser.ConfigParser()        
        cfg.read(configfile)
        cfg.optionxform = str

        for opts in self.options.keys():
            try:
                if self.options[opts].parent is None:
                    continue

                if self.options[opts].type == "bool":
                    self.options[opts].value = cfg.getboolean(self.options[opts].parent, opts)
                elif self.options[opts].type == "list":
                    self.options[opts].value = cfg.get(self.options[opts].parent, opts).split(',')
                else: #assume string for now
                    self.options[opts].value = cfg.get(self.options[opts].parent, opts)
            except:
                pass
    
        return


    def save_config(self, filepath):
        try:
            fp = open(filepath, 'w')
            cfg = ConfigParser.ConfigParser()
            cfg.optionxform = str

            cfg.add_section('Directories')
            cfg.add_section('General')

            for opts in self.options.keys():
                if self.options[opts].value is not None and self.options[opts].parent is not None:
                    if self.options[opts].type == "list":
                        cfg.set(self.options[opts].parent, opts, ','.join(self.options[opts].value))
                    else:
                        cfg.set(self.options[opts].parent, opts, self.options[opts].value)

            cfg.write(fp)
            fp.close()
        except IOError, e:
            raise ChopConfigException(e)
        return
