#!/usr/bin/env python

# Copyright (c) 2013 The MITRE Corporation. All rights reserved.
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

CHOPSHOP_WD = os.path.realpath(os.path.dirname(sys.argv[0]))

if CHOPSHOP_WD + '/shop' not in sys.path:
    sys.path.append(CHOPSHOP_WD + '/shop')

"""
    ChopConfig handles parsing configuration options which can be leveraged by
    other parts of ChopShop and ChopWeb.
"""

class ChopConfig():

    global CHOPSHOP_WD

    base_dir = ''
    configfile = ''
    ext_dir = CHOPSHOP_WD + '/ext_libs/'
    mod_dir = CHOPSHOP_WD + '/modules/'
    savedir = '/tmp/'
    aslist = False
    bpf = ''
    filelist = ''
    filename = ''
    fileout = ''
    host = ''
    GMT = False
    gui = False
    interface = ''
    modinfo = False
    modules = None
    longrun = False
    port = 8080
    pyobjout = False
    jsonout = ''
    saveconfig = ''
    savefiles = False
    stdout = False
    text = False


    def __init__(self):
        pass


    def __str__(self):
        return pformat(self.__dict__)


    def parse_opts(self, options, args=[]):
        if options.configfile:
            self.parse_config(options.configfile)
        for opt, val in options.__dict__.items():
            if val:
                setattr(self, opt, val)
        if len(args) <= 0 and not options.configfile:
            raise ChopConfigException("Module List Required")
        elif len(args) == 1:
            self.modules = args[0]
        elif len(args) > 1:
            if args[0] == 'None':
                self.bpf = ''
            elif len(args[0]) > 0:
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
        opt_list = {'Directories': ['mod_dir',
                                    'ext_dir',
                                    'base_dir',
                                    'savedir'],
                    'General': ['aslist',
                                'bpf',
                                'filelist',
                                'filename',
                                'fileout',
                                'GMT',
                                'gui',
                                'interface',
                                'jsonout',
                                'longrun',
                                'modinfo',
                                'modules',
                                'pyobjout',
                                'savefiles',
                                'stdout',
                                'text']
                    }
        bool = ['aslist', 'gui', 'GMT', 'longrun', 'modinfo',
                'pyobjout', 'savefiles', 'stdout', 'text', 'version']
        for k,v in opt_list.iteritems():
            for i in v:
                try:
                    if i in bool:
                        o = cfg.getboolean(k, i)
                    else:
                        o = cfg.get(k, i)
                    setattr(self, i, o)
                except:
                    pass
        return


    def save_config(self, filepath):
        try:
            fp = open(filepath, 'w')
            cfg = ConfigParser.ConfigParser()
            cfg.add_section('Directories')
            cfg.add_section('General')
            cfg.set('Directories', 'base_dir', self.base_dir)
            cfg.set('Directories', 'ext_dir', self.ext_dir)
            cfg.set('Directories', 'mod_dir', self.mod_dir)
            cfg.set('Directories', 'savedir', self.savedir)
            cfg.set('General', 'aslist', self.aslist)
            cfg.set('General', 'bpf', self.bpf)
            cfg.set('General', 'filelist', self.filelist)
            cfg.set('General', 'filename', self.filename)
            cfg.set('General', 'fileout', self.fileout)
            cfg.set('General', 'GMT', self.GMT)
            cfg.set('General', 'gui', self.gui)
            cfg.set('General', 'interface', self.interface)
            cfg.set('General', 'jsonout', self.jsonout)
            cfg.set('General', 'longrun', self.longrun)
            cfg.set('General', 'modinfo', self.modinfo)
            cfg.set('General', 'modules', self.modules)
            cfg.set('General', 'pyobjout', self.pyobjout)
            cfg.set('General', 'savefiles', self.savefiles)
            cfg.set('General', 'stdout', self.stdout)
            cfg.set('General', 'text', self.text)
            cfg.write(fp)
            fp.close()
        except IOError, e:
            raise ChopConfigException(e)
        return
