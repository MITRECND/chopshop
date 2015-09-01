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


import copy

class ChopProtocol(object):

    def __init__(self, type):
        self.addr = None
        self.timestamp = None
        self.clientData = None
        self.serverData = None

        #These should not be modified on the fly
        #or directly touched by module authors
        self.type = type
        self.sval = False
        self.unique = None
        self._teardown = False

    def setTeardown(self, v = True):
        self._teardown = v

    #If your data is complex enough
    #you MUST inherit from ChopProtocol and redefine _clone
    def _clone(self):
        return copy.deepcopy(self)

    def setUniqueId(self, unique):
        self.unique = unique

    def setAddr(self, addr):
        self.addr = addr

    def setTimeStamp(self, timestamp):
        self.timestamp = timestamp

    def setClientData(self, data):
        self.clientData = data

    def setServerData(self, data):
        self.serverData = data

    def stop(self):
        self.sval = True

