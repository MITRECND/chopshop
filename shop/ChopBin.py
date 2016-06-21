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

from ChopException import BinLibException
from ChopBinary import ChopBinary


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
            if not child.binary:
                chop.prettyprnt("YELLOW", "Binary Module cannot forward data to non-binary modules")
                return

            child_copy = outp._clone()
            handleBinary(child, child_copy)
