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

from threading import Lock, Thread
import threading
import time

""" 
    ChopShop Debug Helper DO NOT MODIFY -- DO NOT TOUCH -- DO NOT USE
    This code should not be used in day to day and should not be used by any modules
    It's sole usage is for debugging the core of ChopShop where exception handling can get
    tricky (mainly with threads)

"""

DEBUG = False

def enable_debug(output = None):
    global DEBUG
    global df
    global dbglock

    DEBUG = True
    debugfile = 'debugout'
    dbglock = Lock()

    if output is not None:
        debugfile = output

    df = open(debugfile, 'w')

def debug_out(output):
    global DEBUG

    if DEBUG:
        global df
        global dbglock
        dbglock.acquire()
        try:
            df.write(output)
            df.flush()
        finally:
            dbglock.release()

class ThreadWatcher(Thread):
    daemon = True
    def __init__(self, interval):
        Thread.__init__(self, name="Watcher")
        self.interval = interval

    def run(self):
        while True:
            thread_list = []
            for thread in threading.enumerate():
                thread_list.append(thread.name)
            print("%d active threads: %s" % (threading.active_count(), ', '.join(thread_list)))
            time.sleep(self.interval)
         
