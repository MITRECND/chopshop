import sys
import os
from threading import Thread, Lock
import Queue

CHOPSHOP_WD = os.path.realpath(os.path.dirname(sys.argv[0]))

if CHOPSHOP_WD + '/shop' not in sys.path:
    sys.path.append(CHOPSHOP_WD + '/shop')

from ChopUiStd import *
import ChopShopDebug as CSD


class ChopUi(Thread):
    def __init__(self):
        Thread.__init__(self)


        self.options = { 'stdout'   : False,
                         'gui'      : False,
                         'fileout'  : False,
                         'filedir'  : None,
                         'savedir'  : None,
                         'savefiles': False,
                         'jsonout'  : False,
                         'jsondir'  : None
                       }

        self.stopped = False 
        self.isrunning = False
        self.message_queue = None
        self.lib_stop_fn = None


    @property
    def stdout(self):
        """Output to stdout"""
        return self.options['stdout']

    @stdout.setter
    def stdout(self, v):
        self.options['stdout'] = v

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
        self.isrunning = True
        #Check to see what has been enabled on the 'text' side

        stdclass = None
        uiclass = None
        fileoclass = None
        jsonclass = None
        filesclass = None

        if self.options['stdout'] == True:
            stdclass = ChopStdout()
            #Assign the default stdout handler 
        elif self.options['stdout'] != False:
            stdclass = self.options['stdout']()
            #Override the default handler with this one 

        if self.options['gui'] == True:
            uiclass = ChopGui(self.stop, self.lib_stop_fn)
        elif self.options['gui'] != False:
            uiclass = self.options['gui'](self.stop, self.lib_stop_fn)

        if self.options['fileout'] == True:
            fileoclass = ChopFileout(format_string = self.options['filedir'])
        elif self.options['fileout'] != False:
            fileoclass = self.options['fileout'](format_string = self.options['filedir'])

        if self.options['jsonout'] == True:
            jsonclass = ChopJson(format_string = self.options['jsondir'])
        elif self.options['jsonout'] != False:
            jsonclass = self.options['jsonout'](format_string = self.options['jsondir'])

        if self.options['savefiles'] == True:
            filesclass = ChopFilesave(format_string = self.options['savedir'])
        elif self.options['savefiles'] != False:
            filesclass = self.options['savefiles'](format_string = self.options['savedir'])

        while not self.stopped:

            try:
                message = self.message_queue.get(True, .1)
            except Queue.Empty, e:
                continue


            if message['type'] == 'ctrl':
                if stdclass is not None:
                    stdclass.handle_ctrl(message)
                if uiclass is not None:
                    uiclass.handle_ctrl(message)
                if fileoclass is not None:
                    fileoclass.handle_ctrl(message)
                if jsonclass is not None:
                    jsonclass.handle_ctrl(message)
                if filesclass is not None:
                    filesclass.handle_ctrl(message)

                #The GUI is the only thing that doesn't care if the core is no
                #longer running
                if message['data']['msg'] == 'finished' and uiclass is None:
                    self.stop()
                    continue

            if message['type'] == 'text':
                if stdclass is not None:
                    stdclass.handle_message(message)
                if uiclass is not None:
                    uiclass.handle_message(message)
                if fileoclass is not None:
                    fileoclass.handle_message(message)

            if message['type'] == 'json':
                if jsonclass is not None:  
                    jsonclass.handle_message(message)
            
            if message['type'] == 'filedata':
                if filesclass is not None:
                    filesclass.handle_message(message) 

        CSD.debug_out("Sending Stop Messages\n")
        if stdclass is not None:
            stdclass.stop()
        if uiclass is not None:
            uiclass.stop()
        if fileoclass is not None:
            fileoclass.stop()
        if jsonclass is not None:
            jsonclass.stop()
        if filesclass is not None:
            filesclass.stop()

        self.isrunning = False
        return
