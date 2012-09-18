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

import sys
from threading import Thread
import curses
from curses import ascii
import binascii
import time
import os
import fcntl
import termios
import struct


import ChopShopDebug as CSD

BUFFER_SIZE = 10000

class Color:
    YELLOW = curses.A_NORMAL
    CYAN = curses.A_NORMAL 
    MAGENTA = curses.A_NORMAL 
    GREEN = curses.A_NORMAL 
    RED = curses.A_NORMAL
    BLUE = curses.A_NORMAL 
    BLACK = curses.A_NORMAL
    WHITE = curses.A_NORMAL

    def __init__(self):
        pass

    def define_colors(self, has_colors):
        if not has_colors:
            return

        curses.init_pair(1, 3, 0) #Yellow on Black
        curses.init_pair(2, 6, 0) #Cyan on Black
        curses.init_pair(3, 5, 0) #Magenta on Black
        curses.init_pair(4, 2, 0) #Green on Black
        curses.init_pair(5, 1, 0) #Red on Black
        curses.init_pair(6, 4, 0) #Blue on Black

        self.YELLOW = curses.color_pair(1)
        self.CYAN = curses.color_pair(2)
        self.MAGENTA = curses.color_pair(3)
        self.GREEN = curses.color_pair(4)
        self.RED = curses.color_pair(5)
        self.BLUE = curses.color_pair(6)
        self.BLACK = curses.A_STANDOUT
        self.WHITE = curses.color_pair(0)

    def get_color(self, color):
        if color == "YELLOW":
            return self.YELLOW
        elif color == "CYAN":
            return self.CYAN
        elif color == "MAGENTA":
            return self.MAGENTA
        elif color == "GREEN":
            return self.GREEN
        elif color == "RED":
            return self.RED
        elif color == "BLUE":
            return self.BLUE
        elif color == "BLACK":
            return self.BLACK
        elif color == "WHITE":
            return self.WHITE
        else:
            return curses.A_NORMAL

Colors = Color()

"""
    vpanel is a "virtual" data panel and stores the data for a given window, it also keeps
    track of where the panel is.

    If you would like to create your own UI instance, know that vpanel is necessary, but only the
    add_data function need be exposed

    add_data -- will set the data in the buffer to what was received

"""

class vpanel:
    panel_id = 0

    def __init__(self,wn):
        self.position = 0
        self.data = []
        self.autoscroll = True
        self.windowname = wn
        self.evencolor = True
        vpanel.panel_id += 1

    def add_data(self, data, color = None):
        global Colors
        newdata = ""
        for ch in str(data):
            #printable characters and \t \n and are output to the screen
            #all others are hexlified
            if ascii.isprint(ch) or  ch == "\t" or ch == "\n":
                newdata += ch
            else:
                newdata +=  "\\" +  str(hex(ord(ch)))[1:]

        if color is None:
            dcolor = Colors.YELLOW
            if self.evencolor:
                dcolor = Colors.CYAN
            self.evencolor = not self.evencolor
        else:
            dcolor = Colors.get_color(color) 
            

        self.data.append([newdata, dcolor])

    def resize(self):
        CSD.debug_out("Resize called\n")
        start = len(self.data)/4
        self.data = self.data[start:]


"""
    ChopUI is an abstracted interface to the curses-based ui -- it is the "public" interface
    that is used by the output capability used by ChopShop. The following functions *must* exist for compatibility
    with ChopShop's Ouput Helpers:

    new_panel -- given a name will setup a window/panel and return a reference to that panel
                 as mentioned above 

    setup_core_ref -- a queue that can be given array commands such as ['stop']

    go -- will start the UI

    join -- wait for UI to finish

    stop -- stop the UI - only needs to be used in an instance where the UI is being forcefully shut down (Ctrl-c)

    Any other function can be internal only and the actual UI implementation can be done in any way as long as the frontend
    conforms to these requirements
"""

class ChopUI:
    def __init__(self):
        self.stdscr = None

        self.buildup()
        self.nui = ChopCurses(self.stdscr)    

    def new_panel(self, name):
        return self.nui.new_vpanel(name)        

    def setup_core_ref(self, core):
        self.nui.setup_core_ref(core)

    def buildup(self):
        self.stdscr = curses.initscr()
        curses.start_color()
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(1)

    def teardown(self):
        self.stdscr.keypad(0)
        curses.nocbreak() 
        curses.echo() 
        curses.endwin()

    def join(self):
        while self.nui.is_alive(): #loop so signals still work
            self.nui.join(.1)
        self.teardown()

    def stop(self):
        self.nui.stop()#should run once more then quit
        self.nui.join()
        self.teardown()

 
    def go(self):
        self.nui.start()

"""
    This is the actual ui implementation and it utilizes ncurses to display a terminal GUI.

    As it stands the UI displays a title window at the top, a left-hand side navigation window and the rest of the space
    is used to display the data for a given "window" or "panel"

    The following keys are supported:
   
    Left  or h: Cycles to the "left" window (the window above in the navigation window)
    Right or l: Cycles to the "right" window (the window below in the navigation window)
    Up    or k: Moves up one line in the data display window
    Down  or j: Moves down one line in the data display window
    PgDwn or J: Moves down 10 lines in the data display window
    PgUp  or K: Moves up 10 lines in the data display window
             b: Moves to the beginning line in the data display window
             n: Moves to the end line in the data display window 
             s: Toggles autoscroll for the given data display window -- default is True
             q: Quits the UI -- also halts execution of the core
             Q: Quits the core -- leaves the UI up and running

"""


class ChopCurses(Thread):
    dlines = 0
    dcols = 0
    dyval = 0
    dxval = 0

    nlines = 0
    ncols = 0
    nyval = 0
    nxval = 0

    stdscr = 0

    panels = []
    current_win = 0
    
    title_window = 0
    nav_window = 0
    data_window = 0

    #Seed to termios.TIOCCWINSZ to get H,W
    seed = struct.pack("HH", 0,0) 

    def __init__(self, stdscr):
        Thread.__init__(self)
        self.started = False
        self.colors = False
        self.stopped = False
        self.stdscr = stdscr

        global Colors

        if curses.has_colors():
            self.colors =  True
            Colors.define_colors(True)

        #Colors is color safe, if colors are not available it will be equal to
        #curses.A_NORMAL
        self.titlecolor = Colors.RED
        self.navcolor = Colors.MAGENTA 

    def setup_core_ref(self, core):
        self.core = core

    def stop(self):
        self.stopped = True

    def run(self):
        self.calculate_dimensions()
        self.windowH = curses.LINES
        self.windowW = curses.COLS

        self.title_window = curses.newwin(1,0,0,0)
        self.nav_window = curses.newwin(self.nlines, self.ncols, self.nyval, self.nxval)
        #Create the pad window
        self.data_window = curses.newpad(BUFFER_SIZE, self.dcols)
        self.data_window.keypad(1)
        self.data_window.timeout(100) #100 ms

        self.update_title()
        self.update_windows()

        CSD.debug_out("Before While Loop\n")

        counter = time.time()
        self.started = True
        while not self.stopped:
            c = self.data_window.getch()

            self.check_resize_ui()
            #Update every 1 seconds
            newtime = time.time()
            if newtime - counter >= 1 :
                counter = newtime
                if self.panels[self.current_win].autoscroll:
                    self.scroll_end()

                #check to see if window has been resized
                if not self.check_resize_ui():
                    self.update_windows()

            if not self.handle_input(c):
                break

    def handle_input(self, c):
        if (c == -1): #means the timeout was reached and no key was received
            return True
        if (c == curses.KEY_RESIZE):#Due to timeout and whatnot this event is not always received
            self.resize_ui(False)
        elif (c == curses.KEY_LEFT or c == ord('h')):
            if self.current_win != 0:
                self.current_win -= 1
                self.update_windows()
        elif (c == curses.KEY_RIGHT or c == ord('l')):
            if self.current_win != len(self.panels) - 1:
                self.current_win += 1
                self.update_windows()
        elif (c == curses.KEY_UP or c == ord('k')):
            if self.panels[self.current_win].position > 0:
                self.panels[self.current_win].position -= 1
                self.update_pad_simple()
        elif (c == curses.KEY_DOWN or c == ord('j')):
            if self.panels[self.current_win].position < BUFFER_SIZE:
                self.panels[self.current_win].position += 1
                self.update_pad_simple()
        elif (c == curses.KEY_NPAGE or c == ord('J')):
            if self.panels[self.current_win].position >= BUFFER_SIZE - 10:
                self.panels[self.current_win].position = BUFFER_SIZE
            else:
                self.panels[self.current_win].position += 10
            self.update_pad_simple()
        elif (c == curses.KEY_PPAGE or c == ord('K')):
            if self.panels[self.current_win].position <= 10:
                self.panels[self.current_win].position = 0
            else:
                self.panels[self.current_win].position -= 10
            self.update_pad_simple()
        elif (c == ord('b')): #scroll to the beginning
            self.panels[self.current_win].position = 0
            self.update_pad_simple()
        elif (c == ord('n')): #scroll to the end
            self.scroll_end()
            self.update_pad_simple()
        elif (c == ord('s')):#Toggles autoscrolling -- by default this is enabled
            if self.panels[self.current_win].autoscroll:
                self.panels[self.current_win].autoscroll = False
            else:
                self.panels[self.current_win].autoscroll = True
        elif (c == ord('q')):
            #Stop the Core
            try:
                self.core.put(['stop'])
            except:
                pass
            return False
        elif (c == ord('Q')):
            #Stop the Core
            try:
                self.core.put(['stop'])
            except:
                pass
        else:
            if c != -1:
                CSD.debug_out("Unknown Key\n")

        return True

    def new_vpanel(self, name):
        ndvwin = vpanel(name)
        self.panels.append(ndvwin)
       
        if self.started:
            self.update_navigation() 

        return ndvwin


    def check_resize_ui(self):
        try:
            (h,w) = self.check_term_size()
        except:
            CSD.debug_out("Exception in check_term_size\n")
            raise

        if (w != self.windowW) or (h != self.windowH):
            self.windowW = w
            self.windowH = h
            self.resize_ui(True)
            return True

        return False
        

    def resize_ui(self, use_self, attempts = 0):

        CSD.debug_out("Resize Called (" + `attempts` +") -\n\t" + `curses.LINES` + " " + `curses.COLS` + "\n")

        if use_self: #there's no need to do another lookup if called by check_resize_ui
            (w,h) = (self.windowW, self.windowH)
        else:
            try:
                (h,w) = self.check_term_size()
            except:
                CSD.debug_out("Exception in check_term_size\n")
                raise

        CSD.debug_out("\t" + `h` + " " +`w` + "\n")

        if(curses.COLS == w and curses.LINES == h):
            return

        (curses.COLS, self.windowW) = (w,w)
        (curses.LINES,self.windowH) = (h,h)

        #clear all of the windows
        self.stdscr.clear()
        self.nav_window.clear()
        self.title_window.clear()
        self.data_window.clear()

        #Need to refresh to remove extraneous characters that might be leftover
        self.nav_window.nooutrefresh()
        self.title_window.nooutrefresh()
        self.stdscr.nooutrefresh()

        #Get the new dimensions of the navigation and data windows
        self.calculate_dimensions()

        CSD.debug_out("Resizing Nav - " + `curses.LINES - 2` + " " + `curses.COLS/8` + "\n")

        #Resize Windows
        self.title_window.resize(1,curses.COLS)
        self.nav_window.resize(self.nlines, self.ncols)
        self.data_window.resize(BUFFER_SIZE, self.dcols)

        self.update_title()
            
        #Reset autoscroll on all panels
        for panel in self.panels:
            panel.autoscroll = True

        #Attempt to refresh the windows
        #if it fails, retry up to 5 times -- haven't seen it make it higher than 3
        try:
            self.update_windows()
        except curses.error:
            if(attempts > 5):
                raise 
            self.resize_ui(False, attempts + 1)

    def calculate_dimensions(self):
        self.dlines = curses.LINES - 3
        self.dcols = ((curses.COLS/8) * 7) - 3
        self.dyval = 2
        self.dxval = (curses.COLS/8) + 2

        self.nlines = curses.LINES - 2
        self.ncols = curses.COLS/8
        self.nyval = 1
        self.nxval = 0

    def scroll_end(self): #scrolls to the end of the data_window
        #Scrolls to the "end"
        CSD.debug_out("Window positions Y,X: %u, %u\n" % self.data_window.getyx())
        (y, x) = self.data_window.getyx() # get current position of cursor

        end = y
        end_pos = 0
        if end - self.dlines > 0:
            end_pos = end - ((self.dlines/16) * 15) #arbitrarily 15/16 of the screen

        if end_pos > BUFFER_SIZE:
            end_pos = BUFFER_SIZE

        CSD.debug_out("Setting end position to: " + str(end_pos) + "\n")

        self.panels[self.current_win].position = end_pos

    def update_windows(self):
        CSD.debug_out("Updating Window\n")
        self.update_navigation()
        self.update_pad()

    def update_title(self):
        self.title_window.addstr("ChopShop", self.titlecolor)
        self.title_window.nooutrefresh()
    
    def update_navigation(self):
        self.nav_window.erase()
        self.nav_window.addstr(1,1, "Navigation Window\n\n", self.navcolor)
        
        counter = 0
        for pan in self.panels:
            standout = curses.A_NORMAL
            if counter == self.current_win and self.colors:
                standout = curses.A_STANDOUT

            self.nav_window.addstr(" " + pan.windowname + "\n", standout )
            counter += 1

        self.nav_window.border()

        try:
            self.nav_window.refresh()
        except:
            pass

    def update_pad_simple(self): #updates the view of the pad instead of the entire contents
        try:
            self.data_window.refresh(self.panels[self.current_win].position, 0, self.dyval, self.dxval, self.dlines, self.dxval + self.dcols)
        except:
            pass #get it on the next go


    def update_pad(self):
        self.data_window.erase()

        for data in self.panels[self.current_win].data:
            try:
                self.data_window.addstr(data[0], data[1])
            except:
                self.panels[self.current_win].resize()
                self.update_pad()
                return

        try:
            self.data_window.nooutrefresh(self.panels[self.current_win].position,0, self.dyval, self.dxval, self.dlines , self.dxval + self.dcols) 
            curses.doupdate()
        except:
            pass #get it on the next go


    def check_term_size(self):
        def check_term(tid):
            try:
                #Format should be Height, Width, X Pixels and Y Pixels
                #Can't figure out why, but TIOCGWINSZ requires an argument the size of what it's going to return
                #but doesn't actually modify it (which is how I'd write it)-- so if you want the (H) you give it 
                #one short, (H,W) two shorts (H,W,X) three shorts and (H,W,X,Y) four shorts 

                #Since I only care about the H,W I created a seed of two shorts
                hw = struct.unpack("HH", fcntl.ioctl(tid, termios.TIOCGWINSZ, self.seed))
            except:
                return None
            return hw 
        
        #Check the standard i/o's first
        hw = check_term(sys.stdin) or check_term(sys.stdout) or check_term(sys.stderr)
        
        if hw is None:
            try:
                #Try the controlling terminal
                tid = os.open(os.ctermid(), os.O_RDONLY)
                hw = check_term(tid)
                os.close(tid)    
            except:
                try:
                    #Try the env
                    hw = (os.environ['LINES'], os.environ['COLUMNS'])
                except:
                    #My default local windows size is 80x24 -- good enough for me!
                    #I mean either way this is a pretty last ditch effort case
                    #and hopefully shouldn't happen
                    hw = (24, 80) 

        return hw
