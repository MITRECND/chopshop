moduleName="TCPlot"

byte_arrs={}
tstmp_arrs={}
suffixer = 1

import sys
import struct
import time
import datetime
import math
import numpy as np
import matplotlib.pyplot as plt
import pickle
from optparse import OptionParser

def parse_args(module_data):
    parser = OptionParser()

    parser.add_option("-d", "--dump", action="store_true",
        dest="dump", default=False, help="Dump traffic summary to text file")
    parser.add_option("-o", "--output", action="store_true",
        dest="output", default=False, help="Print traffic to stdout")
    parser.add_option("-u", "--unified", action="store_true",
        dest="unified", default=False, help="Create a pickled pyplot representing the traffic data as one series")
    parser.add_option("-c", "--comparison", action="store_true",
        dest="comparison", default=False, help="Create a pickled pyplot representing the traffic data in distinct series for client and server.")
    parser.add_option("-n", "--nolines", action="store_true",
        dest="nolines", default=False, help="When creating plots, do not use lines")
    parser.add_option("-l", "--hyphenlines", action="store_true",
        dest="dashedlines", default=False, help="When creating plots, use dashes for lines")
    parser.add_option("-a", "--absolute", action="store_true",
        dest="absolute", default=False, help="When creating comparison plot,represent both client and server using positive byte counts")
        
    (opts,lo) = parser.parse_args(module_data['args'])

    module_data['dump'] = opts.dump
    module_data['output'] = opts.output
    module_data['unified'] = opts.unified
    module_data['comparison'] = opts.comparison
    module_data['absolute'] = opts.absolute
    module_data['nolines'] = opts.nolines
    module_data['dashedlines'] = opts.dashedlines and not module_data['nolines']
    module_data['plot'] = module_data['unified'] or module_data['comparison']

def init(module_data):
    module_options = {'proto':'tcp'}
    parse_args(module_data)
    return module_options
    
def module_info():
    print "Parse input into scatter plots of TCP traffic, separated by stream."

def handleStream(tcp):
    if tcp.server.count_new > 0:
        count = tcp.server.count_new
        from_client = True
        color = "RED"
    else:
        count = tcp.client.count_new
        from_client = False
        color = "GREEN"
        
    if not tcp.stream_data['start']:
        tcp.stream_data['start'] = datetime.datetime.utcfromtimestamp(tcp.timestamp)
    time_since_start = datetime.datetime.utcfromtimestamp(tcp.timestamp) - tcp.stream_data['start']
    
    if tcp.module_data['dump']: # dump info to text file
        path = tcp.module_data['file']
        if not path:
            path = tcp.stream_data['file']
        chop.appendfile("%s.txt" % path, "(%s%i, %.9f)\n" % ("" if from_client else "-", count, time_since_start.total_seconds()))
    elif tcp.module_data["output"]: # dump to stdout or gui out
        chop.prettyprnt(color, "(%i, %.9f)" % (count, time_since_start.total_seconds()))
    elif tcp.module_data['plot']: # create plot
        byte_arrs[tcp.stream_data['file']].append(count if from_client else -count)
        tstmp_arrs[tcp.stream_data['file']].append(time_since_start.total_seconds())
    pass

def taste(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    stream_name = "%s_to_%s_%i" % (src, dst, len(byte_arrs))
    byte_arrs[stream_name] = []
    tstmp_arrs[stream_name] = []
    tcp.stream_data['file'] = stream_name
    tcp.stream_data['start'] = ''
    return True

def shutdown(module_data):
    if module_data['plot']:
        for key in byte_arrs:
            if module_data['unified']:
                dump_unified(key, module_data)
            if module_data['comparison']:
                dump_comparison(key, module_data)
    return
    
def dump_unified(key, module_data):
    tstmps = tstmp_arrs.get(key)
    byte_arr = byte_arrs.get(key)
            
    x = np.linspace(0, tstmps[len(tstmps) - 1])

    ax = plt.subplot(111)
    plt.plot(tstmps, byte_arr, get_linestyle(True, module_data['nolines'], module_data['dashedlines']))
    plt.ylabel("Bytes Sent (- = from server, + = from client)")
    plt.xlabel("Seconds Elapsed")
    plt.grid(True)
    pickle.dump(ax, file("%s_unified.pickle" % key, 'w'))
    plt.clf()
    
def dump_comparison(key, module_data):
    tstmps = tstmp_arrs.get(key)
    byte_arr = byte_arrs.get(key)
    
    client_byte_arr = []
    client_tsmpt_arr = []
    server_byte_arr = []
    server_tsmpt_arr = []
    for (counter, item) in enumerate(byte_arr):
        if item > 0:
            client_byte_arr.append(item)
            client_tsmpt_arr.append(tstmps[counter])
        else:
            server_byte_arr.append(abs(item) if module_data['absolute'] else item)
            server_tsmpt_arr.append(tstmps[counter])
            
    x = np.linspace(0, tstmps[len(tstmps) - 1])

    ax = plt.subplot(111)
    plt.plot(client_tsmpt_arr, client_byte_arr, get_linestyle(True, module_data['nolines'], module_data['dashedlines']), label="Client")
    plt.plot(server_tsmpt_arr, server_byte_arr, get_linestyle(False, module_data['nolines'], module_data['dashedlines']), label="Server")
    ax.legend()
    plt.ylabel("Bytes Sent = abs(y)")
    plt.xlabel("Seconds Elapsed")
    plt.grid(True)
    
    pickle.dump(ax, file("%s_comparison.pickle" % key, 'w'))
    plt.clf()
    
def get_linestyle(primary, nolines, dashlines):
    return "%s%s%s" % ("--" if dashlines else "", "g" if primary else "r", "o" if nolines or dashlines else "")

def teardown(tcp):
    return

def load_plot(file_path):
    """
    Load the pickled plot at the given path. Example of how to open pickle files created by this module
    """
    ax = pickle.load(file(file_path))
    plt.show()