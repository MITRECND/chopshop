#!/usr/bin/env python
#
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
#
#WebServer/WebSocket Code taken from mod_pywebsocket available from
#http://code.google.com/p/pywebsocket/
#That code falls under the following copyright/license:
#
# Copyright 2012, Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import BaseHTTPServer
import CGIHTTPServer
import SimpleHTTPServer
import SocketServer
import ConfigParser
import base64
import httplib
import logging
import logging.handlers
import optparse
import os
import re
import select
import socket
import sys
import threading
import traceback
from threading import Thread, Lock
import Queue
import time
import json
import cgi

from mod_pywebsocket import common
from mod_pywebsocket import dispatch
from mod_pywebsocket import handshake
from mod_pywebsocket import http_header_util
from mod_pywebsocket import memorizingfile
from mod_pywebsocket import util
from mod_pywebsocket import msgutil
from mod_pywebsocket import stream
from mod_pywebsocket import standalone

_DEFAULT_LOG_MAX_BYTES = 1024 * 256
_DEFAULT_LOG_BACKUP_COUNT = 5

_DEFAULT_REQUEST_QUEUE_SIZE = 128
_TRANSFER_DATA_HANDLER_NAME = 'web_socket_transfer_data'

# 1024 is practically large enough to contain WebSocket handshake lines.
_MAX_MEMORIZED_LINES = 1024

from ChopGV import CHOPSHOP_WD
from ChopLib import ChopLib
from ChopConfig import ChopConfig
from ChopException import ChopUiException


class _Options():
    pass

class _ChopQueueTracker(Thread):
    def __init__(self):
        Thread.__init__(self, name = 'QueueTracker')
        self.queues = []
        self.message_queue = None
        self.stopped = False

        self.idlist = {}
        self.idcount = 0

        #Check queue type  
        #Throw exception if queue is not working


    def unset_queue(self):
        self.message_queue = None

    def set_queue(self, message_queue):
        if self.message_queue is not None:
            pass #there is already a message queue register
        self.message_queue = message_queue
    
    def get_new_queue(self):
        new_queue = Queue.Queue() 
        queue_id = len(self.queues)
        self.queues.append(new_queue)
        return (queue_id, new_queue)

    def remove_queue(self, queue_id):
        self.queues.remove(self.queues[queue_id])
        return

    def stop(self):
        self.stopped = True

    def run(self):
        while not self.stopped:
            if self.message_queue is None: #hasn't been set yet
                time.sleep(.2)
                continue

            try:
                message = self.message_queue.get(True, .1)
            except Queue.Empty, e:
                continue             

            
            try:
                #Since this can run choplib multiple times, need to
                #give each module a web unique id to use which won't overlap
                #across instantiations of choplib
                if message['type'] == 'ctrl' and message['data']['msg'] == 'addmod':
                    if message['data']['name'] not in self.idlist: #Hasn't been seen before
                        self.idlist[message['data']['name']] = self.idcount
                        self.idcount += 1
                    else: #It is, must update it
                        message['data']['id'] = int(self.idlist[message['data']['name']])


                if not(message['type'] == 'ctrl'):
                    message['id'] = int(self.idlist[message['module']])

                for qu in self.queues:
                    qu.put(message) 
            except Exception, e:
                raise ChopUiException(e)



class ChopWebUi(Thread):
    def __init__(self):
        Thread.__init__(self, name = 'ChopWebUi')

        self.options = _Options()

        self.options.server_host= ''
        self.options.validation_host = None
        self.options.port = 8080
        self.options.validation_port = None
        self.options.document_root = CHOPSHOP_WD + '/webroot/'
        self.options.request_queue_size = _DEFAULT_REQUEST_QUEUE_SIZE
        self.options.log_level = 'critical'
        self.options.log_file = ''
        self.options.deflate_log_level = 'warn'
        self.options.thread_monitor_interval_in_sec = -1
        self.options.allow_draft75 = False
        self.options.strict = False
        self.options.use_tls = False

        self.stopped = False
        self.message_queue = None
        self.queuetracker = None

    @property
    def server_host(self):
        """Address to listen on"""
        return self.options.server_host

    @server_host.setter
    def server_host(self, v):
        self.options.server_host= v


    @property
    def port(self):
        """Port to listen on"""
        return self.options.port

    @port.setter
    def port(self, v):
        self.options.port = v

    @property
    def document_root(self):
        return self.options.document_root

    @document_root.setter
    def document_root(self,v):
        self.options.document_root= v

    def stop(self):
        self.stopped = True
        self.server.shutdown()
        self.queuetracker.stop()
        self.choplibshell.stop()

    def run(self):
        #Based on mod_pywebsocket/standalone.py main function

        #Start the queue tracker
        self.queuetracker = _ChopQueueTracker()
        self.queuetracker.start()
        self.options.queuetracker = self.queuetracker

        self.choplibshell = _ChopLibShell(self.queuetracker)
        self.choplibshell.start()
        self.options.choplibshell = self.choplibshell

        _configure_logging(self.options)

        os.chdir(self.options.document_root)
        self.options.cgi_directories = []
        self.options.is_executable_method = None
        try:
            if self.options.thread_monitor_interval_in_sec > 0:
                # Run a thread monitor to show the status of server threads for
                # debugging.
                ThreadMonitor(self.options.thread_monitor_interval_in_sec).start()

            self.server = ChopWebSocketServer(self.options)
            self.server.serve_forever()
        except Exception, e:
            logging.critical('mod_pywebsocket: %s' % e)
            logging.critical('mod_pywebsocket: %s' % util.get_stack_trace())

class _ChopDataParser(object):
    def __init__(self, request, queuetracker):
        if queuetracker is None:
            raise Exception

        self.queuetracker = queuetracker
        (self.qid, self.my_queue) = queuetracker.get_new_queue()
        #TODO throw exceptions?

        self.request = request

    def send(self,message):
        self.request.ws_stream.send_message(message, binary = False)

    def go(self):
        while True:
            try:
                message = self.my_queue.get(True, .1)
            except Queue.Empty, e:
                continue

                    

            #TODO more efficient way of sanitization?
            if message['type'] == 'text':
                #message['data']['data'] = base64.urlsafe_b64encode(message['data']['data'])
                message['data']['data'] = message['data']['data'].replace("\"","\\\"")
                message['data']['data'] = message['data']['data'].replace("<","&lt;")
                message['data']['data'] = message['data']['data'].replace(">","&gt;")
                #message['data']['data'] = cgi.escape(message['data']['data'], quote = True)

            try:
                output = json.dumps(message)
            except:
                if message['type'] == 'text':
                    message['data']['data'] = "Parsing Error! -- Received non-character data"
                    output = json.dumps(message)
                else:
                    raise


            self.send(output)

    def cleanup(self):
        if self.qid is not None:
            self.queuetracker.remove_queue(self.qid)

    def __del__(self):
        self.cleanup()
         

class _ChopLibShellLiason(object):
    def __init__(self, request, choplibshell):
        self.request = request
        self.choplibshell = choplibshell
        self.associated = False

    def deassociate(self):
        self.associated = False

    def go(self):
        self.choplibshell.associate(self, self.request) 
        self.associated = True

        while self.associated:
            time.sleep(.1)


    def __del__(self):
        self.choplibshell.deassociate(self, self.request)


class _ChopLibShell(Thread):
    def __init__(self, queuetracker):
        Thread.__init__(self, name = 'ChopLibShell')
        self.request = None 
        self.liason = None
        self.queuetracker = queuetracker

        self.choplib = None
        self.stopped = False


    def associate(self, liason, request):
        if self.liason is not None:
            try:
                self.request = None
                self.liason.deassociate()
            except:
                pass

        self.liason = liason
        self.request = request

    def deassociate(self, liason, request):
        if self.liason == liason:
            self.request = None
            self.liason = None
   
    def _force_deassociate(self):
        if self.liason is not None:
            self.request = None
            self.liason = None

    def stop(self):
        if self.liason is not None:
            try:
                self.liason.deassociate()
            except:
                pass
        self.stopped = True

    def send_message(self, message):
        self.request.ws_stream.send_message(message, binary = False)

    def setup_choplib(self):
        if self.choplib is not None:
            self.destroy_choplib()

        self.choplib = ChopLib()
        self.choplib.text = True

        if self.queuetracker is None:
            raise Exception #queuetracker is managed by the the webui
        self.queuetracker.set_queue(self.choplib.get_message_queue())

    def setup_choplib_from_config(self, chopconfig):
        if self.choplib is not None:
            self.destroy_choplib()

        self.choplib = ChopLib()
        self.choplib.text = True

        if not os.path.exists(chopconfig.filename):
            raise ValueError("Unable to find file '%s'" % chopconfig.filename)
        self.choplib.filename = chopconfig.filename
        self.choplib.base_dir = chopconfig.base_dir
        self.choplib.mod_dir = chopconfig.mod_dir
        self.choplib.ext_dir = chopconfig.ext_dir
        self.choplib.aslist = chopconfig.aslist
        self.choplib.longrun = chopconfig.longrun
        self.choplib.modinfo = chopconfig.modinfo
        self.choplib.GMT = chopconfig.GMT
        self.choplib.bpf = chopconfig.bpf
        self.choplib.modules = chopconfig.modules
        #if chopconfig.savedir:
            #pass
            #chopui.savefiles = True
            #chopui.savedir = chopconfig.savedir
            #self.choplib.savefiles = True

        if self.queuetracker is None:
            raise Exception #queuetracker is managed by the the webui
        self.queuetracker.set_queue(self.choplib.get_message_queue())

    def destroy_choplib(self):
        self.queuetracker.unset_queue()
        if self.choplib is not None:
            self.choplib.stop()
            self.choplib = None

    def reset_choplib(self):
        options = self.choplib.options
        self.destroy_choplib()
        self.setup_choplib()
        self.choplib.options = options

    def run_module_info(self, modules):
        clib = ChopLib()
        clib.text = True
        clib.modules = modules
        clib.modinfo = True
        clib.start()

        stopped = False
        message_queue = clib.get_message_queue()

        while not stopped and clib.is_alive():
            try:
                message = message_queue.get(True, .1)
            except Queue.Empty, e:
                continue

            #clean up messages
            if message['type'] == 'ctrl':
                #self.send_message(message['data']['msg'] )
                if message['data']['msg'] == 'finished':
                    stopped = True
            elif message['type'] == 'text':
                self.send_message(message['data']['data'])

        clib.join()         
        del clib
        
    def help_message(self):
        output = ("Available Commands: \n" +
                "\tnew\n"+
                "\tnew_from_file\n"
                "\tdestroy\n"+
                "\trenew\n"+
                "\tset\n"+
                "\tget\n"+
                "\tlist_params\n" + 
                "\trun\n" +
                "\tstop\n"+ 
                "\tdisconnect\n")
                #"\tshutdown\n")
        return output
    
    def params_message(self):
        params_string = ("Avaiable params: \n" +
                    "\t base_dir \n"  +
                    "\t mod_dir \n" +
                    "\t ext_dir \n" +
                    "\t aslist \n" +
                    "\t longrun \n" +
                    "\t GMT \n" +
                    "\t modules \n" +
                    "\t interface \n" + 
                    "\t filename \n" +
                    "\t bpf \n" +
                    "\t filelist\n" )
        return params_string

    def choplib_get(self, param):
        if param == "all":
            outstring = ""
            for option,value in self.choplib.options.iteritems():
                outstring += option + ": " + str(value) + "\n"

            self.send_message(outstring)
        elif param == "base_dir":
            if self.choplib.base_dir is None:
                self.send_message("base_dir not set")
            else:
                self.send_message(self.choplib.base_dir)
        elif param == "mod_dir":
            self.send_message(self.choplib.mod_dir)
        elif param == "ext_dir":
            self.send_message(self.choplib.ext_dir)
        elif param == "aslist":
            self.send_message(str(self.choplib.aslist))
        elif param == "longrun":
            self.send_message(str(self.choplib.longrun))
        elif param == "GMT":
            self.send_message(str(self.choplib.GMT))
        elif param == "modules":
            self.send_message(self.choplib.modules)
        elif param == "interface":
            self.send_message(self.choplib.interface)
        elif param == "filename":
            self.send_message(self.choplib.filename)
        elif param == "bpf":
            if self.choplib.bpf is not None:
                self.send_message(self.choplib.bpf)
            else:
                self.send_message("bpf not set")
        elif param == "filelist":
            if not self.choplib.filelist:
                self.send_message("filelist not set")
            else:
                outstring = "["
                for f in self.choplib.filelist:
                    outstring += (f + ",")
                outstring = outstring[0:-1] + "]"
                self.send_message(outstring)
        
        
        else:
            self.send_message("Unknown Parameter")


    def choplib_set(self, param, value):
        error = False

        if param == "base_dir":
            self.choplib.base_dir = value
        elif param == "mod_dir":
            self.choplib.mod_dir = value
        elif param == "ext_dir":
            self.choplib.ext_dir = value
        elif param == "aslist":
            bval = False
            if value == 'True':
                bval = True

            self.choplib.aslist = bval
        elif param == "longrun":
            bval = False
            if value == 'True':
                bval = True

            self.choplib.longrun = bval
        elif param == "GMT":
            bval = False
            if value == 'True':
                bval = True
            self.choplib.GMT = bval
        elif param == "modules":
            self.choplib.modules = value
        elif param == "interface":
            self.choplib.interface = value
        elif param == "filename":
            self.choplib.filename = value
        elif param == "bpf":
            self.choplib.bpf = value
        elif param == "filelist":
            self.send_message("TBD")
        else:
            error = True
            self.send_message("Unknown Parameter")

        self.send_message('ok')

    def process_message(self, line):
        line = line.encode('ascii', 'ignore')

        #self.send_message("Echo: " + line)
        commands = line.split(' ', 1)
        if commands[0] == 'new':
            self.setup_choplib()
            self.send_message("Created new choplib instance")
        elif commands[0] == 'new_from_file':
            try:
                config = ChopConfig()
                config.parse_config(commands[1])
                self.setup_choplib_from_config(config)
                self.send_message("Created new choplib instance from %s" % commands[1])
            except Exception, e:
                traceback.print_exc()
                self.send_message("Unable to create choplib instance: %s" % e)
        elif commands[0] == 'destroy':
            self.destroy_choplib()
            self.send_message("Destroyed choplib instance") 
        elif commands[0] == 'renew':
            self.reset_choplib()
            self.send_message("Renewed choplib instance") 
        elif commands[0] == 'set':
            if self.choplib is None:
                self.send_message("Please run 'new' first")
            elif len(commands) < 2:
                self.send_message("set requires a parameter and value")
            else:
                params,value = commands[1].split(' ', 1)
                self.choplib_set(params, value)
        elif commands[0] == 'get':
            if self.choplib is None:
                self.send_message("Please 'new' first")
            elif len(commands) < 2:
                self.send_message("get requires parameter")
            else:
                self.choplib_get(commands[1])
        elif commands[0] == 'list_params':
            self.send_message(self.params_message())


        elif commands[0] == 'module_info':
            if(len(commands) < 2):
                self.send_message("module_info requires a module string")
            else:
                self.run_module_info(commands[1])
        elif commands[0] == 'run':
            if self.choplib is None:
                self.send_message("Must run 'new' first")
            else:
                try:
                    self.choplib.start()
                except RuntimeError, e:
                    self.send_message("Must 'renew' to run again")
        elif commands[0] == 'stop':
            if self.choplib is not None:
                self.choplib.stop()
                #self.choplib = None
        elif commands[0] == 'disconnect':
            self.liason.deassociate()
            self._force_deassociate()
        #elif commands[0] == 'shutdown':
        #    pass
        #    #TBD
        elif commands[0] == 'help':
            self.send_message(self.help_message())
        else:
                self.send_message("Unknown Command: " + commands[0])

    def run(self):
        while not self.stopped:
            if self.request is None:
                time.sleep(.1)
                continue

            self.request.ws_stream.send_message("Shell Connected", binary = False) 
            while (self.request is not None) and (not self.stopped):
                try:
                    line = self.request.ws_stream.receive_message()

                    if line is None:
                        continue

                    self.process_message(line)

                except:
                    #Something broke -- need to deassociate
                    liason = self.liason
                    request = self.request
                    self.liason.deassociate()
                    self.deassociate(liason, request)                    
                    break


class _HandshakeDispatcher(object):
    def do_extra_handshake(self, request):
        pass


class ChopWebSocketServer(standalone.WebSocketServer):
    def __init__(self, options):
        options.dispatcher = _HandshakeDispatcher()

        self._logger = util.get_class_logger(self)

        self.request_queue_size = options.request_queue_size
        self._WebSocketServer__ws_is_shut_down = threading.Event()
        self._WebSocketServer__ws_serving = False

        SocketServer.BaseServer.__init__(
            self, (options.server_host, options.port), ChopWebSocketRequestHandler)

        # Expose the options object to allow handler objects access it. We name
        # it with websocket_ prefix to avoid conflict.
        self.websocket_server_options = options

        self._create_sockets()
        self.server_bind()
        self.server_activate()


class ChopWebSocketRequestHandler(standalone.WebSocketRequestHandler):
    def parse_request(self):
        """Override BaseHTTPServer.BaseHTTPRequestHandler.parse_request.

        Return True to continue processing for HTTP(S), False otherwise.

        See BaseHTTPRequestHandler.handle_one_request method which calls
        this method to understand how the return value will be handled.
        """

        # We hook parse_request method, but also call the original
        # CGIHTTPRequestHandler.parse_request since when we return False,
        # CGIHTTPRequestHandler.handle_one_request continues processing and
        # it needs variables set by CGIHTTPRequestHandler.parse_request.
        #
        # Variables set by this method will be also used by WebSocket request
        # handling (self.path, self.command, self.requestline, etc. See also
        # how _StandaloneRequest's members are implemented using these
        # attributes).
        if not CGIHTTPServer.CGIHTTPRequestHandler.parse_request(self):
            return False

        host, port, resource = http_header_util.parse_uri(self.path)
        if resource is None:
            self._logger.info('Invalid URI: %r', self.path)
            self._logger.info('Fallback to CGIHTTPRequestHandler')
            return True
        server_options = self.server.websocket_server_options
        if host is not None:
            validation_host = server_options.validation_host
            if validation_host is not None and host != validation_host:
                self._logger.info('Invalid host: %r (expected: %r)',
                                  host,
                                  validation_host)
                self._logger.info('Fallback to CGIHTTPRequestHandler')
                return True
        if port is not None:
            validation_port = server_options.validation_port
            if validation_port is not None and port != validation_port:
                self._logger.info('Invalid port: %r (expected: %r)',
                                  port,
                                  validation_port)
                self._logger.info('Fallback to CGIHTTPRequestHandler')
                return True
        self.path = resource

        request = standalone._StandaloneRequest(self, self._options.use_tls)

        try:
            # Fallback to default http handler for request paths for which
            # we don't have request handlers.
            #TODO fill in path determination for static files and this
            #if not self._options.dispatcher.get_handler_suite(self.path):
            self._logger.debug("Path : %r", self.path)
            if self.path != "/data" and self.path != "/shell":
                return True
        except dispatch.DispatchException, e:
            self._logger.info('%s', e)
            self.send_error(e.status)
            return False

        # If any Exceptions without except clause setup (including
        # DispatchException) is raised below this point, it will be caught
        # and logged by WebSocketServer.

        try:
            try:
                handshake.do_handshake(
                    request,
                    self._options.dispatcher, #This should now be custom dispatcher
                    allowDraft75=self._options.allow_draft75,
                    strict=self._options.strict)
            except handshake.VersionException, e:
                self._logger.info('%s', e)
                self.send_response(common.HTTP_STATUS_BAD_REQUEST)
                self.send_header(common.SEC_WEBSOCKET_VERSION_HEADER,
                                 e.supported_versions)
                self.end_headers()
                return False
            except handshake.HandshakeException, e:
                # Handshake for ws(s) failed.
                self._logger.info('%s', e)
                self.send_error(e.status)
                return False

                
            try:
                if self.path == "/data":
                    dataparser = _ChopDataParser(request, server_options.queuetracker)
                    dataparser.go()

                elif self.path == "/shell":
                    #request.ws_stream.send_message("Welcome", binary=False)
                    shell = _ChopLibShellLiason(request, server_options.choplibshell)
                    shell.go()

                if not request.server_terminated:
                    request.ws_stream.close_connection()
            # Catch non-critical exceptions the handler didn't handle.
            except handshake.AbortedByUserException, e:
                self._logger.debug('%s', e)
                raise
            except msgutil.BadOperationException, e:
                self._logger.debug('%s', e)
                request.ws_stream.close_connection(common.STATUS_ABNORMAL_CLOSURE)
            except msgutil.InvalidFrameException, e:
                # InvalidFrameException must be caught before
                # ConnectionTerminatedException that catches InvalidFrameException.
                self._logger.debug('%s', e)
                request.ws_stream.close_connection(common.STATUS_PROTOCOL_ERROR)
            except msgutil.UnsupportedFrameException, e:
                self._logger.debug('%s', e)
                request.ws_stream.close_connection(common.STATUS_UNSUPPORTED_DATA)
            except stream.InvalidUTF8Exception, e:
                self._logger.debug('%s', e)
                request.ws_stream.close_connection(
                    common.STATUS_INVALID_FRAME_PAYLOAD_DATA)
            except msgutil.ConnectionTerminatedException, e:
                self._logger.debug('%s', e)
            except Exception, e:
                util.prepend_message_to_exception(
                    '%s raised exception for %s: ' % (
                        _TRANSFER_DATA_HANDLER_NAME, request.ws_resource),
                    e)
                raise

        except handshake.AbortedByUserException, e:
            self._logger.info('%s', e)
        return False



def _get_logger_from_class(c):
    return logging.getLogger('%s.%s' % (c.__module__, c.__name__))


def _configure_logging(options):
    logging.addLevelName(common.LOGLEVEL_FINE, 'FINE')

    logger = logging.getLogger()
    logger.setLevel(logging.getLevelName(options.log_level.upper()))
    if options.log_file:
        handler = logging.handlers.RotatingFileHandler(
                options.log_file, 'a', options.log_max, options.log_count)
    else:
        handler = logging.StreamHandler()
    formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    deflate_log_level_name = logging.getLevelName(
        options.deflate_log_level.upper())
    _get_logger_from_class(util._Deflater).setLevel(
        deflate_log_level_name)
    _get_logger_from_class(util._Inflater).setLevel(
        deflate_log_level_name)


class ThreadMonitor(threading.Thread):
    daemon = True

    def __init__(self, interval_in_sec):
        threading.Thread.__init__(self, name='ThreadMonitor')

        self._logger = util.get_class_logger(self)

        self._interval_in_sec = interval_in_sec

    def run(self):
        while True:
            thread_name_list = []
            for thread in threading.enumerate():
                thread_name_list.append(thread.name)
            self._logger.info(
                "%d active threads: %s",
                threading.active_count(),
                ', '.join(thread_name_list))
            time.sleep(self._interval_in_sec)


# vi:sts=4 sw=4 et
