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

"""
The c2Event module defines a class that assists malware
command and control parsing by providing a standard ontology
for the types of events communicated between the implant
and the controller.

NOTE: Considering merging with cyboxVocabs:ActionTypeEnum


EXAMPLE
=======
from c2Event import Event
ev = Event(tcp.addr, moduleName)
...
ev.sender = Event.implant
ev.type = Event.Types.file_transfer
ev.subtype = Event.Types.file_transfer.get
ev.data = ...
chop.tsjson(ev.dict())

or

chop.tsjson(Event(tcp.addr, moduleName, Event.implant, type=Event.Types.file_transfer, subtype=Event.Types.file_transfer.get, data=...).dict())


TYPE ONTOLOGY
=============
keepalive
beacon
file_transfer
    get
    put
proxy
shell
    console
    key_event
filesystem
    copy
    delete
    dir
    enumerate_drives
    mkdir
    move
    rename
    search
    stat
process
    enumerate
    kill
    start
monitor
    clipboard
    keystroke
    screencap
sysinfo
registry
network
    enumerate
    netstat
service
    enumerate
    start
    stop
database
    enumerate
crypto
    negotiate
unknown


RESULTANT JSON
==============
When used as above, the resultant JSON follows this schema (json-schema.org):
{
    "$schema": "http://json-schema.org/draft-04/schema#",
    "title": "c2Event.Event",
    "description": "An Event as observed in a malware command and control session.",
    "type": "object",
    "properties": {
        "ver": {
            "description": "The c2Event.Event schema version to which this event conforms.",
            "type": "string"
        },
        "timestamp": {
            "description": "Occurrence of the event in YYYY-MM-DD HH:MM:SS TZ format.",
            "type": "string"
        },
        "transport": {
            "description": "The network/transport protocol, context for the port values if they exist.  For example: 'tcp', 'udp', 'icmp', etc.",
            "type": "string"
        },
        "src_ip": {
            "description": "Source IP address in dotted decimal format.",
            "type": "string"
        },
        "src_port": {
            "description": "Source TCP/UDP port.",
            "type": integer,
        },
        "dst_ip": {
            "description": "Destination IP address in dotted decimal format.",
            "type": "string"
        }
        "dst_port": {
            "description": "Destination TCP/UDP port.",
            "type": "integer"
        },
        "decoder": {
            "description": "Decoder name.",
            "type": "string"
        },
        "sender": {
            "description": "The side sending this event, either 'implant' or 'controller'.",
            "enum": [ "implant", "controller" ]
        },
        "type": {
            "description": "A categorization of this type, to help with trending and advanced analytics.  See the Event.Types class members."
            "type": "string"
        },
        "data": {
            "description": "(Optional) The [decoded/decrypted] data for this event, if there is any."
            "type": "string"
        },
        "subtype": {
            "description": "(Optional) A subcategorization of this type.  See the Event.Types class members' class members."
            "type": "string"
        },
        "encoding": {
            "description": "(Optional) The encodings that should be used to decode the value of the 'data' member, in order of how to decode.  Used when 'data' would contain binary data.",
            "type": "array",
            "items": { enum: [ "base64", "utf8", "utf-8", "percent", "url", "hex", "zlib" ] }
        },
        "level": {
            "description": "(Optional) The reporting level of this event, similar to syslog-style levels."
            "enum": [ "error", "warning", "summary", "detail", "debug" ]
        },
    }
}

"""

class _Named_type:
    def __init__(self,name):
        self._name = name
    def __repr__(self):
        # evaluatable string representation
        return self._name
    def __str__(self):
        # printable string representation
        return self._name


#####################
# Types with subtypes

class _file_transfer(_Named_type):
    get = "get"
    put = "put"

class _shell(_Named_type):
    console = "console"
    key_event = "key_event"

class _filesystem(_Named_type):
    copy = "copy"
    delete = "delete"
    move = "move"
    rename = "rename"
    dir = "dir"
    enumerate_drives = "enumerate_drives"
    mkdir = "mkdir"
    search = "search"
    stat = "stat"

class _process(_Named_type):
    enumerate = "enumerate"
    kill = "kill"
    start = "start"

class _monitor(_Named_type):
    screencap = "screencap"
    keystroke = "keystroke"
    clipboard = "clipboard"

class _network(_Named_type):
    netstat = "netstat"
    enumerate = "enumerate"

class _service(_Named_type):
    enumerate = "enumerate"
    start = "start"
    stop = "stop"

class _database(_Named_type):
    enumerate = "enumerate"

class _crypto(_Named_type):
    negotiate = "negotiate"


######################
# The main Event class

class Event:
    """The base Event class to be used with chop.tsjson() or chop.json().

    Attributes:
        timestamp
            if not set, will not include "timestamp" in the return of dict(), as
            suitable for use with chop.tsjson().
            If timestamp is set to an integer, assume it is a Seconds Since Epoch
            value.  The return of dict() will then include a 'timestamp'
            attribute whose value is an associated readable string
            (YYYY-MM-DD HH:MM:SS TZ) in UTC.
            If timestamp is set to a string, then the return of dict() will then
            include a 'timestamp' attribute whose value is that string.
         
        other
            a dictionary whose members will be merged into the return of dict()
        """

    _version = "1.1"
    timestamp = None

    def __init__(self, addr=None, decoder=None, sender=None, type='unknown', data=None, subtype=None, encoding=None, other=None):
        self.addr = addr
        self.decoder = decoder
        self.sender = sender
        self.type = type
        self.data = data
        self.subtype = subtype
        self.encoding = encoding
        self.other = other

    def dict(self):
        if not self.addr or not self.decoder or not self.sender:
            return None
        ((sip,sport),(dip,dport)) = self.addr
        r = {'ver': self._version,
             'src_ip' : sip,
             'src_port' : sport,
             'dst_ip' : dip,
             'dst_port' : dport,
             'decoder' : self.decoder,
             'sender' : self.sender,
             'type' : str(self.type)}
        if self.data != None:
            r['data'] = self.data
        if self.subtype != None:
            r['subtype'] = str(self.subtype)
        if self.encoding != None:
            r['encoding'] = self.encoding
        if self.timestamp != None:
            if isinstance(self.timestamp, (str, unicode)):
                r['timestamp'] = self.timestamp
            elif isinstance(self.timestamp, int):
                r['timestamp'] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.timestamp)).rstrip()
        if self.other != None:
            r.update(self.other)
        return r

    class Types:
        keepalive = "keepalive"
        beacon = "beacon"

        file_transfer = _file_transfer("file_transfer")

        proxy = "proxy"

        shell = _shell("shell")

        filesystem = _filesystem("filesystem")

        process = _process("process")

        monitor = _monitor("monitor")

        sysinfo = "sysinfo"
        
        registry = "registry"

        network = _network("network")

        service = _service("service")

        database = _database("database")

        crypto = _crypto("crypto")

        unknown = "unknown"

        """
        NOTE: There are two ways to add a new type.

              The simple way is to define a new member variable
              and set it to a string value.  Use this way when
              the type has no subtypes.

              If the type has subtypes, then both a member
              variable and a new private class must be defined.
              This allows simple auto-complete tools, such as
              python-jedi, to work.

              EXAMPLE:
                  here, add:
                      mytype = _mytype("mytype")
                  in "Types with subtypes" section above, add:
                      class _mytype(_Named_type):
                          subtype1 = "subtype1"
                          subtype2 = "subtype2"
                          etc.
                  in "TYPE ONTOLOGY" section above, add:
                      mytype
                          subtype1
                          subtype2
        """

    class Encodings:
        base64 = "base64"
        # hexadecimal
        hex = "hex"
        utf8 = "utf-8"
        percent = "percent"
        url = "percent"
        zlib = "zlib"

    implant = "implant"
    controller = "controller"

    class Levels:
        error = "error"
        warn = "warning"
        summary = "summary"
        detail = "detail"
        debug = "debug"


if __name__ == '__main__':
    pass
