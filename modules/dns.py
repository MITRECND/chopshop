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

from dnslib import (DNSRecord,
                    QR,
                    OPCODE,
                    RCODE,
                    QTYPE,
                    CLASS,
                    DNSError)

from ChopProtocol import ChopProtocol

moduleName = "dns"
moduleVersion = '0.1'
minimumChopLib = '4.0'


def module_info():
    return "Parse DNS"


def init(module_data):
    module_options = {'proto': [{'udp': 'dns'}]}
    return module_options


def handleDatagram(udp):
    ((src, sport), (dst, dport)) = udp.addr
    if sport != 53 and dport != 53:
        udp.stop()
        return

    try:
        o = DNSRecord.parse(udp.data)
    except KeyError as e:
        chop.prnt("Key error: %s" % str(e))
        return
    except DNSError as e:
        chop.prnt("dnslib error: %s" % str(e))
        return
    except Exception as e:
        chop.prnt("Unexpeced exception: %s" % str(e))
        return

    chopp = ChopProtocol('dns')

    # Create the dictionary...
    f = [o.header.aa and 'AA',
         o.header.tc and 'TC',
         o.header.rd and 'RD',
         o.header.ra and 'RA']

    try:
        d = {'header': {'id': o.header.id,
                        'type': QR[o.header.get_qr()],
                        'opcode': OPCODE[o.header.get_opcode()],
                        'flags': ",".join(filter(None, f)),
                        'rcode': RCODE[o.header.rcode]},
             'questions': o.questions}
    except DNSError as e:
        chop.prnt("dnslib error: %s" % str(e))
        return
    except Exception as e:
        chop.prnt("Unexpeted exception: %s" % str(e))
        return

    if OPCODE[o.header.opcode] == 'UPDATE':
        f1 = 'zo'
        f2 = 'pr'
        f3 = 'up'
        f4 = 'ad'
    else:
        f1 = 'q'
        f2 = 'a'
        f3 = 'ns'
        f4 = 'ar'

    dhdr = d['header']
    dhdr[f1] = o.header.q
    dhdr[f2] = o.header.a
    dhdr[f3] = o.header.auth
    dhdr[f4] = o.header.ar

    d['questions'] = []
    for q in o.questions:
        qname = str(q.get_qname())
        # Strip trailing dot.
        if qname.endswith('.'):
            qname = qname[:-1]

        try:
            dq = {'qname': qname,
                  'qtype': QTYPE[q.qtype],
                  'qclass': CLASS[q.qclass]}
            d['questions'].append(dq)
        except DNSError as e:
            chop.prnt("dnslib error: %s" % str(e))
            return
        except Exception as e:
            chop.prnt("Unexpected exception: %s" % str(e))
            return

    d['rr'] = []
    for r in o.rr:
        rname = str(r.get_rname())
        # Strip trailing dot.
        if rname.endswith('.'):
            rname = rname[:-1]
        rdata = str(r.rdata)
        # Strip trailing dot.
        if rdata.endswith('.'):
            rdata = rdata[:-1]

        try:
            dr = {'rname': rname,
                  'rtype': QTYPE[r.rtype],
                  'rclass': CLASS[r.rclass],
                  'ttl': r.ttl,
                  'rdata': rdata}
            d['rr'].append(dr)
        except DNSError as e:
            chop.prnt("dnslib error: %s" % str(e))
            return
        except Exception as e:
            chop.prnt("Unexpected exception: %s" % str(e))
            return

    if sport == 53:
        chopp.serverData = d
        return chopp
    elif dport == 53:
        chopp.clientData = d
        return chopp

    return None


def shutdown(module_data):
    return
