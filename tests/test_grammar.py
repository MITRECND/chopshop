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

"""
Tests for ChopGrammar.py
"""

import os
import sys

# TODO: Remove this once ChopShop is a proper package.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                "shop"))

import ChopGrammar as grammar


def _make_grammar(string):
    return grammar.ChopGrammar().parseGrammar(string)


def test_basic():
    """Test a single module"""
    modules = _make_grammar("payloads")
    assert len(modules) == 1

    assert modules[0].name == "payloads"
    assert not modules[0].parents
    assert not modules[0].children


def test_two_chains():
    """Test two modules in parallel"""
    modules = _make_grammar("payloads; gh0st_decode")
    assert len(modules) == 2
    payloads, ghost = modules

    assert payloads.name == "payloads"
    assert ghost.name == "gh0st_decode"

    assert not payloads.parents
    assert not payloads.children
    assert not ghost.parents
    assert not ghost.children


def test_pipeline():
    """Test a basic parent/child relationship"""
    modules = _make_grammar("http | http_extractor")
    assert len(modules) == 2

    http, extractor = modules
    assert http.name == "http"
    assert extractor.name == "http_extractor"
    assert http.children == [extractor]
    assert extractor.parents == [http]

    assert not http.parents
    assert not extractor.children


def test_tee():
    """Test the "tee" functionality"""
    modules = _make_grammar("(dns, icmp) | malware_detector")
    assert len(modules) == 3

    dns, icmp, malware = modules
    assert dns.name == "dns"
    assert icmp.name == "icmp"
    assert malware.name == "malware_detector"

    assert dns.children == [malware]
    assert icmp.children == [malware]
    assert malware.parents == [dns, icmp]

    assert not dns.parents
    assert not icmp.parents
    assert not malware.children

# TODO: Test that invalid input generates the expected exceptions.
