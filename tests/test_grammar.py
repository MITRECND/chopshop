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

import pytest

# TODO: Remove this once ChopShop is a proper package.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                "shop"))

import ChopGrammar as grammar


def _make_grammar(string):
    return grammar.ChopGrammar().parseGrammar(string)


def test_repr():
    """Test the __repr__ function"""
    modules = _make_grammar("blah")
    assert repr(modules[0]).startswith("blah")


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


def test_tee_with_three_elements():
    modules = _make_grammar("(a, b, c)")
    assert len(modules) == 3
    a, b, c = modules

    assert not a.parents
    assert not a.children
    assert not b.parents
    assert not b.children
    assert not c.parents
    assert not c.children


def test_nested_tees():
    """This is functionally the same as the above grammar"""
    modules = _make_grammar("((a, b), c)")
    assert len(modules) == 3
    a, b, c = modules

    assert not a.parents
    assert not a.children
    assert not b.parents
    assert not b.children
    assert not c.parents
    assert not c.children


def test_pipeline_in_tee():
    """Test parents and children in pipelines inside tees"""
    modules = _make_grammar("a | (b | c, d) | e")
    assert len(modules) == 5
    a, b, c, d, e = modules

    assert a.children == [b, d]
    assert b.children == [c]
    assert c.children == [e]
    assert d.children == [e]
    assert not e.children

    assert not a.parents
    assert b.parents == [a]
    assert c.parents == [b]
    assert d.parents == [a]
    assert e.parents == [c, d]


def test_trailing_characters():
    """Test that invalid trailing characters raise an error"""
    with pytest.raises(ValueError) as excinfo:
        _make_grammar("a '")
    assert "Invalid trailing characters" in str(excinfo.value)


def test_trailing_characters():
    """Test that invalid trailing characters raise an error"""
    with pytest.raises(ValueError) as excinfo:
        _make_grammar("a '")
    assert "Invalid trailing characters" in str(excinfo.value)


def test_unexpected_tee_end():
    """Test that ETEE cannot occur without prior BTEE"""
    with pytest.raises(Exception) as excinfo:
        _make_grammar("a)")
    assert str(excinfo.value) == "Unexpected ETEE token )"


def test_unterminated_tee():
    """Test that ETEE cannot occur without prior BTEE"""
    with pytest.raises(Exception) as excinfo:
        _make_grammar("(a")
    assert str(excinfo.value) == "Unable to find end of Tee"


def test_tee_cannot_take_place_of_options():
    """A tee cannot begin except at the beginning of a chain or after a PIPE"""
    with pytest.raises(Exception) as excinfo:
        _make_grammar("a (b, c)")
    assert str(excinfo.value) == "Unexpected Tee"


def test_tee_requires_two_elements():
    """Each Tee must contain at least two items"""
    with pytest.raises(Exception) as excinfo:
        _make_grammar("(a)")
    assert str(excinfo.value) == "Usage of a Tee requires at least two elements"


def test_nonterminal_tee_must_be_followed_by_pipe():
    """If a TEE is not the last step, it must be followed by a PIPE"""
    with pytest.raises(Exception) as excinfo:
        _make_grammar("(a, b) c")
    assert str(excinfo.value) == "Unexpected token after TEE: STRING"

    with pytest.raises(Exception) as excinfo:
        _make_grammar("(a, b) (c, d)")
    assert str(excinfo.value) == "Unexpected token after TEE: BTEE"
