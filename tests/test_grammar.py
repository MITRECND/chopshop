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


def _check_exception(grammar, exception_message, exception_class=Exception):
    """Verify that trying to parse a certain grammar gives the expected error.

    Args:
        grammar (str): the module list expression
        exception_message (str): for generic exceptions, the exact text of the
            Exception that is expected.
        exception_class (type): a specific type of Exception to catch.
            Default: Exception
    """
    with pytest.raises(exception_class) as excinfo:
        _make_grammar(grammar)
    assert str(excinfo.value) == exception_message


def _test_option_parsing(grammar, expected_arguments):
    """Test that arguments to a module are parsed in the expected way"""
    modules = _make_grammar(grammar)
    assert len(modules) == 1
    assert modules[0].arguments == expected_arguments


def test_repr():
    """Test the __repr__ function"""
    modules = _make_grammar("blah")
    assert repr(modules[0]).startswith("blah")

# Examples from the documentation

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

# TEE tests

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


def test_tee_on_both_sides_of_pipe():
    """Test a pipeline with both input and output tees."""
    modules = _make_grammar("(a, b) | (c, d)")
    assert len(modules) == 4
    a, b, c, d = modules

    assert a.children == b.children == [c, d]
    assert c.parents == d.parents == [a, b]

# Test option parsing

def test_option_without_value():
    """Test a module with a single flag-style option"""
    _test_option_parsing("a -v", ['-v'])


def test_option_with_long_name():
    """Test a module with a single flag-style option, using the long name"""
    _test_option_parsing("a --verbose", ['--verbose'])


def test_option_with_value():
    """Test a module with a single parameter-style option"""
    _test_option_parsing("a -c 5", ['-c', '5'])


def test_option_with_quoted_value():
    """Test a module with a single parameter-style option in quotes"""
    _test_option_parsing("a -n 'a value'", ['-n', 'a value'])


def test_module_argument():
    """Test a module with a single argument"""
    _test_option_parsing("a foo", ['foo'])


def test_quoted_argument():
    """Test a module with a single quoted argument"""
    _test_option_parsing("a 'foo'", ['foo'])


def test_single_hyphen_argument():
    """A single dash can come after flag options"""
    _test_option_parsing("a -v -", ['-v', '-'])


def test_single_hyphen_parameter_argument():
    """A single dash can come after parameter options"""
    _test_option_parsing("a -c 5 -", ['-c', '5', '-'])

# Test various error parsing situations

def test_trailing_characters():
    """Test that invalid trailing characters raise an error"""
    _check_exception("a '", "Invalid trailing characters: '", ValueError)


def test_unexpected_tee_end():
    """Test that ETEE cannot occur without prior BTEE"""
    _check_exception("a)", "Unexpected ETEE token )")


def test_unterminated_tee():
    """Test that ETEE cannot occur without prior BTEE"""
    _check_exception("(a", "Unable to find end of Tee")


def test_tee_cannot_take_place_of_options():
    """A TEE must start at the beginning of a CHAIN or after a PIPE"""
    _check_exception("a (b, c)", "Unexpected Tee")


def test_tee_requires_two_elements():
    """Each TEE must contain at least two items"""
    _check_exception("(a)", "Usage of a Tee requires at least two elements")


def test_string_cannot_follow_tee():
    """A TEE cannot be directly followed by a STRING."""
    _check_exception("(a, b) c", "Unexpected token after TEE: STRING")


def test_tee_cannot_follow_tee():
    """A TEE cannot be directly followed by another TEE."""
    _check_exception("(a, b) (c, d)", "Unexpected token after TEE: BTEE")


def test_cannot_start_with_option():
    """An OPTION token cannot be the first token."""
    _check_exception("-a 1",
                     "Invocation must begin with a 'STRING' token, not a "
                     "OPTION token")


def test_nonoption_string_token_must_be_last():
    _check_exception("a foo bar",
                     "STRING token must be last element of invocation or "
                     "following a OPTION token")


def test_nonoption_quoted_token_must_be_last():
    _check_exception("a 'foo' bar",
                     "QUOTED token must be last element of invocation or "
                     "following a OPTION token")


# TODO These should raise a better error
def test_pipe_cannot_be_first_token():
    _check_exception("| a", "list index out of range", IndexError)


# TODO This should probably raise an error rather than silently ignoring the
# trailing pipe
def test_pipe_as_last_character():
    modules = _make_grammar("a |")
    assert len(modules) == 1
    assert not modules[0].parents
    assert not modules[0].children
