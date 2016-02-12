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

"""
Grammar for module processing pipelines in ChopShop

Chains = Chain [SEMICOLON Chain]*
Chain = [Invocation | Tee] [PIPE [Invocation | Tee]]*
Invocation = STRING [OPTION [QUOTED | STRING]?]* [QUOTED | STRING]?
Tee = BTEE Chain [COMMA Chain]+ ETEE
"""

from cStringIO import StringIO
import re


class __ChopModule__(object):

    def __init__(self, mstr):
        self.children = []
        self.parents = []
        self.name = mstr
        self.arguments = []
        self.legacy = False
        self.inputs = {}
        self.outputs = []

    def __repr__(self):
        return "%s@%x" % (self.name, id(self))


def make_token(name):
    return lambda scanner, token: (name, token)


class ChopGrammar(object):

    # TODO: Add support for escaped sequences?
    scanner = re.Scanner([
        (r'"((?:[^\t\n\r\f\v"])*)"', make_token("QUOTED")),
        (r"'((?:[^\t\n\r\f\v'])*)'", make_token("QUOTED")),
        (r"[ ]", make_token("SPACE")),
        (r"\;", make_token("SEMICOLON")),
        (r"\(", make_token("BTEE")),
        (r"\)", make_token("ETEE")),
        (r"\|", make_token("PIPE")),
        (r"\,", make_token("COMMA")),
        (r"[^\t\n\r\f\v'\";()|,-][^ \t\n\r\f\v'\";()|,]*",
         make_token("STRING")),
        (r"--[a-zA-Z0-9_-]+", make_token("OPTION")),
        (r"-[a-zA-Z0-9]+", make_token("OPTION")),
        (r"-", make_token("STRING")),
    ])

    def __init__(self):
        self.top_modules = []
        self.all_modules = []
        self.strbuff = None

    def parseGrammar(self, grammar_string):
        results, remainder = self.scanner.scan(grammar_string)

        if remainder:
            raise ValueError("Invalid trailing characters: %s" % remainder)

        nresults = []
        for token in results:
            if token[0] != "SPACE":
                nresults.append(token)
        results = nresults

        self.verify_chains(results)

        return self.all_modules

    def find_tee_end(self, chain, left):
        btee_stack = [True]
        # Assume left is the position of BTEE
        right = left + 1
        while right < len(chain):
            if chain[right][0] == "BTEE":
                btee_stack.append(True)
            elif chain[right][0] == "ETEE":
                if not len(btee_stack):  # there's no cooresponding BTEE
                    raise Exception("Unexpected End Tee token ')'")
                if len(btee_stack) == 1:  # this is the ETEE we're looking for
                    return right
                btee_stack.pop()
            right += 1
        raise Exception("Unable to find end of Tee")

    def verify_chains(self, chains):
        left = 0
        right = 0
        flows = []

        # get chain
        # pdb.set_trace()
        while right < len(chains):
            while right < len(chains) and chains[right][0] != "SEMICOLON":
                right += 1
            chain = chains[left:right]
            right += 1
            left = right
            (ancestors, children) = self.verify_chain(chain)
            flows.extend(ancestors)

        self.top_modules = flows
        return True

    def verify_chain(self, chain):
        left = 0
        right = 0

        ancestors = []
        parents = []

        # get chain
        while right < len(chain):
            while right < len(chain) and (chain[right][0] != "PIPE" and chain[right][0] != "BTEE"):
                right += 1

            if right >= len(chain) or chain[right][0] == "PIPE":  # Assume Invocation
                invocation = chain[left:right]
                mod = self.verify_invocation(invocation)
                if len(parents) == 0:
                    parents.append(mod)
                    ancestors.append(mod)
                else:
                    for parent in parents:
                        parent.children.append(mod)
                        mod.parents.append(parent)
                    parents = [mod]

            elif chain[right][0] == "BTEE":  # Must find end of TEE
                if left != right:
                    raise Exception("Unexpected Tee")
                # left = right
                right = self.find_tee_end(chain, left)
                tee = chain[left + 1: right]  # Remove the TEE elements

                if (right + 1) < len(chain):  # There's more tokens after the end of the tee
                    if chain[right + 1][0] != "PIPE":
                        raise Exception('Unexpected token after TEE: ' + chain[right + 1][0])
                    else:
                        right += 1
                (tparents, tchildren) = self.verify_tee(tee)
                if len(parents) == 0:
                    parents = tchildren
                    ancestors = tparents
                else:
                    for parent in parents:
                        for tparent in tparents:
                            parent.children.append(tparent)
                            tparent.parents.append(parent)
                    parents = tchildren

            right += 1
            left = right

        return (ancestors, parents)

    def verify_tee(self, tee):
        left = 0
        right = 0
        comma = False

        parents = []
        children = []

        while right < len(tee):
            while right < len(tee) and (tee[right][0] != "COMMA" and tee[right][0] != "BTEE"):
                right += 1

            if right >= len(tee) or tee[right][0] == "COMMA":  # Element of TEE, i.e., a chain
                if right < len(tee) and tee[right][0] == 'COMMA':
                    comma = True
                chain = tee[left:right]
                (cparents, cchildren) = self.verify_chain(chain)
                for cparent in cparents:
                    parents.append(cparent)
                for cchild in cchildren:
                    children.append(cchild)

            elif tee[right][0] == "BTEE":  # TEE in the Chain, need to skip it to find the comma
                right = self.find_tee_end(tee, right)
                continue

            right += 1
            left = right

        if not comma:
            raise Exception('Usage of a Tee requires at least two elements')

        return (parents, children)

    def verify_invocation(self, invocation):
        right = 1
        if invocation[0][0] != "STRING":
            raise Exception("Invocation must begin with a 'STRING' token, not a %s token" % invocation[0][0])

        mymod = __ChopModule__(invocation[0][1].rstrip())

        while right < len(invocation):
            if invocation[right][0] == "OPTION":
                mymod.arguments.append(invocation[right][1].rstrip())
                if (right + 1) < len(invocation):  # Check if the next element is the argument to the option
                    if invocation[right + 1][0] == "QUOTED":
                        # Need to strip the quotes
                        mymod.arguments.append(invocation[right + 1][1].rstrip()[1:-1])
                        right += 1  # skip the parameter
                    elif invocation[right + 1][0] == "STRING":
                        mymod.arguments.append(invocation[right + 1][1].rstrip())
                        right += 1  # skip the parameter
                    # If not, just skip it and let it be parsed out
            elif invocation[right][0] == "QUOTED":
                if (right + 1) < len(invocation):
                    raise Exception("QUOTED token must be last element of invocation or following a OPTION token")
                # Need to remove the quotes from the quoted string
                mymod.arguments.append(invocation[right][1].rstrip()[1:-1])
            elif invocation[right][0] == "STRING":
                if (right + 1) < len(invocation):
                    raise Exception("STRING token must be last element of invocation or following a OPTION token")
                mymod.arguments.append(invocation[right][1].rstrip())
            else:
                raise Exception("Unexpected %s token %s" % (invocation[right][0], invocation[right][1]))
            right += 1

        self.all_modules.append(mymod)
        return mymod

    def get_family_(self, top, tabs=0):
        for _ in range(0, tabs):
            self.strbuff.write("\t")

        self.strbuff.write("%s -->\n" % top.name)

        if len(top.children):
            for child in top.children:
                self.get_family_(child, tabs + 1)

    def get_family(self, top):
        if self.strbuff is not None:
            self.strbuff.close()

        self.strbuff = StringIO()
        self.get_family_(top)
        output = self.strbuff.getvalue()
        self.strbuff.close()
        return output

    def get_tree(self):
        output = ""
        for mod in self.top_modules:
            output += self.get_family(mod) + "\n"
        return output

    def print_family(self, top, tabs=0):
        for _ in range(0, tabs):
            print "\t",

        print top.name, "-->"

        if len(top.children):
            for child in top.children:
                self.print_family(child, tabs + 1)

    def print_tree(self):
        for mod in self.top_modules:
            self.print_family(mod)
