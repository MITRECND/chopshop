#!/bin/sh

# Copyright (c) 2013 The MITRE Corporation. All rights reserved.
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

if [ $# -ne 2 ]; then
	echo "Usage: $0 <module name> <tcp|udp>"
	exit 1
fi


BASEDIR=$(dirname $0)
MODDIR="${BASEDIR}/modules"
DOCSDIR="${BASEDIR}/docs"

MODNAME=$1
MODFILE="${MODNAME}.py"
DOCNAME="${MODNAME}.txt"
if [ -e "${MODDIR}/${MODFILE}" ]; then
	echo "Module already exists."
	exit 1
fi

shift
TYPE=$1

# Encourage people to write docs by touching
# the docs file for them.
touch "${DOCSDIR}/${DOCNAME}"

if [ ${TYPE} = "tcp" ]; then
	HANDLE='handleStream'
	ARG='tcp'
elif [ ${TYPE} = "udp" ]; then
	HANDLE='handleDatagram'
	ARG='udp'
else
	echo "Usage: $0 <module name> <tcp|udp>"
	exit 1
fi

cat << _EOF >> "${MODDIR}/${MODFILE}" || exit 1
moduleName="${MODNAME}"

def module_info():
    pass

def init(module_data):
    module_options = { 'proto': '${ARG}' }
    return module_options

def ${HANDLE}(${ARG}):
    return

def shutdown(module_data):
    return
_EOF

# TCP gets teardown() and taste(), UDP does not.
if [ ${TYPE} = "tcp" ]; then
cat << _EOF >> "${MODDIR}/${MODFILE}" || exit 1

def taste(${ARG}):
    return False

def teardown(${ARG}):
    return
_EOF
fi

exec ${EDITOR:-vi} "${MODDIR}/${MODFILE}"
