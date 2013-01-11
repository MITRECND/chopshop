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

SHELL=	/bin/sh
SED=	/usr/bin/sed
SED_ARGS=	-i '' -Ee
INSTALL=	/usr/bin/install
INSTALLDATA=	/usr/bin/install -m 644

VERSION=	3.0-BETA
RELEASE_NAME=	chopshop-${VERSION}
RELEASE_DIR=	release
RELEASE_FILE=	${RELEASE_DIR}/${RELEASE_NAME}.tbz2

# Define this if you want to install into your home directory.
# make install PREFIX=/home/wshields
PREFIX?=	/usr/local

# These can be defined if defaults are not good enough for you.
OWNER?=		$(shell id -u)
GROUP?=		$(shell id -g)

# Install chopshop binaries and supporting libraries here.
BINDIR=		${PREFIX}/bin
LIBEXECDIR=	${PREFIX}/libexec/chopshop

# Install modules and external libraries here.
SHOPDIR=	${LIBEXECDIR}/shop
MOD_DIR=	${LIBEXECDIR}/modules
EXT_LIBS_DIR=	${LIBEXECDIR}/ext_libs

# One of these things is not like the others!
UNAME:=	$(shell uname -s)
ifeq (${UNAME}, Linux)
SED=	/bin/sed
SED_ARGS=	-i'' -re
endif

# Use GNU tar when releasing on OS X. BSD tar, the default tar(1),
# includes extended headers that cause (harmless) warnings when
# extracting with older versions of GNU tar. Since I roll releases
# on OS X always use gnutar. This should be extended for other systems
# that don't default to BSD tar.
ifeq (${UNAME}, Darwin)
TAR=	/usr/bin/gnutar
else
TAR=	/usr/bin/tar
endif

# Define this if you have a specific python binary to use.
# Provide the full path to your python binary of choice.
#
# dependency-check makes sure it's 2.6 or newer.
# make dependency-check PYTHON=/opt/bin/python
ifeq (${UNAME}, FreeBSD)
PYTHON?=	/usr/local/bin/python
else
PYTHON?=	/usr/bin/python
endif

PY_VER:=	$(shell ${PYTHON} -V 2>&1)
PY_MAJ:=	$(word 2,$(subst ., ,${PY_VER}))
PY_MIN:=	$(word 3,$(subst ., ,${PY_VER}))
PY_TEST:=	$(shell [ ${PY_MAJ} -eq 2 -a ${PY_MIN} -ge 6 ] && echo true)

DNSLIB_MODULES=	dns_extractor

HTPY_MODULES=	http_extractor

MONGO_MODULES=	dns_extractor \
		http_extractor

YARA_MODULES=	yarashop

dependency-check:
	@echo "Checking dependencies..."
	@echo "Checking python..."
ifeq (${PY_TEST}, true)
	@echo "Python OK: ${PY_VER}"
else
	@echo "FATAL: Python BAD: ${PY_VER} (Need 2.6+)"
endif
	@echo "Checking pynids..."
	@if ${PYTHON} -c 'import nids'; then \
		echo "pynids OK"; \
	else \
		echo "FATAL: pynids BAD"; \
	fi
	@echo "Checking pymongo..."
	@if ${PYTHON} -c 'import pymongo'; then \
		echo "pymongo OK"; \
	else \
		echo "pymongo BAD"; \
		echo "These modules will not work:"; \
		echo "${MONGO_MODULES}"; \
	fi
	@echo "Checking htpy..."
	@if ${PYTHON} -c 'import htpy'; then \
		echo "htpy OK"; \
	else \
		echo "htpy BAD"; \
		echo "These modules will not work:"; \
		echo "${HTPY_MODULES}"; \
	fi
	@echo "Checking dnslib..."
	@if ${PYTHON} -c 'import dnslib'; then \
		echo "dnslib OK"; \
	else \
		echo "dnslib BAD"; \
		echo "These modules will not work:"; \
		echo "${DNSLIB_MODULES}"; \
	fi
	@echo "Checking yaraprocessor..."
	@if ${PYTHON} -c 'import yaraprocessor'; then \
		echo "yaraprocessor OK"; \
    else \
		echo "yaraprocessor BAD"; \
		echo "These modules will not work:"; \
		echo "${YARA_MODULES}"; \
	fi

# When installing we need to modify the chopshop working directory
# so that external libraries and modules are found properly.
install:
	@${SED} ${SED_ARGS} 's,^(CHOPSHOP_WD = os.path.realpath\().*(\)),\1"${LIBEXECDIR}"\2,;1,1s,.*,#!${PYTHON},' chopshop
	@${SED} ${SED_ARGS} 's,^(sys.path.append\().*,\1"${SHOPDIR}"),;1,1s,.*,#!${PYTHON},' suture 
	@${INSTALL} -v -d ${BINDIR}
	@${INSTALL} -v -o ${OWNER} -g ${GROUP} chopshop ${BINDIR}
	@${INSTALL} -v -o ${OWNER} -g ${GROUP} suture ${BINDIR}
	@${INSTALL} -v -d ${SHOPDIR}
	@${INSTALLDATA} -v -o ${OWNER} -g ${GROUP} shop/* ${SHOPDIR}
	@${INSTALL} -v -d ${MOD_DIR}
	@${INSTALLDATA} -v -o ${OWNER} -g ${GROUP} modules/* ${MOD_DIR}
	@${INSTALL} -v -d ${EXT_LIBS_DIR}
	@${INSTALLDATA} -v -o ${OWNER} -g ${GROUP} ext_libs/* ${EXT_LIBS_DIR}

# Using COPYFILE_DISABLE=true causes OS X to not copy the resource forks.
# Transformations are not applied to resource forks so we had a couple of bad
# entries in the released tarballs because of this.
release:
	@/bin/rm -rf ./${RELEASE_DIR}
	@/bin/mkdir ./${RELEASE_DIR}
	@COPYFILE_DISABLE=true ${TAR} -cvj --transform=s,^,${RELEASE_NAME}/, --exclude ${RELEASE_DIR} --exclude ".git*" --exclude "*.swp" --exclude "*.pyc" -f ${RELEASE_FILE} .
