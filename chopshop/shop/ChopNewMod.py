#!/usr/bin/env python

import argparse
import os
import sys
from string import Template
from subprocess import call


default_template = \
"""moduleName="${MODNAME}"
moduleVersion="0.1"
minimumChopLib="4.0"

def module_info():
    pass

def init(module_data):
    module_options = { 'proto': [{'${TYPE}': ''}] }
    return module_options

def ${HANDLE}(${ARG}):
    $HBODY
    return

def shutdown(module_data):
    return
"""

tcp_template_mod =\
"""
def taste(${ARG}):
    return False

def teardown(${ARG}):
    return
"""

def main():

    parser = argparse.ArgumentParser(description="Create a new ChopShop module")
    parser.add_argument("module_name", metavar="module_name", type=str,
                        help="Name of the new module")
    parser.add_argument("_type", metavar="type", type=str,
                        choices=["tcp", "ip", "udp", "CUSTOM"],
                        help="The type of module to create")
    parser.add_argument("custom_type", metavar="CUSTOM_TYPE", type=str,
                        default=None, nargs='?',
                        help="The type of the CUSTOM module")
    parser.add_argument("-d", "--development-mode", dest="devel",
                        action="store_true", default=False,
                        help=("Assumed ChopShop has been installed "
                              "in development mode and a module can be"
                              "installed directly. This option overrides -o"))
    parser.add_argument("-o", "--output-directory", dest="directory",
                        default=None, type=str,
                        help=("The directory to write template "
                              "to, defaults to cwd"))
    parser.add_argument("-e", "--editor", default=False, action="store_true",
                        help=("Launch the editor to begin editing "
                              "the module right away"))

    args = parser.parse_args()

    if args._type == 'CUSTOM' and args.custom_type is None:
        args.error("CUSTOM_TYPE required when using CUSTOM type")

    module_file = "%s.py" % (args.module_name)
    doc_file = "%s.rst" % (args.module_name)

    if args.devel:
        module_dir = os.path.join(os.path.abspath(os.path.join(
                     os.path.dirname(os.path.abspath(__file__)),
                     os.pardir)), "modules")
        docs_dir = os.path.join(os.path.join(os.path.abspath(os.path.join(
                   os.path.dirname(os.path.abspath(__file__)),
                   os.pardir)), os.pardir), "docs", "modules")

        module_path = os.path.join(module_dir, module_file)
        doc_path = os.path.join(docs_dir, doc_file)
    elif args.directory is None:
        args.directory = os.getcwd()
        module_path = os.path.join(args.directory, module_file)
        doc_path = os.path.join(args.directory, doc_file)
    else:
        module_path = module_file
        doc_path = doc_file

    if os.path.exists(module_path):
        print("Module already exists")
        sys.exit(1)

    handleBody = ""
    if args._type == "tcp":
        HANDLE = 'handleStream'
        ARG = 'tcp'
    elif args._type == "udp":
        HANDLE = 'handleDatagram'
        ARG = 'udp'
    elif args._type == "ip":
        HANDLE = 'handlePacket'
        ARG = 'ip'
    elif args._type == 'CUSTOM':
        HANDLE = 'handleProtcol'
        args._type = args.CUSTOM_TYPE
        ARG = 'chopp'
        handleBody = \
        """if %s.type != %s:
            return
        """ % (ARG, args._type)

    print(module_path, doc_path)

    with open(module_path, 'wb') as f:
        output = default_template
        if args._type == "tcp":
            output += tcp_template_mod
        t = Template(output)
        out = t.substitute(HANDLE=HANDLE, ARG=ARG, HBODY=handleBody,
                           TYPE=args._type, MODNAME=args.module_name)
        f.write(out)

    with open(doc_path, 'wb') as f:
        pass

    if args.editor:
        editor = os.environ.get("EDITOR", None)
        if editor is None and os.path.isfile('/usr/bin/editor'):
            # Debian-based only TODO XXX FIXME
            editor = '/usr/bin/editor'
        else:
            editor = 'vi'
        call([editor, module_path])


if __name__ == "__main__":
    main()
