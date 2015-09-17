#!/bin/sh

set -x

git clone --recursive git://github.com/MITRECND/htpy

cd htpy

python setup.py build
python setup.py install
