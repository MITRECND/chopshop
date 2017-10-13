#!/bin/sh

set -x

git clone --recursive https://github.com/MITRECND/pynids

cd pynids

python setup.py build
python setup.py install
