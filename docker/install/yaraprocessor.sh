#!/bin/sh

set -x

git clone git://github.com/MITRECND/yaraprocessor.git

cd yaraprocessor

python setup.py install
