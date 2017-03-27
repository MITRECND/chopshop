#!/bin/sh

set -x

git clone https://github.com/MITRECND/yaraprocessor.git

cd yaraprocessor

python setup.py install
