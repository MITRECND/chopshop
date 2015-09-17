#!/bin/sh

set -x

git clone git://git.carnivore.it/libemu.git

cd libemu

autoreconf -v -i

./configure --enable-python-bindings --prefix=/opt/libemu
make install
echo "/opt/libemu/lib/" >> /etc/ld.so.conf.d/libemu.conf
ldconfig

git clone git://github.com/buffer/pylibemu.git

cd pylibemu

python setup.py build
python setup.py install
