.. _installation:

Installation
============

You can run ChopShop using a Docker_ container or install it directly onto the
target machine (either system-wide or into a virtualenv_).  ChopShop requires
Python 2.6 or 2.7.

.. note::

    The manual installation process has been tested and confirmed to work on
    Ubuntu 14.04.  It should be possible to install ChopShop on most
    POSIX-compliant operating systems, though in some cases package names or
    build steps may be different than shown below.  If you run into problems,
    please file an issue in the GitHub repository.  Pull requests to improve
    the installation process or documentation for other platforms are
    encouraged!

.. _Docker: https://www.docker.com
.. _virtualenv: https://virtualenv.pypa.io/

Docker
------

Once you install Docker, you can fetch the ChopShop Docker image::

    $ docker pull mitrecnd/chopshop

You can run a container using a command such as the following::

    $ docker run --rm -it -v /path/to/folder/pcap:/pcap mitrecnd/chopshop -f my.pcap "http | http_extractor"

The arguments ``-f my.pcap "http | http_extractor"`` are passed directly to the
``chopshop`` program. For more information on the ``chopshop`` command and its
options, see :ref:`chopshop-cli`. For more information on using ChopShop with
Docker, see the ``docker/docker.md`` file.

Using the Makefile
------------------

The recommended method for manually installing ChopShop is to use the included
Makefile. This file can also be used to check for required dependencies.

1. Download the latest stable version of ChopShop from the Releases_ page
   (replacing ``X.Y`` with the latest version)::

    $ wget https://github.com/MITRECND/chopshop/archive/RELEASE_X.Y.tar.gz
    $ tar xf RELEASE_X.Y.tar.gz
    $ cd chopshop-RELEASE_X.Y

   Alternatively, you can clone the most recent version from GitHub. The master
   branch may have fixed bugs from the prior stable version, and may contain
   additional features added since the latest release::

    $ git clone https://github.com/MITRECND/chopshop.git
    $ cd chopshop

.. _Releases: https://github.com/MITRECND/chopshop/releases

2. Install ChopShop. By default, ChopShop will be installed into
   ``/usr/local``, but you can change this with the ``PREFIX`` environment
   variable. You can also change the owner and group of the ChopShop files with
   ``OWNER`` and ``GROUP``, and specify the path to particular Python
   interpreter with ``PYTHON``::

    $ sudo make install

3. Install ChopShop dependencies. The Makefile contains a ``dependency-check``
   target that can be used to verify which dependencies are installed::

    $ make dependency-check

   The only dependency required by the ChopShop core is ``pynids``. Several
   modules have their own dependencies. Information on installing particular
   dependencies can be found below.

4. Run ChopShop. Assuming the ``chopshop`` program was installed onto your
   path, you can run it with a command like::

    $ chopshop -f my.pcap "http | http_extractor"

   For more information on the ``chopshop`` command and its options, see
   :ref:`chopshop-cli`.


Using a virtualenv
------------------

If you want to try out ChopShop with minimal changes to your underlying system,
or want isolate ChopShop from other projects with potentially conflicting
dependencies, ChopShop can also be installed into a virtualenv_. As with the
Makefile approach, this can be done using either a tagged release of ChopShop,
or a cloned copy of the source repository. Dependencies should be installed
into the virtualenv; make sure the virtualenv is activated, or you're otherwise
using the ``pip`` binary from the virtualenv::

    $ ...
    $ /path/to/virtualenv/bin/pip install ...
    $ ...

You can also use symlinks or create the virtualenv with
``--system-site-packages`` if you need OS-provided packages (such as with
M2Crypto on Ubuntu).

You can use the Makefile to check the dependencies installed in your virtualenv
as well. Make sure you use the ``PYTHON`` environment variable to point to the
virtualenv's Python interpreter::

    (my_env)$ PYTHON=`which python` make dependency-check


Dependencies
------------

ChopShop depends on several C libraries, with their corresponding Python
wrappers. This guide assumes that you are familiar with installing packages. On
Ubuntu, you should have the ``build-essential`` and ``python-dev`` packages
installed first::

    $ sudo apt-get install build-essential python-dev

For installing Python packages, pip_ is highly recommended.

Other OS-provided packages may be need for specific dependencies. They are
listed below.

If you are installing into a virtualenv, you do not need to use ``sudo`` to run
the ``python setup.py install`` or ``pip install`` commands.

.. _pip: https://pip.pypa.io/

pynids
~~~~~~

pynids_ (the Python bindings for libnids_) is a required dependency for
ChopShop. pynids itself depends on libpcap and libnet, so you will need to run
the following command first (on Ubuntu)::

    $ sudo apt-get install libnet1-dev libpcap-dev

To install pynids, run the following::

    $ git clone https://github.com/MITRECND/pynids.git
    $ cd pynids
    $ sudo python setup.py install

.. _pynids: https://github.com/MITRECND/pynids
.. _libnids: https://github.com/MITRECND/libnids

htpy
~~~~

htpy_ (the Python bindings for libhtp_) is required for the ChopShop
:ref:`http` module. libhtp depends on zlib, so you will need to run the
following command first (on Ubuntu)::

    $ sudo apt-get install zlib1g-dev

Install htpy::

    $ git clone https://github.com/MITRECND/htpy.git
    $ cd htpy
    $ sudo python setup.py install

.. _htpy: https://github.com/MITRECND/htpy
.. _libhtp: https://github.com/OISF/libhtp

pymongo
~~~~~~~

The :ref:`dns_extractor` module can optionally store data into MongoDB_, when
passed the ``-m`` flag.  Instructions for installing MongoDB are beyond the
scope of this guide, but you can install pymongo with the following command::

    $ sudo pip install pymongo

.. _MongoDB: https://www.mongodb.org/

dnslib
~~~~~~

dnslib_ is required by the dns module. It can be installed with pip::

    $ sudo pip install dnslib

.. _dnslib: https://bitbucket.org/paulc/dnslib


pylibemu
~~~~~~~~

pylibemu_ (the Python bindings for libemu_) are required for the
shellcode_extractor module in ChopShop. libemu requires some additional Ubuntu
packages to build successfully::

    $ sudo apt-get install autoconf libtool

To install libemu::

    $ git clone https://github.com/buffer/libemu.git
    $ cd libemu
    $ autoreconf -v -i
    $ ./configure --prefix=/usr/local
    $ sudo make install
    $ sudo ldconfig

Then, install pylibemu with pip::

    $ sudo pip install pylibemu

.. _pylibemu: https://github.com/buffer/pylibemu
.. _libemu: https://github.com/buffer/libemu


yaraprocessor
~~~~~~~~~~~~~

yaraprocessor_ is an extension to Yara_, designed to work with PCAP files in
ChopShop. yaraprocessor requires that Yara and its Python bindings be installed
first::

    $ wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
    $ tar xf v3.4.0.tar.gz
    $ cd yara-3.4.0
    $ ./bootstrap.sh
    $ ./configure
    $ sudo make install
    $ sudo ldconfig
    $ cd yara-python
    $ sudo python setup.py install

Then, install yaraprocessor with pip::

    $ sudo pip install yaraprocessor

.. _yaraprocessor: https://github.com/MITRECND/yaraprocessor
.. _Yara: https://yara.readthedocs.org/

M2Crypto
~~~~~~~~

M2Crypto_ is needed for the :ref:`chop_ssl` module.

On Ubuntu, it's easiest to use the OS-provided package. There is currently a
bug__ when trying to build the PyPI-provided
version of M2Crypto on Ubuntu 14.04::

    $ sudo apt-get install python-m2crypto

.. _M2Crypto: https://gitlab.com/m2crypto/m2crypto
__ https://gitlab.com/m2crypto/m2crypto/issues/69
