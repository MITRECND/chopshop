.. _chop_ssl:

chop_ssl
========

This module converts 'tcp' data to 'sslim' data to be used by modules
downstream.

The format of the 'sslim' data follows the ChopProtocol model and looks like::

    sslim = {
        type = 'sslim'
        timestamp = # Timestamp of this specific ssl transaction
        addr = <((src, ''), (dst,''))> # quad-tuple address
        serverData = # A string containing the decrypted bytes.
        clientData = # A string containing the decrypted bytes.
    }

Module flags/options::

    -v: Be verbose about new flows and packets
    -k: Private key file (must be RSA)
