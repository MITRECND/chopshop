icmp
====

This module converts 'ip' data to 'icmp' data to be used by modules downstream.

The format of the 'icmp' data follows the ChopProtocol model and looks like::

    icmp = {
        type = 'icmp'
        timestamp = #Timestamp of this specific ip transaction
        addr = <((src, ''), (dst,''))> #quad-tuple address
        serverData = #unused
        clientData = #unused
        data = {
            type = icmp type (e.g., '0' [Echo Reply])
            code = icmp code, related to type
            checksum = icmp checksum from header
            raw = raw icmp message
        }
    }

Module flags/options::

    None
