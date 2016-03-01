.. _http:

http
====

This module converts supported input types to 'http' data to be used by modules downstream.

The supported input types are:

* TCP
* sslim

The format of the 'http' data follows the ChopProtocol model and looks like::

    http = {
        type = 'http'
        timestamp = #Timestamp of this specific http transaction
        flowStart = #Timestamp of the tcp session
        addr = <((src, sport), (dst,dport))> #quad-tuple address
        serverData = {
            headers = <all response headers>
            status = <status code>
            body = <response body>
            truncated = <True|False> #Was the body truncated by this module
            body_len = <full body length>
            hash_fn = <md5|sha1|sha256|sha512> #What hash function was used to hash the body
            body_hash = <hash of response body>
        },
        clientData = {
            headers = <all request headers>
            uri = <request uri>
            method = <GET|POST| ... > #What method was used
            protocol = <UNKNOWN|0.9|1.0|1.1|Error> #What protocol version was used 
            body = <request body>
            truncated = <True|False> #Was the body truncated by this module
            body_len = <full body length>
            hash_fn = <md5|sha1|sha256|sha512> #What hash function was used to hash the body
            body_hash = <hash of request body>
        }
    }


Module flags/options::

  -h, --help            show this help message and exit
  -v, --verbose         Be verbose about incoming packets and errors
  -b, --no-body         Do not store http bodies
  -s, --suppress        Suppress htpy log output
  -l LENGTH, --length=LENGTH
                        Maximum length of bodies in bytes (Default: 5MB, set
                        to 0 to process all body data)
  -a HASH_FUNCTION, --hash-function=HASH_FUNCTION
                        Hash Function to use on bodies (default 'md5',
                        available: 'sha1', 'sha256', 'sha512')
  -p PORTS, --ports=PORTS
                        List of ports to check comma separated, e.g.,
                        "80,8080", pass an empty string "" to scan all ports
                        (default '80')


Notes:
If http parses a transaction that exceeds the length specified (default 5MB)
it will truncate the body at that point (setting truncate to True) but will
continue to hash and measure the length of the body. This means that body_len 
and body_hash will always be indicative of what was seen in the transaction 
even if the body was truncated.

Every transaction received will have its own timestamp for that transaction.
This value coorelates to timestamp of the packet after the headers have been
processed by htpy. The flowStart value is the tcp.timestamp of the 3-way
handshake.
