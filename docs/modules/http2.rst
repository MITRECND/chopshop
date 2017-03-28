.. _http2:

http2
====

This module converts supported input types to 'http' data to be used by modules downstream.

The supported input types are:

* TCP

The format of the 'http' data follows the same data format as the http module

Module flags/options::

  -h, --help            show this help message and exit
  -v, --verbose         Be verbose about incoming packets and errors
  --forgiving           Attempt to detect http2 in non-standard looking
                        traffic
  -a HASH_FUNCTION, --hash-function=HASH_FUNCTION
                        Hash Function to use on bodies (default 'md5',
                        available: 'sha1', 'sha256', 'sha512')
  -p PORTS, --ports=PORTS
                        List of ports to check, comma separated, e.g.,
                        "443,4443", pass an emptry string to scan all ports
                        (default '80')



Notes:
This is a preliminary decoder and is rather naive in its decoding of HTTP/2 traffic
given the complexity of the protocol -- but since it creates 'http' type data
it can be used with the http_extractor module, making it easier to read/parse
HTTP/2 traffic. Also note this module requires the 'hpack' library to do RFC
7541 hpack decoding of header data as specified by the http 2 RFC (7540)

ToDo:
* Information about Frames and Streams
    * Output new http2 type?
* Support for sslim data as input
