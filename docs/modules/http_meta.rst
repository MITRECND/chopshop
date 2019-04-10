.. _http_meta:

http_meta
=========

This module extracts information from HTTP packets. It then generates a new format
called "http_meta" for consumption downstream.

It is dependant on the 'http' type provided by the http module

The format of the 'http_meta' data looks like::

    http_meta = {
        type = 'http_meta'
        timestamp = #Timestamp of this specific http transaction
        flowStart = #Timestamp of the tcp session
        addr = <((src, sport), (dst,dport))> #quad-tuple address
        data = {
            request = {
                headers = <all request headers>
                uri = <request uri>
                method = <GET|POST| ... > #What method was used
                protocol = <UNKNOWN|0.9|1.0|1.1|Error> #What protocol version was used 
                truncated = <True|False> #Is the body truncated
                                         # can also compare the body size to body_len
                body = <request body>
                body_encoding = 'base64' # only present if data was base64 encoded
                                         # see below module flag/option
                body_len = <full body length>
                hash_fn = <md5|sha1|sha256|sha512> #What hash function was used to hash the body
                body_hash = <hash of request body>
            },
            response = {
                headers = <all response headers>
                status = <status code>
                truncated = <True|False> #Is the body truncated
                                         #you can also compare the body size to body_len
                body = <response body>
                body_encoding = 'base64' # only present if data was base64 encoded
                                         # see below module flag/option
                body_len = <full body length>
                hash_fn = <md5|sha1|sha256|sha512> #What hash function was used to hash the body
                body_hash = <hash of response body>
            }
        }
    }

Module flags/options::

  -h, --help           show this help message and exit
  -b, --base64-encode  Base64 Encode bodies
