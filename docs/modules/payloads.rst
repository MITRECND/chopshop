payloads
========

The payloads decoder is used to print plaintext or xor encoded payloads from
supported input types.

The supported input types are:
* TCP
* UDP
* sslim

The module must be given a comma separated list of IP addresses to watch
for. If desired a xor key can be given (prefixed with 0x) which will be
applied to the payload of each packet.
