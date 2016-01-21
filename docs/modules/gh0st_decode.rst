gh0st_decode
============

Decoder for gh0st backdoor. The gh0st backdoor is well known and documented.
The structure of the gh0st protocol is:

* A 5 byte value.
* Length of entire compressed message.
* Length of uncompressed zlib payload.
* zlib payload (starts with 0x789c).

Once a gh0st message has been found it is buffered until the entire message
is available. Once buffering is complete the message is decompressed.
The first byte of most messages is a command or token. The list of commands
and tokens are documented in the code.
