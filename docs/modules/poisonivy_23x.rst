poisonivy_23x
=============

# Copyright (c) 2013 FireEye, Inc. All rights reserved.
# Copyright (c) 2014 The MITRE Corporation. All rights reserved.

Decoder for Poison Ivy versions 2.3.0 and 2.3.2. This module checks the
beginning of each TCP session for possible Poison Ivy challenge-response
sequences. If found, it will try to validate the response using the password(s)
supplied as an argument. If no password is supplied, it tries the default
password: admin. A single password can be supplied in either plain text or
hex-ascii form, or a text file containing line-delimited passwords can be
supplied. If the proper password is found, the decoder goes to work on the
packets. In order to use our decoder, you must install CamCrypt, a python
wrapper for an open source implementation of the Camellia encryption library.
Most of the features of Poison Ivy are covered to some extent. 

Files transferred to or from the 'server' will be saved to disk when the '-f'
option is used. Webcam, audio, keylog, and single screen captures will be saved
to disk when the '-c' option is used. The audio captures are saved as raw data
which can easily be converted to wav files using a tool like 'sox'. The decoder
will print the sample rate, channel, and bit data. File and registry search
details and results are printed. The details of any network relays instantiated
are printed.

File, registry, service, process, device and installed application listings are
partially supported. The default output will highlight that listing requests
have occurred and when applicable will highlight which key/directory is being
listed. Directory listings will be printed but without file details. When the
module is invoked with the '-l' option, all returned list data will be
saved to file raw as it is seen by the Poison Ivy client, a mixture of strings
and binary data describing those strings. Running the 'strings' tool or a
hex editor on these dumps is useful if you are interested in the details of
what was listed.

If there is an unrecognized command, or if you would like to extend the
functionality of this decoder, the '-d' option is quite useful. It will
print hex dumps of all the headers and assembled streams for both directions,
making it easy to analyze and build more parsing functionality.

Thanks to Frank Poz for his work on the CamCrypt library that is utilized in
this module.

If the module is running but not able to decode your Poison Ivy pcap, try this:
https://code.google.com/p/camcrypt/issues/detail?id=1


