etumbot
=======

A decoder for the etumbot malware.

You can run it with:

./chopshop -f etumbot.pcap "http | etumbot -v -H 192.168.1.1"

Where "192.168.1.1" is the HTTP Host header used by the malware. This version
of the decoder also checks that the referer is 'http://www.google.com/'.
