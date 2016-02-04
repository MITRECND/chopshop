ChopShop Data Structures
========================

TCP Data
--------

.. py:class:: tcpdata

    Represents the TCP data passed to modules. The tcpdata structure contains
    the follwing attributes

    .. py:attribute:: addr

        quadtuple containing source ip/port and destination ip/port same
        as nids' addr

    .. py:attribute:: nids_state

        same as nids' state, using this should not generally be necessary
        unless better granularity of the end state (in the teardown) is
        necessary

    .. py:attribute:: client

        :py:class:`hstream` object which contains information about the client

    .. py:attribute:: server

        :py:class:`hstream` object which contains information about the server

    .. py:attribute:: timestamp

        variable that contains the timestamp of this packet, same as a call to
        nids.get\_pkt\_ts()

    .. py:attribute:: module_data

        dictionary that is passed back and forth and persists data across the
        lifetime of a module

    .. py:attribute:: stream_data

        dictionary that is passed back and forther and persists data across the
        lifetime of a stream

    Along with the following methods:

    .. py:method:: discard(integer)

        tells ChopShop that this module wants to discard "integer" bytes of the
        stream, same as in nids

    .. py:method:: stop()

        tells ChopShop that this module no longer cares about collecting on
        this stream -- only useful in handleStream

.. py:class:: hstream

    Represents one side/half/direction of a TCP connection. Corresponds to the
    :c:type:`half_stream` struct in libnids.

    .. py:attribute:: state

    .. py:attribute:: data

    .. py:attribute:: urgdata

    .. py:attribute:: count

    .. py:attribute:: offset

    .. py:attribute:: count_new

    .. py:attribute:: count_new_urg

    All elements are the same as described in nids/pynids documentation.

UDP Data
--------

The structure that is passed to modules handling UDP data contains the
following elements.

.. py:class:: udpdata

    .. py:attribute:: addr

        quadtuple containing source ip/port and destination ip/port same as
        nids' addr

    .. py:attribute:: data

        array of UDP payload contents

    .. py:attribute:: timestamp

        variable that contains the timestamp of this packet, same as a call to
        :py:func:`nids.get_pkt_ts`

    .. py:attribute:: module_data

        dictionary that is passed back and forth and persists data across the
        lifetime of a module

    .. py:attribute:: ip

        array of IP layer and payload. This may be removed in future versions,
        do not rely upon it

    The ``udpdata`` class has the following methods:

    .. py:method:: stop()

        tells ChopShop that this quad-tuple should be ignored for the lifetime
        of the module.

IP Data
-------

The ``ipdata`` structure contains elements cooresponding to the ip header
spec:

.. py:class:: ipdata

    .. py:attribute:: version

        The version of ip (note that libnids doesn't support v6 so this should
        always be 4)

    .. py:attribute:: ihl

        Internet Header Length

    .. py:attribute:: dscp

        Differentiated Services Code Point

    .. py:attribute:: ecn

        Explicit Congestion Notification

    .. py:attribute:: length

        Total packet length including header and data (as according to the
        packet)

    .. py:attribute:: identification

        Identification field from packet

    .. py:attribute:: flags

        Fragmentation Flags

    .. py:attribute:: fra

        offset - Fragmentation Offset

    .. py:attribute:: ttl

        The Time To Live of the packet

    .. py:attribute:: protocol

        The protocol this is carrying (e.g., icmp or tcp)

    .. py:attribute:: checksum

        The header checksum

    .. py:attribute:: src

        The ip source

    .. py:attribute:: dst

        The ip destination

    .. py:attribute:: raw

        This is the raw ip packet

    .. py:attribute:: addr

        A quadtuple containing source and destination elements. Note that the
        port values are blank.
