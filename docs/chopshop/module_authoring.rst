.. _module_authoring:

Developing ChopShop Modules
===========================

Once you are familiar with how ChopShop and the built-in modules operate, you
are ready to write your own modules!  If you need a refresher, check out
:ref:`chopshop-cli`.

A ChopShop module is just a Python module (file) that defines some specific
variables and functions (listed below).  The file must have a unique name
ending in ``.py`` and be placed it in the :term:`modules directory`. Modules
can accept run-time options, and can process raw TCP, UDP, or IP traffic, or
the output of other modules.

Some experience with pynids/libnids is helpful, but not required, to write
ChopShop modules.

Quick Start
-----------

The ``newmod.sh`` script lets you quickly create the skeleton for a new
ChopShop module, including the required variables and functions depending on
the type of data you plan to process.  The script takes 2 (or 3) arguments:

* The first argument is the name for your new module.
* The second argument is the type of data you plan to process (one of ``tcp``,
  ``udp``, ``ip``, or ``CUSTOM``).
* If ``CUSTOM``, the third argument should be the type of custom data you plan
  to process (for example, ``http``).

Examples::

   ./newmod.sh awesome_decoder tcp
   ./newmod.sh my_http_parser CUSTOM http

As a bonus, the script will open your ``$EDITOR`` to let you get right to work
customizing your module's behavior.

Required Variables
------------------

Each ChopShop module must define the following variables:

.. py:data:: moduleName

   The module name (str). For example, ``'myawesomemodule'``.

.. py:data:: moduleVersion

   The module version (str). For example, ``'0.1'``. No particular format for
   this string is required, but it is recommended to use `semantic
   versioning`_.

.. py:data:: minimumChopLib

   The minimum version of :term:`ChopLib` required to support this module. For
   example, ``'4.0'``.

Modules that do not define ``moduleName`` will not function (since they cannot
be referenced from a ChopShop processing pipeline). Any module that does not
define ``moduleVersion`` or ``minimumChopLib`` will be considerd 'legacy'
(pre-4.0) and will not be able to access module pipelining and some other newer
features.

.. _semantic versioning: http://semver.org/

Required Functions
------------------

All modules must define the :py:func:`module_info` and :py:func:`init`
functions.

.. py:function:: module_info()

   This function is invoked when ``chopshop`` is passed the ``-m`` or
   ``--module_info`` flag. This function should return a string consisting of a
   usage message and any options the module takes.

.. py:function:: init(module_data)

   This function is invoked once per ``chopshop`` process. Any module-level
   initialization required before processing any packets, such as processing
   module-level arguments, should be done in this function.

   The ``module_data`` argument is a dictionary with (at least) the following
   keys:

   * ``args`` (list of str): The arguments passed to this module by the
     ``chopshop`` invocation. Typically these should be passed to the
     :py:func:`parse_args()` method of an :py:class:`optparse.OptionParser`
     object.

   The ``module_data`` dictionary can be modified in the ``init`` function.
   This dictionary is accessible in any of the ``handleX`` functions, so can be
   used to store information needed throughout the lifetime of the module.

   The ``init`` function MUST return a dictionary, containing a ``proto`` key.
   The value corresponding to this key should be a list of dictionaries, each
   mapping an input type to an output type, for a type of processing the module
   can perform.  The input type can be either a core type (``tcp``, ``udp``, or
   ``ip``) or a secondary type.  The output type can be a secondary type or an
   empty string; modules intended to be the last in any particular chain should
   use ``''`` as the output type.  Core types should **NOT** be used as output
   types.  This list is used for module chaining, to verify the input and
   output of each module in the chain is compatible.

   For example, a module which processes UDP data and does not return data for
   later modules might return ``{'proto': [{'udp': ''}]}``. A module which
   processes TCP data and returns ``http`` data would return ``{'proto':
   [{'tcp': 'http'}]}``.

   The dictionary returned by the ``init`` function may also contain an
   ``error`` key to indicate an error occurred during initialization (for
   example, if the ``args`` were invalid). The value of this key should be a
   human-readable string, which is presented to the user.

   .. note::
      Legacy (pre-4.0) ChopShop modules did not support chaining, and used a
      single string value for the ``proto`` key, such as ``{'proto': 'tcp'}``.
      This style should not be used for new modules.

Modules intended to process TCP data must additionally define the
:py:func:`taste` and :py:func:`handleStream` functions.

.. py:function:: taste(tcp_data)

   Called when a new stream is detected (SYN, SYN/ACK, ACK), but before any
   data is received.  Treat tcp\_data like the object sent to callbacks for
   nids' register\_tcp. (ex: o.addr, o.client.count\_new, o.discard(0))

   Returns: True or False, specifying whether or not to further
            process data from this stream.

.. py:function:: handleStream(tcp_data)

   Treat this like the callback for nids.register\_tcp(). Treat tcp\_data like
   the object sent to callbacks for nids' register\_tcp. (ex: o.addr,
   o.client.count\_new, o.discard(0))

Modules intended to process UDP data must define the :py:func:`handleDatagram`
function.

.. py:function:: handleDatagram(udp_data)

   Called once per UDP datagram. Calling udp.stop() tells ChopShop to ignore
   this quad-tuple for the lifetime of the module. This is very different from
   TCP behavior, so be aware!


Modules intended to process IP data must define the :py:func:`handlePacket`
function.

.. py:function:: handlePacket(ip)

   handler for ip data -- refer to below structure to understand what data is
   passed

Secondary modules (those which process data other than TCP, UDP, or IP--like
HTTP) must define a generic function :py:func:`handleProtocol`.

.. py:function::handleProtocol(protocol)

   handler for secondary, module-defined types.  Refer to documentation above
   for the structure of data passed to this function (more below on module
   chaning)

Optional Functions
~~~~~~~~~~~~~~~~~~

Modules do not need to define the following functions but doing so
provides extra functionality or information.

ALL MODULES
^^^^^^^^^^^

shutdown(module\_data) -- Called when ChopShop is shutting down; gives
the module one last chance to do what it needs to.

TCP MODULES
^^^^^^^^^^^

teardown(tcp\_data) -- Called when a stream is closed (RST, etc.) Treat
tcp\_data like the object sent to callbacks for nids' register\_tcp.
(ex: o.addr, o.client.count\_new, o.discard(0))


ChopProtocol
^^^^^^^^^^^^

The ChopProtocol base class is what secondary modules will receive
through the 'handleProtocol' function. It has the following elements:

addr - quadtuple containing source ip/port and destination ip/port same
as nids' addr

timestamp - variable that contains the timestamp of this packet, same as
a call to nids.get\_pkt\_ts()

module\_data - dictionary that is passed back and forth and persists
data across the lifetime of a module

type - variable specifying the 'type' of the data

clientData - arbitrary python data structure defined by primary modules
for data from the client

serverData - arbitrary python data structure defined by primary modules
for data from the server

\_teardown - (ChopLib 4.3+) variable that tells the framework that this
data should be forwarded to the teardown code of modules down stream.
The function setTeardown is provided as a convenience function for code
clarity. Data returned in tcp's handleTeardown is automatically marked
as teardown data.

Note that if you are creating a module that consumes data from another
module, you must refer to that modules documentation to see what their
instance of ChopProtocol contains!


Primary vs. Secondary Modules
-----------------------------

ChopShop has two types of modules to supports its chaining functionality
called 'primary' and 'secondary'. The distinction is that primary
modules parse data that is considered a 'core' type within ChopShop,
specifically this would be tcp, udp, and ip. A module that processes a
module created type is considered secondary. The http\_extractor module,
for example is a secondary module as it only accepts 'http' type data.
It's important to note that since ChopShop supports ingesting multiple
types within a single module, a module can technically both be a primary
and secondary module -- but the distinction between primary and
secondary is generally a runtime distinction, as in what functions will
be called in either case. More on this will be covered below.

Module Chaining
---------------

Taking all of the above into consideration, this section will cover how
module chaining is supposed to work from a module authors perspective.

Primary Modules
~~~~~~~~~~~~~~~

Modules that ingest the core types 'tcp', 'udp', and 'ip' can return an
instance of ChopProtocol to be consumed by secondary modules. Before
use, ChopProtocol must be imported by doing:

.. raw:: html

   <pre>
   from ChopProtocol import ChopProtocol
   </pre>

To instantiate an instance of ChopProtocol you can do something like:

.. raw:: html

   <pre>
   myhttpinstance = ChopProtocol('http')
   </pre>

The argument passed to ChopProtcol is the 'type' of the data being
passed, in the above example, the data is of type 'http'.

After instantiating an object based on ChopProtocol you have access to
the following functions:

setAddr - Set the quadtuple containing source ip/port and destination
ip/port -- this will be auto set by the framework if you do not

setTimestamp - Set variable that contains the timestamp of the protocol
-- this will be autoset to the timestamp of whatever packet you return
data on if you do not set it

setClientData - Set the arbitrary data structure for the data coming
from the client

setServerData - Set the arbitrary python data structure for the data
coming from the server

setTeardown - (ChopLib 4.3+) Indicate this data should be forwarded to
downstream module's teardown functions.

Note that the format of ChopProtocol is not meant to be restrictive. You
can and should override or ignore some functionality if it doesn't fit
your model of how data should be handled (e.g., creating a 'data'
element instead of having client and server elements). Before returning
an instance of ChopProtocol it is recommended you familarize yourself
with internal structure of the class. It is also extremely important
that you thoroughly document the format and organization of the object
you return from your module.

\_clone function
^^^^^^^^^^^^^^^^

ChopLib requires the ability to create copies of ChopProtocol to provide
modules with their own unique copy. By default ChopProtocol contains a \_clone
function that uses copy's 'deepcopy' function. If your data (e.g., clientData
and serverData) are complex enough, this might not be enough to copy your data.
In these instances you should create an inherited class based on ChopProtocol
and redefine the \_clone function.

Secondary Modules
~~~~~~~~~~~~~~~~~

If you want to write a decoder for a protcol that runs on top of another
protocol, such as http, normally you would first parse the http traffic
out and then proceed to parse the protocol that you were actually trying
to decode. With module chaining, you can pass the data through a primary
module that takes tcp and turns it into http and then focus on only the
protocol you care about

As documented above, secondary modules have one function they must
define to handle data:

handleProtocol(protocol) -- Protocol data, partially defined by primary
module

Starting with ChopLib 4.3, you can optionally define the following to
handled 'teardown' data:

teardownProtocol(protocol) -- Protocol data, partially defined by
primary module

Secondary modules can further return data to be used by other,
downstream secondary modules by the same procedure as primary modules
for returning custom types.

Note that module authors writing secondary modules should refer to
documentation for primary modules since the organization, data, etc in
what is returned by a primary module many not conform to the default
ChopProtocol syntax.

The "chop" library
------------------

ChopShop provides the "chop" library for module usage to interact with
the outside world. This allows the module writer to worry less about how
to output data. The chop library provides output "channels" to allow you
to very easily output data to the location of the module invoker's
choosing. The following output channels are supported:

.. raw:: html

   <pre>
   chop.prnt - Function that works similar to print, supports output to a gui, stdout, or a file depending on the users command line arguments
   chop.debug - Debug function that outputs to a gui, stderr, or a file depending on the users command line arguments
   chop.json - Outputs a json string based on an object passed to it, enabled if JSON output is enabled by the user
   </pre>

chop also provides the following other related functions:

.. raw:: html

   <pre>
   chop.tsprnt - same as chop.prnt but prepends the packet timestamp to the string
   chop.prettyprnt - same as chop.prnt but the first argument is a color string, e.g., "RED"
   chop.tsprettyprnt - same as chop.tsprnt but the first argument is a color string, e.g., "CYAN"
   chop.set_custom_json_encoder - given a reference to a function will attempt to use it as a custom json encoder for all calls to chop.json
   chop.set_ts_format_short - accepts a boolean that enables short time format '[H:M:S]' (default is '[Y-M-D H:M:S TZ]')
   </pre>

DO NOT use python's regular "print" command.

The following colors are currently supported with chop.prettyprnt and
chop.tsprettyprnt:

.. raw:: html

   <pre>
   "YELLOW" - Yellow on a Black Background
   "CYAN" - Cyan on a Black Background
   "MAGENTA" - MAGENTA on a Black Background
   "RED" - Red on a Black Background
   "GREEN" - Green on a Black Background
   "BLUE" - Blue on a Black Background
   "BLACK" - Black on a White Background
   "WHITE" - White on a Black Background
   </pre>

Note that if a gui is not available or colors are not supported in the
terminal running ChopShop, chop.prettyprnt's functionality is equivalent
to chop.prnt.

Examples
~~~~~~~~

Using the chop library is pretty straightforward, if you want to output
regular text data just type:

.. raw:: html

   <pre>
   chop.prnt("foo")
   chop.prnt("foo", "bar", "hello")
   chop.prnt("The answer is: %s" % data)
   </pre>

If you would like to mirror the functionality of python's print's
ability to supress the trailing '' added to output, you can do the
following:

.. raw:: html

   <pre>
   chop.prnt("foo", None)
   </pre>

To color the data (for gui purposes) just type:

.. raw:: html

   <pre>
   chop.prettyprnt("RED", "foo")
   chop.prettyprnt("MAGENTA", "bar")
   chop.prettyprnt("YELLOW", "bah", None)
   </pre>

If you would like to support outputting json data, you can utilize
chop.json to do so:

.. raw:: html

   <pre>
   myobj = {'foo': ['bar', 'bah']}
   chop.json(myobj)
   </pre>

If you feel the need to make your own custom json encoder, you can use
"chop.set\_custom\_json\_encoder(encoder\_function)" to customize how
the json will be output.

Note that the default json encoder does not support any non standard
types

File Saving
~~~~~~~~~~~

ChopShop provides a simple API for saving files using the chop.\*file()
family of functions. There are three functions in this family:

.. raw:: html

   <pre>
   chop.savefile
   chop.appendfile
   chop.finalizefile
   </pre>

The definition of chop.savefile() looks like:

.. raw:: html

   <pre>
       def savefile(filename, data, finalize = True)
   </pre>

To use chop.savefile() you provide the filename and the data. The
optional third argument (a boolean) is used to determine if the file
object should be kept open or closed. This allows you to do
(pseudo-code):

.. raw:: html

   <pre>
   while (chunk_of_data = decode_some_data_from_pcap):
       if on_last_chunk:
           finalize = True
       else:
           finalize = False
       chop.savefile('foo', chunk_of_data, finalize)
   </pre>

If not given, the default behavior is to close the file object. Since
each file object is opened in write mode module authors need to be aware
of this behavior as it will overwrite any existing files with the same
name.

Similar to chop.savefile(), chop.appendfile() has the following
definition:

.. raw:: html

   <pre>
       def appendfile(filename, data, finalize = False)
   </pre>

To use chop.appendfile() you provide the filename and the data. The
optional third argument (a boolean) is used to determine if the file
object should be kept open or closed. If not given, the default behavior
is to leave the file object open. Note, that unlike savefile, appendfile
opens files in "append" mode, so it will not overwrite any file that
already exists.

The last function in the file family is chop.finalizefile() -- as the
name implies, it allows you to finalize (or close) a file once you are
done with it. It has the following definition:

.. raw:: html

   <pre>
       def finalizefile(filename)
   </pre>

If the filename given is not open, finalizefile will do nothing. Also
note that you can use savefile or appendfile to the same affect by
calling them with an empty string as the data and finalize set to True.
E.g.:

.. raw:: html

   <pre>
       chop.appendfile(filename, "", True)
       chop.savefile(filename, "", True)
   </pre>

finalizefile gives you a shorter, quicker way to close the file that is
easier to see in code.

Note that as a module author you only provide the filename, not the full
path to the file you want created on disk. The full path is handled by
the -s argument to chopshop. For example:

.. raw:: html

   <pre>
   chopshop -f foo.pcap -s "/tmp/%N" "gh0st_decode -s; awesome_carver -s"
   </pre>

This will make sure each carved file from gh0st\_decode go into
/tmp/gh0st\_decode and files from awesome\_carver will go in
/tmp/awesome\_carver. The other supported format string is "%T" which
will be translated into the current UNIX timestamp (/tmp/%N/%T would put
files in /tmp/module\_name/timestamp).

Best Practices for Module Writing
---------------------------------

Module writers should follow the best practices outlined below:

-  Never use function calls that can adversely affect ChopShop or any
   other module.
-  Calls like sys.exit() should not be used as your module might kill
   ChopShop or affect another module.
-  If it is possible to determine early on if a flow is useful, do so.
-  Do not wait until teardown to examine a flow unless it is absolutely
   necessary.
-  Transaction based communication might require processing in the
   teardown.
-  Do not use globals, their usage and behavior can be unpredictable.
   Put them in module\_data or stream\_data where appropriate.
-  Use the code available in ext\_libs to reduce work and duplication.
-  Do not roll your own code if it exists already.
-  If you duplicate code often enough, take it out and put into the
   ext\_libs.
-  In the init if there's an error add a key 'error' to the dictionary
   you return to indicate there was an error and what the error is
   (error string).
-  If your module parses arguments please use OptionParser() in your
   init() function (or a function unconditionally called from init) to
   do so. This allows the -m argument to chopshop to print the
   appropriate usage for your module.
-  Never use any output functions like print or sys.stdout.write().
-  If you can, use chop.prettyprnt to stylize the data so it's easier to
   see and keep track of in the gui.

