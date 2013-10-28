Module Development
==================
Introduction
------------
Creating ChopShop modules consists of creating a python file with a unique name
and placing it in the modules directory. This file must have a .py extension in
order to be recognized by the framework.

newmod.sh
---------
ChopShop provides a shell script to setup a module stub for you. You can use
'newmod.sh' to create this stub and open an editor for you to get right to
work. The newmod.sh script takes two arguments. The first is the name of the
module you want to create and the second is a string (either 'tcp' or 'udp')
depending upon the layer 4 payload you intend to parse.

<code>
./newmod.sh awesome_decoder tcp
</code>

tcp_data structure
------------------
The tcp data that is passed to modules contains the following elements:

<b>addr</b> - quadtuple containing source ip/port and destination ip/port same
as nids' addr

<b>nids_state</b> - same as nids' state, using this should not generally be
necessary unless better granularity of the end state (in the teardown) is
necessary

<b>client</b> - object which contains information about the client

<b>server</b> - object which contains information about the server

<b>timestamp</b> - variable that contains the timestamp of this packet, same as
a call to nids.get_pkt_ts()

<b>module_data</b> - dictionary that is passed back and forth and persists data
across the lifetime of a module

<b>stream_data</b> - dictionary that is passed back and forther and persists
data across the lifetime of a stream

Along with the following functions

<b>discard(integer)</b> -- tells ChopShop that this module wants to discard
"integer" bytes of the stream, same as in nids

<b>stop()</b> -- tells ChopShop that this module no longer cares about
collecting on this stream -- only useful in handleStream

Both the client and server objects contain the following fields:

<b>state</b>

<b>data</b>

<b>urgdata</b>

<b>count</b>

<b>offset</b>

<b>count_new</b>

<b>count_new_urg</b>

All elements are the same as described in nids/pynids documentation.

udp_data structure
------------------
The udp_data structure that is passed to functions contains the following
elements:

<b>addr</b> - quadtuple containing source ip/port and destination ip/port same
as nids' addr

<b>data</b> - array of UDP payload contents

<b>timestamp</b> - variable that contains the timestamp of this packet, same as
a call to nids.get_pkt_ts()

<b>module_data</b> - dictionary that is passed back and forth and persists data
across the lifetime of a module

<b>ip</b> - array of IP layer and payload. This may be removed in future
versions, do not rely upon it

The udp_data structure has the following functions:

<b>stop()</b> -- tells ChopShop that this quad-tuple should be ignored for the
lifetime of the module

ChopProtocol structure
----------------------
The ChopProtocol base class is what secondary modules will receive through the
'handleProtocol' function. It has the following elements:

<b>addr</b> - quadtuple containing source ip/port and destination ip/port sam
as nids' addr

<b>timestamp</b> - variable that contains the timestamp of this packet, same as
a call to nids.get_pkt_ts()

<b>module_data</b> - dictionary that is passed back and forth and persists data
across the lifetime of a module

<b>type</b> - variable specifying the 'type' of the data

<b>clientData</b> - arbitrary python data structure defined by primary modules for data
from the client

<b>serverData</b> - arbitrary python data structure defined by primary modules for data
from the server


Variables
---------
Every module <b>must</b> define the following global variables:
"moduleName" -- The module name (string) [E.g., 'myawesomemodule']
"moduleVersion" -- The module version (string) [E.g., '0.1']
"minimumChopLib" -- The minimum version of ChopLib [E.g., '4.0']


Modules will not function without "moduleName"
Any module that does not define 'moduleVersion' or 'minimumChopLib'
will be considerd 'legacy' (pre 4.0) and will not be able to access
module pipelining


Required Functions
------------------
###ALL MODULES
Modules must define the following functions to be used with ChopShop:

<b>module_info()</b> -- invoked when a chopshop user uses the -m/--module_info
flag, module may write out any information it wants to inform the user of its
functionality/usage by returning a string. The usage of 'print' in this function
has been removed.

<b>init(module_data)</b> -- Initialize the module, before processing any
packets.
  module_data is a dictionary with at least the following key(s):
    'args': an array of command-line args suitable to pass to
            the parse_args() function of an
            optparse.OptionParser() object.

  Returns: dictionary with at least the following key(s):
    'proto': Array of dictionaries linking input types to outputs
            E.g., proto = [ {'tcp' : ''}]
                  proto = [ {'tcp' : 'http'}]
            Note: 'tcp', 'udp', and 'ip' are considered pre-defined types and should
            not be used as return types (further note, 'ip' has not been implemented yet)

    Optional: the return dictionary may also include:
        'error': indicates an error in the module has occured
                 set to a friendly string so that ChopShop can
                 inform the user

###TCP MODULES
<b>taste(tcp_data)</b> -- Called when a new stream is detected (SYN, SYN/ACK,
ACK), but before any data is received.
  Treat tcp_data like the object sent to callbacks for nids' register_tcp.
  (ex: o.addr, o.client.count_new, o.discard(0))

  Returns: True or False, specifying whether or not to further
           process data from this stream.

<b>handleStream(tcp_data)</b> -- Treat this like the callback for
nids.register_tcp().
  Treat tcp_data like the object sent to callbacks for nids' register_tcp.
  (ex: o.addr, o.client.count_new, o.discard(0))

###UDP MODULES
<b>handleDatagram(udp_data)</b> -- Called once per UDP datagram. Calling
udp.stop() tells ChopShop to ignore this quad-tuple for the lifetime of the
module. This is very different from TCP behavior, so be aware!

Optional Functions
------------------
Modules do not need to define the following functions but doing so provides
extra functionality or information.

<b>shutdown(module_data)</b> -- Called when ChopShop is shutting down;
gives the module one last chance to do what it needs to.


<b>teardown(tcp_data)</b> -- TCP-only, called when a stream is closed (RST, etc.)
  Treat tcp_data like the object sent to callbacks for nids' register_tcp.
  (ex: o.addr, o.client.count_new, o.discard(0))

###Secondary Modules
With ChopShop 4.0, it is now possible to chain modules allowing more generic work
to be done by one modules and then passed to multiple children module for further processing.
For example, if you want to write a decoder for a protcol that runs on top of http, normally
you would first parse the http traffic out and then proceed to parse the protocol that you
were <b>actually</b> trying to decode. With 4.0 though, you can pass the data through a primary
module that takes tcp and turns it into http and then focus on only the protocol you care about

<b>handleProtocol(protocol)</b> -- Protocol data, partially defined by primary module



The "chop" library
==================
ChopShop provides the "chop" library for module usage to interact with the
outside world. This allows the module writer to worry less about how to output
data. The chop library provides output "channels" to allow you to very easily
output data to the location of the module invoker's choosing. The following
output channels are supported:

<pre>
chop.prnt - Function that works similar to print, supports output to a gui,
stdout, or a file depending on the users command line arguments
chop.debug - Debug function that outputs to a gui, stderr, or a file depending
on the users command line arguments
chop.json - Outputs a json string based on an object passed to it, enabled if
JSON output is enabled by the user
</pre>

chop also provides the following other related functions:
<pre>
chop.tsprnt - same as chop.prnt but prepends the packet timestamp to the string
chop.prettyprnt - same as chop.prnt but the first argument is a color string,
e.g., "RED"
chop.tsprettyprnt - same as chop.tsprnt but the first argument is a color
string, e.g., "CYAN"
chop.set_custom_json_encoder - given a reference to a function will attempt to
use it as a custom json encoder for all calls to chop.json
chop.set_ts_format_short - accepts a boolean that enables short time format
'[H:M:S]' (default is '[Y-M-D H:M:S TZ]')
</pre>

<b>NO methods should use python's regular "print" command</b>

The following colors are currently supported with chop.prettyprnt and
chop.tsprettyprnt:

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

Note that if a gui is not available or colors are not supported in the terminal
running ChopShop, chop.prettyprnt's functionality is equivalent to chop.prnt.

Examples
--------
Using the chop library is pretty straightforward, if you want to output regular
text data just type:
<pre>
chop.prnt("foo")
chop.prnt("foo", "bar", "hello")
chop.prnt("The answer is: %s" % data)
</pre>

If you would like to mirror the functionality of python's print's ability to
supress the trailing '\n' added to output, you can do the following:
<pre>
chop.prnt("foo", None)
</pre>

To color the data (for gui purposes) just type:
<pre>
chop.prettyprnt("RED", "foo")
chop.prettyprnt("MAGENTA", "bar")
chop.prettyprnt("YELLOW", "bah", None)
</pre>

If you would like to support outputting json data, you can utilize chop.json to
do so:
<pre>
myobj = {'foo': ['bar', 'bah']}
chop.json(myobj)
</pre>

If you feel the need to make your own custom json encoder, you can use
"chop.set_custom_json_encoder(encoder_function)" to customize how the json will
be output.

Note that the default json encoder does not support any non standard types

File Saving
-----------
ChopShop provides a simple API for saving files using the chop.*file() family
of functions. There are three functions in this family:

<pre>
chop.savefile
chop.appendfile
chop.finalizefile
</pre>

The definition of chop.savefile() looks like:
<pre>
    def savefile(filename, data, finalize = True)
</pre>

To use chop.savefile() you provide the filename and the data. The optional
third argument (a boolean) is used to determine if the file object should be
kept open or closed. This allows you to do (pseudo-code):

<pre>
while (chunk_of_data = decode_some_data_from_pcap):
    if on_last_chunk:
        finalize = True
    else:
        finalize = False
    chop.savefile('foo', chunk_of_data, finalize)
</pre>

If not given, the default behavior is to close the file object. Since each file
object is opened in write mode module authors need to be aware of this behavior
as it will overwrite any existing files with the same name.

Similar to chop.savefile(), chop.appendfile() has the following definition:
<pre>
    def appendfile(filename, data, finalize = False)
</pre>

To use chop.appendfile() you provide the filename and the data. The optional
third argument (a boolean) is used to determine if the file object should be
kept open or closed. If not given, the default behavior is to leave the file
object open. Note, that unlike savefile, appendfile opens files in "append"
mode, so it will not overwrite any file that already exists.

The last function in the file family is chop.finalizefile() -- as the name
implies, it allows you to finalize (or close) a file once you are done with it.
It has the following definition:
<pre>
    def finalizefile(filename)
</pre>

If the filename given is not open, finalizefile will do nothing. Also note that
you can use savefile or appendfile to the same affect by calling them with an
empty string as the data and finalize set to True. E.g.:
<pre>
    chop.appendfile(filename, "", True)
    chop.savefile(filename, "", True)
</pre>

finalizefile gives you a shorter, quicker way to close the file that is easier
to see in code.

Note that as a module author you only provide the filename, <b>not</b> the full
path to the file you want created on disk. The full path is handled by the -s
argument to chopshop. For example:
<pre>
chopshop -f foo.pcap -s "/tmp/%N" "gh0st_decode -s; awesome_carver -s"
</pre>

This will make sure each carved file from gh0st_decode go into
/tmp/gh0st_decode and files from awesome_carver will go in /tmp/awesome_carver.
The other supported format string is "%T" which will be translated into the
current UNIX timestamp (/tmp/%N/%T would put files in
/tmp/module_name/timestamp).

Best Practices for Module Writing
=================================
Module writers should follow the best practices outlined below:

* Never use function calls that can adversely affect ChopShop or any other
  module.
* Calls like sys.exit() should not be used as your module might kill ChopShop
  or affect another module.
* Teardown your module so that other modules may continue processing.
* If it is possible to determine early on if a flow is useful, do so.
* Do not wait until teardown to examine a flow unless it is absolutely
  necessary.
* Transaction based communication might require processing in the teardown.
* Do not use globals, their usage and behavior can be unpredictable. Put them
  in module_data or stream_data where appropriate.
* Use the code available in ext_libs to reduce work and duplication.
* Do not roll your own code if it exists already.
* If you duplicate code often enough, take it out and put into the ext_libs.
* In the init if there's an error add a key 'error' to the dictionary you
  return to indicate there was an error and what the error is (error string).
* If your module parses arguments please use OptionParser() in your init()
  function (or a function unconditionally called from init) to do so. This
  allows the -m argument to chopshop to print the appropriate usage for your
  module.
* Never use any output functions like print or sys.stdout.write().
* If you can, use chop.prettyprnt to stylize the data so it's easier to see and
  keep track of in the gui.
