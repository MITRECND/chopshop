chopshop
========

Protocol Analysis/Decoder Framework

Description
===========
Chopshop is a MITRE developed framework to aid analysts in the creation and
execution of pynids based decoders and detectors of APT tradecraft.

Note that chopshop is still in beta and is dependant on libnids/pynids for the
majority of its underlying functionality.

Using Chopshop
==============
Chopshop consists of a python script that is run on the command line. It
requires Python 2.6+ and pynids to be installed[1]. It also requires "modules"
to be created that do the processing of network data. Chopshop, by itself, does
not do any processing of pcap data -- it provides the facilities for the
modules to do so.

[1]: There is a known issue when running chopshop on Ubuntu where the version
of pynids obtained via apt causes an ImportError.  Per
https://bugs.launchpad.net/ubuntu/+source/python-nids/+bug/795991, this issue
affects some variants of at least 11.10 and 12.04.  A workaround is to
compile pynids from source which can be obtained from
http://jon.oberheide.org/pynids/.

Chopshop provides the following arguments:

<pre>
usage: chopshop [options] ["bpf filter"] "list ; of ; modules"

options:
  -h, --help            show this help message and exit
  -B BASE_DIR, --base_dir=BASE_DIR
                        Base directory to load modules and external libraries from
  -E EXT_DIR, --ext_dir=EXT_DIR
                        Directory to load external libraries from
  -M MOD_DIR, --mod_dir=MOD_DIR
                        Directory to load modules from
  -f FILENAME, --file=FILENAME
                        input pcap file
  -l, --aslist          Treat filename as a file containing a list of files
  -L, --long            Read from filename forever even if there's no more
                        pcap data
  -i INTERFACE, --interface=INTERFACE
                        interface to listen on
  -m, --module_info     print information about module(s) and exit
  -G, --GMT             timestamps in GMT (tsprnt and tsprettyprnt only)
  -v, --version         print version and exit
  -g, --gui             Enable ChopShop Gui
  -S, --stdout          Explicitly enable output to stdout
  -F FILEOUT, --fileout=FILEOUT
                        Enable File Output
  -s SAVEDIR, --savedir=SAVEDIR
                        Location to save carved files
  -J JSONOUT, --jsonout=JSONOUT
                        Enable JSON Output
</pre>

Along with some basic command line options, chopshop requires the names of
modules it is supposed to run, semi-colon separated. By default chopshop will
look in the current working directory for a "modules" directory and search for
modules there.

Note that -F, -J, and -s require a formatted string that understands the
following variables:
<pre>
%N - the name of the module
%T - the current unix timestamp
%% - a literal '%'
</pre>

This enables files to be output to a location of the program invoker's
choosing, more info can be found below in the examples.

User Interface
==============
When invoked with the -g flag, Chopshop starts with a gui enabled. The GUI,
written in curses, will take over the entire screen and display information in
different windows. The following keys are recognized by the GUI:

<pre>
Left  or h: Cycles to the "left" window (the window above in the navigation window)
Right or l: Cycles to the "right" window (the window below in the navigation window)
Up    or k: Moves up one line in the data display window
Down  or j: Moves down one line in the data display window
PgDwn or J: Moves down 10 lines in the data display window
PgUp  or K: Moves up 10 lines in the data display window
         b: Moves to the beginning line in the data display window
         n: Moves to the end line in the data display window
         s: Toggles autoscroll for the given data display window -- default is True
         q: Quits the entire program -- generally, also clears the screen on exit
         Q: Quits the core -- leaves the UI up and running
</pre>

When moving around in the data window, remember to disable autoscroll or else
the window will return to the end of the data shortly.

Modules
=======
As mentioned, chopshop requires modules to do the bulk of its work. Modules
are, in essence, mini programs that do all of the grunt work to decode or
analyze traffic. More information on the creation of modules can be found
later.

To use a module, it must be in the modules directory and be given the proper
arguments (if required). All modules are capable of being given command line
arguments and module documentation should be referenced for proper invocation
requirements.

Example Use Cases
=================
Example 1
---------
As an example let's assume we have a pcap (/pcaps/netcat.pcap) which has
traffic that uses the netcat to access a remote shell. We can use the chopshop
module called "payloads" to dump the traffic. Someone trying to run chopshop
against this pcap would type:

<code>
chopshop -f /pcaps/netcat.pcap "host 192.168.1.10" "payloads -c -r"
</code>

The above invocation would run chopshop, load the payloads module, apply a BPF filter and run all traffic in the netcat.pcap file against the module.

Example 2
---------
As a second example, let's assume we have a pcap /pcaps/data.pcap which has
traffic that is either netcat traffic or could be gh0st traffic.  We're not
quite sure which one it is and would like to try both.  Someone trying to
analyze this data with chopshop would do:

<code>
chopshop -f /pcaps/data.pcap "payloads -c -r; gh0st_decode"
</code>

The above invocation would run chopshop, load both the payloads and
gh0st_decode modules and run all traffic in data.pcap through both. Both
modules would also retain their own information and not clobber each other in
the process.

Example 3
---------
Let's assume the same information as the above example but this time we would
like to output all data to the output directory in our current working
directory:

<code>
chopshop -F "output/%N.txt" -f /pcaps/data.pcap "payloads -c -r; gh0st_decode"
</code>

The above invocation would run chopshop, load both the payloads and
gh0st_decode modules and run all traffic in data.pcap through both.
Additionally, they would output all of their output to "output/payloads.txt"
and "output/gh0st_decode.txt" respectively.  Note that by using -F, output to
stdout is suppressed unless specifically invoked (by using -S).

Example 4
---------
Building upon the last example let's output the modules output to their own
directories and name each of the files after the module name and timestamp:

<code>
chopshop -F "output/%N/%N-%T.txt" -f /pcaps/data.pcap "payloads -c -r; gh0st_decode"
</code>

The above invocation would do the same thing as the above example but would
output data to "output/payloads/payloads-[timestamp].txt" and
"output/gh0st_decode/gh0st_decode-[timestamp].txt".

Processing multiple pcaps
=========================
All examples and use cases so far have only shown chopshop processing one pcap
at a time. Chopshop has the capability to process multiple pcaps in a few ways.
The easiest of which is to pipe their names into chopshop from the command
line:

<code>
find /pcaps -name "*.pcap" | sort | chopshop "host 192.168.1.10" "payloads -c -r"
</code>

Chopshop by default, if given no input information (-f or -i), will assume
there is a list of filenames being passed via stdin.

Example 5
---------
Chopshop can be used in a long running mode by using the -l and -L flags. These
flags make chopshop assume that the input file is a list of files it should
process and that it should continuously run until told to cancel (via Ctrl-C or
'Q' in the gui).

<code>
chopshop -f myfilelist -l -L "host 192.168.1.10" "payloads -c -r"
</code>

If 'myfilelist' is a fifo, we can feed it a list of files and have chopshop
process those files.

Module Development
==================
Introduction
------------
Creating chopshop modules consists of creating a python file with a unique name
and placing it in the modules directory. This file must have a .py extension in
order to be recognized by the framework.

newmod.sh
---------
Chopshop provides a shell script to setup a module stub for you. You can use
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

<b>discard(integer)</b> -- tells chopshop that this module wants to discard
"integer" bytes of the stream, same as in nids

<b>stop()</b> -- tells chopshop that this module no longer cares about
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

<b>stream_data</b> - dictionary that is passed back and forther and persists
data across the lifetime of a stream

<b>ip</b> - array of IP layer and payload. This may be removed in future
versions, do not rely upon it

The udp_data structure has the following functions:

<b>stop()</b> -- tells chopshop that this quad-tuple should be ignored for the
lifetime of the module

Variables
---------
Every module must define a global "moduleName" variable and populate it with
the module name -- this is mainly used for output purposes but is an absolute
requirement for every module.

Required Functions
------------------
###ALL MODULES
Modules must define the following functions to be used with chopshop:

<b>module_info()</b> -- invoked when a chopshop user uses the -m/--module_info
flag, module may print out any information it wants to inform the user of its
functionality/usage -- this is the only function that should use the standard
Python "print" command

<b>init(module_data)</b> -- Initialize the module, before processing any
packets.
  module_data is an dictionary with at least the following key(s):
    'args': an array of command-line args suitable to pass to
            the parse_args() function of an
            optparse.OptionParser() object.

  Returns: dictionary with at least the following key(s):
    'proto': must be set to 'tcp' or 'udp'.
    Optional: the return dictionary may also include:
        'error': indicates an error in the module has occured
                 set to a friendly string so that chopshop can
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
udp.stop() tells chopshop to ignore this quad-tuple for the lifetime of the
module. This is very different from TCP behavior, so be aware!

Optional Functions
------------------
Modules do not need to define the following functions but doing so provides
extra functionality or information.

<b>shutdown(module_data)</b> -- Called when the chopshop is shutting down;
gives the module one last chance to do what it needs to.

<b>teardown(tcp_data)</b> -- Called when a stream is closed (RST, etc.)
  Treat tcp_data like the object sent to callbacks for nids' register_tcp.
  (ex: o.addr, o.client.count_new, o.discard(0))

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

<b>NO methods should use python's regular "print" command '''except''' for
module.info().</b>

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
running chopshop, chop.prettyprnt's functionality is equivalent to chop.prnt.

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

For debug data type:
<pre>
chop.debug("Debug Data")
chop.debug("f value: % s" % f)
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

* Never use function calls that can adversely affect chopshop or any other
  module.
* Calls like sys.exit() should not be used as your module might kill chopshop
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
* Never use any output functions like print or sys.stdout.write(). The
 <b>only</b> exception is in module_info().
* If you can, use chop.prettyprnt to stylize the data so it's easier to see and
  keep track of in the gui.
