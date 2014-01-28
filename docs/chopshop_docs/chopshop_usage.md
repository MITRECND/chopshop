Using chopshop
==============
The chopshop program consists of a python script that is run on the command line. It
requires Python 2.6+ and pynids to be installed. It also requires "modules"
to be created that do the processing of network data. ChopShop, by itself, does
not do any processing of pcap data -- it provides the facilities for the
modules to do so.


The chopshop program provides the following arguments:

<pre>
Usage: chopshop [options] ["bpf filter"] "list ; of ; modules"

Options:
  -h, --help            show this help message and exit
  -B BASE_DIR, --base_dir=BASE_DIR
                        Base directory to load modules and external libraries
                        from
  -c CONFIGFILE, --configfile=CONFIGFILE
                        Import a config file
  -C SAVECONFIG, --saveconfig=SAVECONFIG
                        Save current arguments to a config file
  -E EXT_DIR, --ext_dir=EXT_DIR
                        Directory to load external libraries from
  -f FILENAME, --file=FILENAME
                        input pcap file
  -F FILEOUT, --fileout=FILEOUT
                        Enable File Output
  -g, --gui             Enable ChopShop Gui
  -G, --GMT             timestamps in GMT (tsprnt and tsprettyprnt only)
  -i INTERFACE, --interface=INTERFACE
                        interface to listen on
  -J JSONOUT, --jsonout=JSONOUT
                        Enable JSON Output
  -l, --aslist          Treat FILENAME as a file containing a list of files
  -L, --long            Read from FILENAME forever even if there's no more
                        pcap data
  -m, --module_info     print information about module(s) and exit
  -M MOD_DIR, --mod_dir=MOD_DIR
                        Directory to load modules from
  -s SAVEDIR, --savedir=SAVEDIR
                        Location to save carved files
  -S, --stdout          Explicitly enable output to stdout
  -t, --module_tree     print information about module tree and exit
  -v, --version         print version and exit

</pre>

Along with some basic command line options, chopshop requires the names of
modules it is supposed to run. By default chopshop will look in the current 
working directory for a "modules" directory and search for modules there.

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
When invoked with the -g flag, chopshop starts with a gui enabled. The GUI,
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
As mentioned, ChopShop requires modules to do the bulk of its work. Modules
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
traffic that uses the netcat to access a remote shell. We can use the ChopShop 
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
at a time. ChopShop has the capability to process multiple pcaps in a few ways.
The easiest of which is to pipe their names into chopshop from the command
line:

<code>
find /pcaps -name "*.pcap" | sort | chopshop "host 192.168.1.10" "payloads -c -r"
</code>

The chopshop by default, if given no input information (-f or -i), will assume
there is a list of filenames being passed via stdin.

Example 5
---------
The chopshop can be used in a long running mode by using the -l and -L flags. These
flags make chopshop assume that the input file is a list of files it should
process and that it should continuously run until told to cancel (via Ctrl-C or
'Q' in the gui).

<code>
chopshop -f myfilelist -l -L "host 192.168.1.10" "payloads -c -r"
</code>

If 'myfilelist' is a fifo, we can feed it a list of files and have chopshop
process those files.
