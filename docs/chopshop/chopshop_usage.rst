.. _chopshop-cli:

chopshop - command line interface to ChopShop
=============================================

The ``chopshop`` program is a Python script designed to be run on the
command line. It requires Python 2.6+ and pynids to be installed. It
also requires "modules" to be created that do the processing of network
data. ChopShop, by itself, does not do any processing of pcap data -- it
provides the facilities for the modules to do so.

.. raw:: html

   <pre>
   Usage: chopshop [options] ["bpf filter"] "list | (of, many) | modules ; and | more"

   ChopShop is a MITRE created utility to aid analysts in decoding network
   traffic

   Options:
     -h, --help            show this help message and exit
     -B BASE_DIR, --base_dir=BASE_DIR
                           Base directory to load modules and external libraries
                           from. Option prioritized over -M and -E
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

Along with some basic command line options, chopshop requires the names
of modules it is supposed to run. By default chopshop will look in the
current working directory for a "modules" directory and search for
modules there.

Note that -F, -J, and -s require a formatted string that understands the
following variables:

.. raw:: html

   <pre>
   %N - the name of the module
   %T - the current unix timestamp
   %% - a literal '%'
   </pre>

This enables files to be output to a location of the program invoker's
choosing, more info can be found below in the examples.

Quick Start
-----------

See the :ref:`installation` instructions if you haven't already installed
ChopShop.


User Defined Directories
------------------------

Users have the option to override the default directories ChopShop uses
to look for modules and external libraries. ChopShop provides three
options to override default values. The first is called the base
directory, the argument flag for this in chopshop is -B or --base\_dir.
This parameter takes a path or comma separated list of paths to look for
both modules and external libraries (ext\_libs). So if you pass
"/usr/local/chopshop-partner" as the base directory, ChopShop would
assume the 'modules' directory and the 'ext\_libs' directory are located
in that directory (e.g, '/usr/local/chopshop-partner/modules'). The
other two options are -M or --mod\_dir and -E or --ext\_dir. Both allow
you to individually override the location of modules or external
libraries as desired. For example, if you only need to override the
default location of modules but are okay with the default location of
external libraries, you can pass "-M
'/usr/local/chopshop-partner/modules/'" as an argument which will tell
ChopShop to look in that directory for modules.

The behavior of these parameters allows you to specify multiple
directories which will be checked be in priority order. ChopShop will
also append the default path to the list automatically so if nothing is
found in the list given by the user it will fall back to the built-in
paths. Taking the example for base\_dir from above, if a user passes
"/usr/local/chopshop-partner" as the new base, if, as an example, that
base directory didn't contain the gh0st decoder, ChopShop will
automatically search the default path after failing to find the module
in the path specified at command-line. To specify multiple directories
on the commandline comma separate the paths (e.g.,
"/usr/local/chopshop-development,/usr/local/chopshop-partner"). Again,
as mentioned, ChopShop will automatically append the default path to the
end so adding it is not necessary.

Configuration Files
-------------------

The chopshop program provides two relevant flags that allow you to
create and consume configuration files to aid in configuring your
environment so you don't have to repeatedly pass the same flags. To
create a configuration file based on the given command-line arguments
just pass the -C flag to chopshop with a destination filename. Then to
consume that config file just use -c and chopshop will parse the given
configuration file. Further, chopshop will check for a default file in
the user's home directory, called .chopshop.cfg for default config
parameters. For users who often use the -B or -M/-E parameters this
should save them some time. Note that config files passed at the
commandline override any config parameters found in .chopshop.cfg and
command line args override paramters from config files.

User Interface
--------------

When invoked with the -g flag, chopshop starts with a gui enabled. The
GUI, written in curses, will take over the entire screen and display
information in different windows. The following keys are recognized by
the GUI:

.. raw:: html

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

When moving around in the data window, remember to disable autoscroll or
else the window will return to the end of the data shortly.

Modules
-------

As mentioned, ChopShop requires modules to do the bulk of its work.
Modules are, in essence, mini programs that do all of the grunt work to
decode or analyze traffic. More information on the creation of modules
can be found in other documents.

To use a module, it must be accessible in the modules directory (or
directories) and be given the proper arguments (if required). All
modules are capable of being given command line arguments and module
documentation should be referenced for proper invocation requirements.

Example Use Cases
-----------------

Example 1
~~~~~~~~~

As an example let's assume we have a pcap (/pcaps/netcat.pcap) which has
traffic that uses the program netcat to access a remote shell. We can
use the ChopShop module called "payloads" to dump the traffic. Someone
trying to run chopshop against this pcap would type:

 chopshop -f /pcaps/netcat.pcap "host 192.168.1.10" "payloads"

The above invocation would run chopshop, load the payloads module, apply
a BPF filter and run all traffic in the netcat.pcap file against the
module.

Example 2
~~~~~~~~~

As a second example, let's assume we have a pcap /pcaps/data.pcap which
has traffic that is either netcat traffic or could be gh0st traffic.
We're not quite sure which one it is and would like to try both. Someone
trying to analyze this data with chopshop would do:

 chopshop -f /pcaps/data.pcap "payloads; gh0st\_decode"

The above invocation would run chopshop, load both the payloads and
gh0st\_decode modules and run all traffic in data.pcap through both.
Both modules would also retain their own information and not clobber
each other in the process. Ideally, you will know what traffic is in a
pcap before you run it through chopshop, so this example is a little
contrived, but running multiple modules on a pcap can come in handy in
some situtations.

Example 3
~~~~~~~~~

Let's assume the same information as the above example but this time we
would like to output all data to the output directory in our current
working directory:

    chopshop -F "output/%N.txt" -f /pcaps/data.pcap "payloads; gh0st\_decode"

The above invocation would run chopshop, load both the payloads and
gh0st\_decode modules and run all traffic in data.pcap through both.
Additionally, they would output all of their output to
"output/payloads.txt" and "output/gh0st\_decode.txt" respectively. Note
that by using -F, output to stdout is suppressed unless specifically
invoked (by using -S) so there would be nothing printed out to the
screen.

Example 4
~~~~~~~~~

Building upon the last example let's output the modules output to their
own directories and name each of the files after the module name and
timestamp:

    chopshop -F "output/%N/%N-%T.txt" -f /pcaps/data.pcap "payloads; gh0st\_decode"

The above invocation would do the same thing as the above example but
would output data to "output/payloads/payloads-[timestamp].txt" and
"output/gh0st\_decode/gh0st\_decode-[timestamp].txt".

Example 5
~~~~~~~~~

chopshop can be used in a long running mode by using the -l and -L
flags. These flags make chopshop assume that the input file is a list of
files it should process and that it should continuously run until told
to cancel (via Ctrl-C or 'Q' in the gui).

    chopshop -f myfilelist -l -L "host 192.168.1.10" "payloads"

If 'myfilelist' is a fifo, we can feed it a list of files and have
chopshop process those files.

Example 6
~~~~~~~~~

Module chaining is achieved by using the pipe (\|) character. An example
using the provided http and http\_extractor modules would look like:

    chopshop -f foo.pcap "http \| http\_extractor"

The above invocation, assuming there is http data in foo.pcap, would
would be processed by http, which would then pass on data to
http\_extractor. The http\_extractor module would then print out the
data it finds.

Example 7
~~~~~~~~~

ChopShop also supports tees and reverse tees using parens and commas
allowing you to feed the output of a module to multiple modules or vice
versa. A simple example follows below. Note that a child module (any
module on the right hand side of a pipe) needs to be able to accept the
types of data that the parents are creating or a warning will be
displayed to the screen.

    chopshop -f malware.pcap "(dns, icmp) \| malware\_detector"

Processing multiple pcaps
~~~~~~~~~~~~~~~~~~~~~~~~~

All examples and use cases so far have only shown chopshop processing
one pcap at a time. ChopShop has the capability to process multiple
pcaps in a few ways. The easiest of which is to pipe their names into
chopshop from the command line:

    find /pcaps -name "\*.pcap" \| sort \| chopshop "host 192.168.1.10" "payloads"

chopshop by default, if given no input information (-f or -i), will
assume there is a list of filenames being passed via stdin.
