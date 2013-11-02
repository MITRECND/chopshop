Embedding ChopShop
==================

Starting with ChopShop 3.0 it is possible to embed the core of ChopShop aka,
ChopLib into other python programs. Before going into how to do this, here's a
quick overview of the design.

ChopShop, which refers to the overall project (and not the specific program
'chopshop') consists of disjointed pieces of code to accomplish its goals. The
chopshop program leverages these pieces to present to the user the ability to
analyze traffic more easily than would be done using manual processes. The
chopshop program has three pieces, specifically consisting of the core
library (ChopLib), a user interface (the chopshop program itself) and a
presentation layer (the ChopUi). The library and the ui are then tied together
using an interprocess message queue to pass messages.


Before getting into each of the three pieces, let's discuss that interprocess
message queue that was mentioned above. The queue is a one way queue that is
meant to send data from the library to whatever element on the other side is being
used for presentation. In chopshop, for example, ChopUi is consuming the
queue.

There are two high-level types of messages that are sent across the queue,
'Control' messages and 'Data' messages. All messages are python data objects.
Control messages have the following structure:

ctrl_message = { 'type' : 'ctrl',
                 'data' : { 'msg': 'X', 
                             other dependant on 'X'}
               }

    if 'X' == 'finished':
        'status': 'ok' | 'error'
    if 'X' == 'addmod':
        'name': "module name"
        'id'  : "module id"
    if 'X' == 'stop':
        no other elements

Data messages have the following format:

message = { 'type'   : 'txt'|'json'|'filedata'
            'module' : 'module name',
            'id'     : 'module id',
            'time'   : 'packet timestamp',
            'addr'   : TODO XXX FIXME,
            'proto'  : 'tcp'|'udp',
            'data'   : {type dependant data dictionary}
          }


    if 'type' == 'txt':
        'data' = { 'data' : 'string data',
                   'suppress' : True|False -- suppress the \n at the end of the line
                   'color' : 'Requested Color'
                 }
    if 'type' == 'json':
        'data' = { 'data' : 'string of json data'}

    if 'type' == 'filedata':
        'data' = { 'data' : data to output,
                   'mode' : requested write mode (w|a),
                   'finalize': True|False -- whether this is the final write and the file should be closed
                 }

The 'type' and 'data' fields are the only consistent names across all of
messages and any usage of a message should at the least check the type before
using it.


So now that we've looked at the message format, let's look at all three pieces 
and see how to embed them. We will be using the chopshop program as an example.


ChopLib:
ChopLib is the core of ChopShop, it does the actual handling of the modules
and all of the real work, if you want to embed ChopShop into a program, this
is more than likely what you'll want, at the least.

An instance of ChopLib is instantiated like any other python class:

<code>
#The following line assumes the shop is in your path
from ChopLib import ChopLib

choplib = ChopLib()
</code>

ChopLib has the following options:

mod_dir -- The directory to load modules from. Defaults to ChopShop's working
directory + /modules. If overriden will be relative to base_dir if set, if not
should be set to an absolute path
<default: CHOPSHOP_WD + '/modules/'>


ext_dir -- The directory to load external libraries from. Defaults to
ChopShop's working directory + /ext_libs. If overriden will be relative to
base_dir if set, if not should be set to an absolute path
<default: CHOPSHOP_WD + '/ext_libs/'>

base_dir -- The base directory to look for modules/ext_libs. By default this
is not set and is ignored
<default: None>

filename -- Pcap file to use as input
<default: ''>

filelist -- List of Pcap files to use as input
<default: None>

bpf -- The BPF filter to send to nids
<default: None>

aslist -- Whether to treat 'filename' as a list of files to read in
<default: False>

longrun -- Reads from input forever even if there's no data to read, useful
for reading from FIFO's
<default: False>

interface -- What interface to read from. This option has priority over
reading from a file
<default: ''>

modinfo -- This instance of the ChopLib should only read the module_info and
then exit
<default: False>

GMT -- Timestamps should be in GMT
<default: False>

savefiles -- If set to True, will enable ChopLib's saving of files
<default: False>

text -- If set to True, will enable ChopLib's hanlding of text data
<default: False>

jsonout -- If set to True, will enable ChopLib's handling of json data
<default: False>

savedir -- Sets the save directory for files carved by ChopLli
<default: '/tmp/'>

modules -- The list of modules that is going to be processed. This is
essentially what people type in at the commandline
<default: ''>


ChopLib has the following functions that are useful for embedding:

ChopLib.start() -- Kicks of ChopLib to start processing

ChopLib.finish() -- Should be called to properly kill intra-communication
channels

ChopLib.join() -- Inherited from Thread, should be called to properly join

The above functions are the ones used by chopshop but other functions are
available depending on what functionality is desired:

ChopLib.get_message_queue() -- returns the interprocess message queue that is
used for output

ChopLib.get_stop_fn() -- returns the stop function used to stop the Library

ChopLib.version() -- returns the version of ChopLib

ChopLib.setup_local_chop(name = "ChopShop", pid = -1) -- usually not needed
but allows the calling program (e.g., chopshp) to get its own local 'chop' library



ChopUi:

ChopUi is a wrapper around other functions and classes. It is designed to be
overridable and simple. By default, ChopUi will use the output handlers
available in ChopUiStd for all functionality but all of those handler can be
overriden by specifying an alternative object.

ChopUi has the following options:

ChopUi.stdout - Set to True to enable handling of output to stdout, set to an
Object to override the stdout handler.
<default: False>

ChopUi.gui - Set to True to enable hanlding of output to gui, set to an Object
to override the gui handler.
<default: False>

ChopUi.fileout - Set to True to enable handling of text output to a file, set to an
Object to override the handler.
<default: False>

ChopUi.filedir - Set to the format string to where the file should be saved
<default: None>

ChopUi.savefiles - Set to True to enable handling of file saving, set to an
Object to override the handler.
<default: False>

ChopUi.savedir - Set to the format string as to where to save files
<default: None>

ChopUi.jsonout - Set to True to enable handling of json output data, set to an
Object to override the handler.
<default: False>

ChopUi.jsondir - Set to a format string as to where to save json output data
<default: None>


The following functions are useful when using ChopUi:

ChopUi.start() - Kicks of the ui

ChopUi.bind(ChopLib_Instance) - 'Binds' a ChopLib instance to this ui instance

ChopUi.stop() - Stops the ui

A few other functions exist that shouldn't be needed for regular operations:

ChopUi.set_message_queue(message_queue) - Sets the message queue to be
consumed from -- called by ChopUi.bind()

ChopUi.set_library_stop_fn(lib_stop_fn) - Sets the library stop function --
called by ChopUi.bind()


Putting it together, we create a program like chopshop. As the glue chopshop
as the following responsibilities:

Parse all command line arguments
Handle reading from stdin if necesary
Handle signals
Setting up options to the library and ui
Starting the ui and the library
Cleaning up properly

Overriding UI handlers:
All Ui handlers need four functions to be defined to be callable by ChopUi:

Handler.__init__(ui_stop_fn, lib_stop_fn) -- This function will start up the
handler, giving it functions to stop either the Ui or the Library if
necessary. Most handlers will ignore those variables

Handler.handle_message(message) -- This function is meant to handle the data
messsage for the type it is. For example a stdout handler will only get 'txt'
messages and should never get 'json' messages

Handler.handle_ctrl(message) -- This function is meant to handle 'ctrl'
messages

Handler.stop() -- This function is called with ChopUi is ending and gives the
handler a chance to shutdown properly

To override the handler, you simply need to assign the handler you want to
override with the object you want to replace it. For example:


from ChopUi import ChopUi
chopui = ChopUi()
chopui.stdout = MyAwesomeStdoutHandler

As long as that object 'MyAwesomeStdoutHandler' has the four required
functions, it will be used without issue to handle any 'txt' data

