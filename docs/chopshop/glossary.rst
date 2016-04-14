ChopShop Glossary
=================

This page contains definitions for terms used within this documentation and the
ChopShop code. Several terms have been used inconsistently in the past; this
page is an attempt at consistency.

.. glossary::

   chopshop
      (styled with all lower case) the command line program 'chopshop'.  For
      more information, see :ref:`chopshop-cli`.

   ChopShop
      (styled with a capital "C" and capital "S") the entire project, including
      the core, external libraries, modules, and user interfaces.

   core
   shop
   ChopShop Core
      the code that makes up the basic functionality of ChopShop.  These files
      are located in the ``shop/`` directory, so this code is also referred to
      as the ``shop``.

   external libraries
      code that modules can import for additional functionality.  Code in the
      ChopShop Core should not use external libraries, and modules should not
      import code from other modules, so this is primarily for code that is
      shared between multiple modules.

   external libraries directory
      the directory which ChopShop searches for external_libraries.  Any code
      in this directory is available for modules to import. Libraries used by
      built-in modules are located in the ``ext_libs/`` directory in the root
      directory of the project; this is the default used by the ``chopshop``
      program, but can be modified with the `-E` command-line flag.

   library
   ChopShop Library
   ChopLib
      the central processing code in ChopShop.  Implemented in
      ``shop/ChopLib.py``

   module
      an extension to ChopShop, used to handle a particular type of network
      traffic data.  A module can be further classified as either a
      :term:`primary module` or a :term:`secondary module`.

   modules directory
      the directory which ChopShop searches for modules.  Built-in modules are
      located in the ``modules/`` directory in the root directory of the
      project; this is the default used by the ``chopshop`` program, but can be
      modified with the `-M` command-line flag.

   primary data type
      TCP, UDP, or IP packet data. These data types are defined by libnids. The
      first module in any chain must be able to handle one of the primary data
      types.

   primary module
      a ChopShop module that handles one of ChopShop's
      :term:`primary data type` s. A primary module should be first in any
      module chain.

   secondary data type
      any type of data that is not a :term:`primary data type`. Examples
      include ``http`` and ``dns`` data.

   secondary module
      a ChopShop module that handles a :term:`secondary data type` defined by
      another module; any Chopshop module that is not a :term:`primary module`.
      For example, a module that handles ``http`` data is a secondary module.

   Ui
   ChopShop Ui Handler Library
   ChopUi
      the code used to isolate modules from particular output facilities (such
      as the terminal, web, or files).  Modules write their data to a queue;
      the data is consumed by the ChopUi component and output according to how
      ChopShop was invoked.  Implemented in ``shop/ChopUi.py``
