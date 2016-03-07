Welcome to ChopShop's documentation!
====================================

ChopShop Documentation
----------------------

Contents:

.. toctree::
   :maxdepth: 2

   chopshop/installation
   chopshop/chopshop_usage
   chopshop/chopweb_usage
   chopshop/data_structures
   chopshop/embedding_chopshop
   chopshop/module_authoring
   chopshop/core_development

Module Documentation
--------------------

.. toctree::
   :maxdepth: 2
   :glob:

   modules/*

Glossary
--------

.. glossary::

   chopshop
      (styled with all lower case) the command line program 'chopshop'.  For
      more information, see :ref:`chopshop-cli`.

   ChopShop
      (Styled with a capital "C" and capital "S") the entire project, including
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

   library
   ChopShop Library
   ChopLib
      the central processing code in ChopShop.  Implemented in
      ``shop/ChopLib.py``

   module
      an extension to ChopShop, used to handle a particular type of network
      traffic data.  A module can be further classified as either a
      :term:`primary module` or a :term:`secondary module`.

   primary module
      a ChopShop module that handles one of ChopShop's core data types (TCP,
      UDP, or IP)

   secondary module
      a ChopShop module that handles a non-core data type defined by another
      module; any Chopshop module that is not a :term:`primary module`.  For
      example, a module that handles ``http`` data is a secondary module.

   Ui
   ChopShop Ui Handler Library
   ChopUi
      the code used to isolate modules from particular output facilities (such
      as the terminal, web, or files).  Modules write their data to a queue;
      the data is consumed by the ChopUi component and output according to how
      ChopShop was invoked.  Implemented in ``shop/ChopUi.py``


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

