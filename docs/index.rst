Welcome to ChopShop's documentation!
====================================

Terminology
-----------

Usage of ChopShop terminology and capitalization has been a bit
confusing and so the developers have created a set of standards as to
how to reference ChopShop and its different pieces.

-  ChopShop - References the project as a whole and all of its pieces
-  chopshop - References the command line program 'chopshop'
-  The core - References the main libraries that make up ChopShop, also
   sometimes called the 'shop'
-  The Library - References the ChopShop Library, i.e., ChopLib located
   in the shop
-  The Ui - References the ChopShop Ui Handler Library, i.e., ChopUi
   located in the shop
-  Primary Module - References a module that ingests the core types that
   ChopShop supports, namely 'tcp', 'udp', and 'ip'
-  Secondary Module - References a module that ingests non-core types
   that are primary or secondary module defined, e.g., 'http'

ChopShop Documentation
----------------------

Contents:

.. toctree::
   :maxdepth: 2

   chopshop/installation
   chopshop/chopshop_usage
   chopshop/chopweb_usage
   chopshop/embedding_chopshop
   chopshop/module_authoring
   chopshop/core_development

Module Documentation
--------------------

.. toctree::
   :maxdepth: 2
   :glob:

   modules/*

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

