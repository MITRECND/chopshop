Developing ChopShop Core
========================

This page contains information for developers seeking to modify or extend
ChopShop's core.  If you are looking for information on developing ChopShop
modules, see :ref:`module_authoring`.


Setting up the development environment
--------------------------------------

#. Clone the ChopShop repository.
#. Follow ChopShop's :ref:`installation` instructions as normal (in a
   virtualenv, if you would like).
#. Run ``pip install -r dev-requirements.txt`` to install additional
   dependencies needed to develop ChopShop's core.

Testing and Code Coverage
-------------------------

To run tests, including a coverage report, run a command like::

    py.test --cov=shop/ChopGrammar.py --cov-report=html

Once other modules are tested, you can expand the ``--cov`` argument to include
more files.
