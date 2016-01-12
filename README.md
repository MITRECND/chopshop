ChopShop 4
========

Protocol Analysis/Decoder Framework

Description
===========
ChopShop is a MITRE developed framework to aid analysts in the creation and execution of pynids based decoders and detectors of APT tradecraft.

Note that ChopShop is still in perpetual beta and is dependent on libnids/pynids for the majority of its underlying functionality.

Documentation has been moved to the docs folder. Please reference that folder for information such as:
- Chopshop Usage
- Module Authoring
- Embedding Chopshop


Note: There is a known issue when running ChopShop on Ubuntu where the version of pynids obtained via apt causes an ImportError.  Per https://bugs.launchpad.net/ubuntu/+source/python-nids/+bug/795991, this issue affects some variants of at least 11.10 and 12.04.  A workaround is to compile pynids from source which can be obtained from https://github.com/MITRECND/pynids/.
