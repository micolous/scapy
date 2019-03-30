# crcmod

This is a modified version of crcmod-1.7 Python 3 version (released 2010).

It has the following modifications for Scapy:

* The C/C++ versions of the module have been removed
* Code generation for C/C++ has been removed
* It has been adapted to use Scapy's version of six, and some of Scapy's py2/3
  compatibility helpers
* Most PEP-8 issues have been resolved
* Support for `array.array` types was removed (for Python 2 compatibility)
* Many pre-defined names added to `crcmod.__init__`
* Unit tests run in `UTscapy` (see `test/crcmod.uts`)

This modified code is available under the original terms of crcmod (BSD-like
license).
