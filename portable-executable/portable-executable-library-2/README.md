# PE Bliss #

### Cross-Platform Portable Executable C++ Library ###

Compatible with Windows and Linux (tested on MSVC++ 2008, 2010, GCC 4.4 on Linux). Currently tested on little-endian systems only and might not support big-endian ones.

Library has many usage samples and is well unit-tested.

_Library is free to use in both commertial and non-commertial projects. You can also modify and redistribute it. If you are using it, please, do not forget to specify the name or other copyright of PE Bliss somewhere in the description of your project._



---


**A huge update is coming soon!** Possible new features of the future update:

  * more high-level classes and functions to work with PE resources;

  * high-level .NET PE parsing (metadata tables, signatures, resources);

  * C++/CLI wrapper, which allows .NET developers to use the library in C# or VB.NET projects;

  * more samples and tests;

  * bugfixes.



---


**Current version: 1.0.0**

### Summary ###

[+] Read 32- and 64-bit PE files (PE, PE+) for Windows, work similar with both formats

[+] Create PE/PE+ binaries from scratch

[+] Rebuild 32- and 64-bit PE files

[+] Work with directories and headers

[+] Convert addresses

[+] Read and write PE sections

[+] Read and write imports

[+] Read and write exports (forwarders supported)

[+] Read and write relocations

[+] Read and write resources

[+] Read and write TLS (including callbacks and raw data)

[+] Read and write image config (including SE Handlers and Lock Prefix addresses)

[+] Read basic .NET information

[+] Read and write bound imports

[+] Read exception directory (PE+ only)

[+] Read debug directory and extended debug information

[+] Calculate entropy

[+] Change file alignment

[+] Change base address

[+] Work with DOS Stub and Rich overlay

[+] High-level resource reading: bitmaps, icons, cursors, version info, string and message tables

[+] High-level resource editing: bitmaps, icons, cursors, version info



Library doesn't use WinAPI and doesn't execute PE files, so it's safe to use it with suspicious binaries.



---

[Author's blog](http://kaimi.ru/)
