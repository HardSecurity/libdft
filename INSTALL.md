# Installation Instructions

Copyright (C) 2015-2022, Brown University, Secure Systems Lab.  
Copyright (C) 2010-2015, Columbia University.

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved. This file is offered as-is,
without warranty of any kind.


## Installation

   The simplest way to compile this package is the following:

  1. Extract the latest Pin build. Assuming that it was extracted in
     `/usr/src/pin`, we shall refer to that path as Pin's root path
      from now on.

  2. Type `export PIN_HOME=/usr/src/pin` to set the environment
     variable `PIN_HOME` to the root path of Pin.  
     Replace `/usr/src/pin` with *your* root path.

  3. `cd` to the directory `src/`, which contains the source code of `libdft`,
     and type `make` to compile the package (_i.e.,_ the `libdft` library).  
     NOTE: use `Makefile.old` if your Pin version is v2.12-55942 of older.

  4. `cd` to the directory `tools/` and type `make tools` to compile the
     accompanying tools (_e.g.,_ `nullpin`, `libdft`, `libdft-dta`, _etc._).  
     NOTE: use `Makefile.old` if your Pin version is v2.12-55942 of older.

  5. You can remove the program binaries and object files from `src/`
     and `tools/` by typing `make clean` on the respective directory.


## Compilers and Options

Tested with gcc/g++ 4.4.x on Debian GNU/Linux v6 (squeeze),
Debian GNU/Linux v5 (lenny), and Ubuntu v10.04.1 LTS (Lucid Lynx).
