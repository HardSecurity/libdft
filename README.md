# `libdft`

Dynamic data flow tracking (DFT) deals with the tagging and tracking of
"interesting" data as they propagate during program execution. DFT has been
repeatedly implemented by a variety of tools for numerous purposes, including
protection from buffer overflow and cross-site scripting attacks, analysis of
legitimate and malicious software, detection and prevention of information
leaks, _etc._ `libdft` is a dynamic DFT framework that is at once _fast_,
_reusable_, and works with _commodity_ software and hardware. It provides an
API, which can be used to deliver DFT-enabled tools that can be applied on
unmodified binaries running on common operating systems and hardware, thus
facilitating research and rapid prototyping.

Further information about the design and implementation of `libdft` can be
found in our [paper](./libdft_vee2012.pdf), presented at [VEE 2012](https://dl.acm.org/toc/sigplan/2012/47/7).

```
@inproceedings {libdft_vee2012,
	title		= {{libdft: Practical Dynamic Data Flow Tracking for
				Commodity Systems}},
	author		= {Kemerlis, Vasileios P. and Portokalidis, Georgios
				and Jee, Kangkook and Keromytis, Angelos D.},
	booktitle	= {ACM SIGPLAN/SIGOPS Conference on Virtual Execution
				Environments (VEE)},
	pages		= {121--132},
	year		= {2012}
}
```


## Installation

`libdft` relies on Pin (http://www.intel.com/software/pintool), which is a
dynamic binary instrumentation (DBI) framework from Intel. In order to install
`libdft` you first need a working copy on the latest Pin build, as well as the
essential build tools for GNU/Linux (GCC, GNU Make, _etc._). After downloading
and installing Pin please follow the instructions in the [`INSTALL`](./INSTALL)
file, in order to finish the installation of `libdft`.


## Tools

`libdft` is designed to facilitate the creation of "Pintools" that employ
dynamic DFT. As the name implies, `libdft` is also a shared library, which can
be used to transparently perform DFT on binaries. Additionally, it provides an
API that enables tool authors to adjust the applied DFT by specifying data
sources and sinks, and customize the tag propagation policy. We have included
_three_ simple Pin tools inside the `tools/` subdirectory to aid the
development of DFT-powered Pintools. The first is `nullpin`, which is
essentially a `null` tool that runs a process using Pin without any form of
instrumentation or analysis. This tool can be used to measure the overhead
imposed by Pin's runtime environment. The second uses `libdft` to apply DFT on
the application being executed, but does not use any of the API functions to
define data sources and sinks (_i.e.,_ it does not customize the applied DFT).
The name of this tool is `libdft`, and similarly to the previous case it can be
used to evaluate the overhead imposed by `libdft`. Finally, the third tool,
namely `libdft-dta`, is used in order to illustrate the API of `libdft`, and
serves as template for future meta-tools. In particular, it implements a
dynamic taint analysis (DTA) platform by transparently utilizing DFT in
unmodified x86 Linux binaries.

DTA operates by tagging all data coming from the network as "tainted", tracking
their propagation, and alerting the user when they are used in a way that could
compromise his system. In this case, the network is the source of "interesting"
data, while instructions that are used to control a program's flow are the
sinks. For the x86 architecture, these are `jmp` and `call` instructions with
non-immediate operands, as well as `ret` instructions. Oftentimes, attackers
are able to manipulate the operands of such instructions by abusing various
types of software memory errors such as buffer overflows, format string
vulnerabilities, dangling pointers, _etc._ They can then seize control of a
program by redirecting execution to existing code (_e.g.,_ return-to-libc,
ROP), or their own injected instructions. `libdft-dta` checks if tainted data
are used in indirect control transfers, and if so, it halts execution with an
informative message containing the offending instruction and the contents of
the instruction pointer.


## Usage

After building both `libdft` and the accompanying tools (_i.e.,_ `nullpin`,
`libdft`, and `libdft-dta`), you can apply them directly in unmodified x86
Linux binaries as follows (assuming that Pin in installed in `/usr/src/pin`,
and `libdft` in your local home directory):

```
 /usr/src/pin/pin -follow_execv -t ~/libdft/tools/nullpin.so -- <executable>
```

  a. `-follow_execv` command-line switch is used in order to execute all
     processes spawned by the `exec(3)` class system calls with Pin.

  b. `-t` command-line switch specifies the corresponding tool.

`nullpin` and `libdft` are dummy tools and hence they take no arguments.
However, in `libdft-dta` you can specify the file that logs alerts and policy
violations by using the `-l` command-line switch after the tool name and before
`--`.  Additionally, `-s [0|1]`, `-f [0|1]`, and `-n [0|1]` disable/enable
`stdin`, files, and network I/O channels as taint sources.


## License

This software uses the [BSD License](./LICENSE).
