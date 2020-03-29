Installation of SSLyze
######################

This part of the documentation covers the installation of SSLyze.

SSLyze can be installed on the following platforms:

* Windows 10 (64 bits)
* macOS Catalina
* Linux (x86 and x86-64)

Other platforms (such as ARM-based platforms) are not supported.

Using pip
*********

To install SSLyze, simply run this simple command in your terminal of choice::

    $ pip install --upgrade setuptools
    $ pip install sslyze

Using the source code
*********************

SSLyze is actively `developed on GitHub <https://github.com/nabla-c0d3/sslyze>`_.

You can clone the public repository::

    $ git clone git://github.com/nabla-c0d3/sslyze.git

Once you have a copy of the source, you can embed it in your own Python
package, or install it into your site-packages easily::

    $ cd sslyze
    $ pip install .

Using the Windows executable
****************************

A pre-compiled Windows executable is available in
`the Releases page of the GitHub project <https://github.com/nabla-c0d3/sslyze/releases>`_.

This executable only gives access to the command line interface and does not allow using SSLyze's Python API.

Using Docker
************

`Warning: Docker support is experimental.`

By default, the Docker image runs SSLyze with the `-h` flag::

    $ docker run --rm -it nablac0d3/sslyze

    Usage: sslyze [options] target1.com target2.com:443 target3.com:443{ip} etc...
     Options:
      --version             show program's version number and exit
      -h, --help            show this help message and exit


The image is intended to be run as an executable like so::

    $ docker run --rm -it nablac0d3/sslyze --regular www.github.com:443

You can create an alias for it by adding the following line to your shell's rc file (e.g. ~/.bashrc)::

    $ alias 'sslyze'='docker run --rm -it nablac0d3/sslyze'
    $ source ~/.bashrc
    $ sslyze
