"""
This is a skeleton file that can serve as a starting point for a Python
console script. To run this script uncomment the following lines in the
``[options.entry_points]`` section in ``setup.cfg``::

    console_scripts =
         fibonacci = security_ghost.skeleton:run

Then run ``pip install .`` (or ``pip install -e .`` for editable mode)
which will install the command ``fibonacci`` inside your current environment.

Besides console scripts, the header (i.e. until ``_logger``...) of this file can
also be used as template for Python modules.

Note:
    This file can be renamed depending on your needs or safely removed if not needed.

References:
    - https://setuptools.pypa.io/en/latest/userguide/entry_point.html
    - https://pip.pypa.io/en/stable/reference/pip_install
"""

import argparse
import logging
import sys
from lib.library import am_i_online, get_current_mac, change_mac_linux, get_random_mac
from security_ghost import __version__

__author__ = "Aaron Wilmoth"
__copyright__ = "Aaron Wilmoth"
__license__ = "MIT"
# __version__ = "0.1.0"

_logger = logging.getLogger(__name__)


# ---- Python API ----
# The functions defined in this section can be imported by users in their
# Python scripts/interactive interpreter, e.g. via
# `from security_ghost.skeleton import fib`,
# when using this Python module as a library.


def fib(n):
    """Fibonacci example function

    Args:
      n (int): integer

    Returns:
      int: n-th Fibonacci number
    """
    assert n > 0
    a, b = 1, 1
    for _i in range(n - 1):
        a, b = b, a + b
    return a


# ---- CLI ----
# The functions defined in this section are wrappers around the main Python
# API allowing them to be called directly from the terminal as a CLI
# executable/script.


def parse_args(args):
    """Parse command line parameters

    Args:
      args (List[str]): command line parameters as list of strings
          (for example  ``["--help"]``).

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """

    parser = argparse.ArgumentParser(description="Security Ghost Version")
    parser.add_argument(
        "--version",
        action="version",
        version=f"security_ghost {__version__}",
    )
    parser.add_argument(
        "--socks",
        required=True,
        dest="socks_config",
        help="socks proxy config file path",
        type=str,
        metavar="SOCKS_PATH",
    )
    parser.add_argument(
        "--vpn",
        required=True,
        dest="vpn_config",
        help="VPN config file path",
        type=str,
        metavar="VPN_PATH",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="loglevel",
        help="set loglevel to INFO",
        action="store_const",
        const=logging.INFO,
    )
    parser.add_argument(
        "-vv",
        "--very-verbose",
        dest="loglevel",
        help="set loglevel to DEBUG",
        action="store_const",
        const=logging.DEBUG,
    )
    return parser.parse_args(args)


def setup_logging(loglevel):
    """Setup basic logging

    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(
        level=loglevel, stream=sys.stdout, format=logformat, datefmt="%Y-%m-%d %H:%M:%S"
    )


def main(args):
    """Wrapper allowing :func:`fib` to be called with string arguments in a CLI fashion

    Instead of returning the value from :func:`fib`, it prints the result to the
    ``stdout`` in a nicely formatted message.

    Args:
      args (List[str]): command line parameters as list of strings
          (for example  ``["--verbose", "42"]``).
    """
    args = parse_args(args)
    print(args)
    setup_logging(args.loglevel)
    # _logger.debug("Starting crazy calculations...")
    # print(f"The {args.n}-th Fibonacci number is {fib(args.n)}")
    # _logger.info("Script ends here")
    print(am_i_online())
    if am_i_online():
        _logger.info("*You are online*")
    current_mac = get_current_mac("en0")
    print("[+] Current Mac :" + current_mac)
    change_mac_linux("en0", "000E04DB5F02")
    current_mac = get_current_mac("en0")

    if current_mac == get_random_mac():
        print("[+] Mac address was successfully changed to  :" + current_mac)
    else:
        print("[-] Mac address did not get changed .")


def run():
    """Calls :func:`main` passing the CLI arguments extracted from :obj:`sys.argv`

    This function can be used as entry point to create console scripts with setuptools.
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    # ^  This is a guard statement that will prevent the following code from
    #    being executed in the case someone imports this file instead of
    #    executing it as a script.
    #    https://docs.python.org/3/library/__main__.html

    # After installing your project with pip, users can also run your Python
    # modules as scripts via the ``-m`` flag, as defined in PEP 338::
    #
    #     python -m security_ghost.skeleton --socks socks.conf --vpn wireguard.conf
    #
    run()
    # print(sys.argv)
    # security-ghost --socks socks.conf --vpn wireguard.conf --dns cloudflare
