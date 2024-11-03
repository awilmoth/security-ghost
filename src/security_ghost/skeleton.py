import argparse
import logging
import sys
import requests
import socks
from python_wireguard import Key, Client, ServerConnection
from lib.library import (
    am_i_online,
    get_current_mac,
    change_mac_linux,
    get_random_mac,
    get_primary_network_interface,
    setup_wireguard_interface,
    parse_wireguard_conf,
    route_ssh_via_primary_network_interface,
    unpack_wireguard_config,
    check_wireguard_installed,
    load_wireguard_module,
    parse_socks_config,
    get_current_mac,
    change_mac_linux,
    setup_encrypted_dns,
    TunneledHTTPAdapter,
    cleanup_connection,
)
from security_ghost import __version__
from requests.adapters import HTTPAdapter
import socket
import subprocess
import os


__author__ = "Aaron Wilmoth"
__copyright__ = "Aaron Wilmoth"
__license__ = "MIT"

_logger = logging.getLogger(__name__)


def parse_args(args):
    """Parse command line parameters

    Args:
      args (List[str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(description="Security Ghost")
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Up command
    up_parser = subparsers.add_parser('up', help='Bring up the secure connection')
    up_parser.add_argument(
        "--vpn",
        required=True,
        dest="vpn_config",
        help="VPN config file path",
        type=str,
        metavar="VPN_PATH",
    )
    up_parser.add_argument(
        "--socks",
        required=True,
        dest="socks_config",
        help="socks proxy config file path",
        type=str,
        metavar="SOCKS_PATH",
    )
    up_parser.add_argument(
        "--change_mac",
        dest="change_mac",
        choices=["yes", "no"],
        default="yes",
        help="Enable/disable MAC address changing (default: yes)",
    )
    up_parser.add_argument(
        "--dns",
        choices=["quad9", "cloudflare"],
        default="quad9",
        help="Choose DNS provider for encrypted DNS (default: quad9)"
    )

    # Down command
    down_parser = subparsers.add_parser('down', help='Bring down the secure connection')

    # Add version and verbosity arguments to the main parser
    parser.add_argument(
        "--version",
        action="version",
        version=f"security-ghost {__version__}",
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
    parser.set_defaults(loglevel=logging.WARNING)

    return parser.parse_args(args)


def setup_logging(loglevel):
    """Setup basic logging

    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(
        level=loglevel,
        stream=sys.stdout,
        format=logformat,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

def main(args):
    args = parse_args(args)
    setup_logging(args.loglevel)

    if args.command == 'down':
        interface = get_primary_network_interface()
        if interface:
            cleanup_connection(interface)
        return

    elif args.command == 'up':
        print(f"Using VPN config: {args.vpn_config}")
        print(f"Using SOCKS config: {args.socks_config}")
        if am_i_online():
            print("[+] System is online")
        else:
            print("[-] System is not online")
            return
        if args.change_mac == "yes":
            interface = get_primary_network_interface()
            if not interface:
                print("[-] Could not detect primary network interface")
                return

            print(f"[+] Detected primary interface: {interface}")
            current_mac = get_current_mac(interface)
            print(f"[+] Current MAC: {current_mac}")
            new_mac = get_random_mac()
            change_mac_linux(interface, new_mac)
            current_mac = get_current_mac(interface)
            if current_mac == new_mac:
                print(f"[+] MAC address was successfully changed to: {current_mac}")
            else:
                print("[-] MAC address did not get changed.")
        else:
            print("[*] MAC address changing is disabled")

        # Setup encrypted DNS
        if not setup_encrypted_dns(args.dns):
            print("[-] Failed to setup encrypted DNS")
            return

        # Read SOCKS configuration
        socks_config = parse_socks_config(args.socks_config)

        with requests.Session() as session:
            sock = socks.socksocket()
            proxy_type = getattr(socks, socks_config["type"])
            sock.setproxy(
                proxy_type,
                socks_config["host"],
                socks_config["port"],
                True,
                socks_config["username"],
                socks_config["password"],
            )
            session.mount("http://", TunneledHTTPAdapter(sock))
            session.mount("https://", TunneledHTTPAdapter(sock))
            # Get the IP address when using SOCKS proxy
            socks_ip = session.get('https://httpbin.org/ip').json()['origin']
            
            # Get IP of primary interface
            interface_ip = requests.get('https://httpbin.org/ip').json()['origin']
            
            if socks_ip == interface_ip:
                raise RuntimeError(f"SOCKS proxy is not working - traffic is going through primary interface (IP: {interface_ip})")
                
            print(f"[+] SOCKS proxy connected to server at: {socks_ip}")

            config_data = parse_wireguard_conf(args.vpn_config)
            (
                interface_private_key,
                interface_address,
                peer_public_key,
                peer_allowed_ips,
                peer_endpoint,
            ) = unpack_wireguard_config(config_data)
            client_name = "wg0"
            local_ip = interface_address.split("/")[0]
            try:
                client_private_key = Key(interface_private_key)
                peer_public_key = Key(peer_public_key)

                client = Client(client_name, client_private_key, local_ip)

                endpoint = peer_endpoint.split(":")[0]
                port = int(peer_endpoint.split(":")[1])

                server_conn = ServerConnection(
                    peer_public_key,
                    endpoint,
                    port,
                )

                client.set_server(server_conn)
                client.connect()

                print("[+] WireGuard client connected successfully.")

                # Check if WireGuard is installed and load the module
                if check_wireguard_installed():
                    load_wireguard_module()

                    # Setup wg0 interface
                    setup_wireguard_interface()
                    print("[+] Wireguard interface set up successfully")

                    # Route SSH traffic via primary network interface
                    route_ssh_via_primary_network_interface(interface)
                    print("[+] SSH traffic is being routed via primary network interface.")

                else:
                    print("[-] Please install WireGuard to proceed.")

            except ValueError as e:
                print(f"Error: {e}")
            except Exception as e:
                print(f"Unexpected error: {e}")


def run():
    """Calls :func:`main` passing the CLI arguments extracted from :obj:`sys.argv`

    This function can be used as entry point to create console scripts with setuptools.
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
