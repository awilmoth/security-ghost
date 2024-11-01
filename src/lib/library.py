import requests
import os
import random
import re
import subprocess
from requests.structures import CaseInsensitiveDict
from http.client import HTTPConnection
from urllib.parse import urlparse
from decouple import config
import socks
from python_wireguard import Key, Client, ServerConnection
import configparser


# Extracting SOCKS proxy variables from environment using decouple
SOCKS_TYPE = config("SOCKS_TYPE")
SOCKS_HOST = config("SOCKS_HOST")
SOCKS_PORT = config("SOCKS_PORT", cast=int)
SOCKS_USERNAME = config("SOCKS_USERNAME")
SOCKS_PASSWORD = config("SOCKS_PASSWORD")


def run_shell_command(command):
    """
    Function to run shell commands and handle errors.
    """
    try:
        subprocess.check_call(command, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Command failed: {command}\nError: {e}")


def setup_wireguard_interface():
    """
    Setup WireGuard interface wg0 and configure routing.
    """
    commands = [
        # "ip link add wg0 type wireguard",
        # "wg setconf wg0 /root/wireguard.conf",  # Update with correct path
        "ip -4 address add 10.10.10.2/24 dev wg0",
        "ip link set mtu 1420 up dev wg0",
        "wg set wg0 fwmark 51820",
        "ip -4 route add 0.0.0.0/0 dev wg0 table 51820",
        "ip -4 rule add not fwmark 51820 table 51820",
    ]

    for command in commands:
        run_shell_command(command)


def route_ssh_via_eth0():
    """
    Ensure SSH traffic (port 22) uses the eth0 interface.
    """
    commands = [
        "iptables -t mangle -A OUTPUT -p tcp --sport 22 -o eth0 -j MARK --set-mark 0x1",
        "ip rule add fwmark 0x1 lookup 100",
        "ip route add default via $(ip route get 8.8.8.8 | head -1 | cut -d' ' -f3) dev eth0 table 100",
    ]

    for command in commands:
        run_shell_command(command)


def am_i_online(url="https://dns.google"):
    """
    Check if the system is online by making a GET request to a specified URL.

    Parameters:
    url (str): The URL to check connectivity against. Defaults to 'https://dns.google'.

    Returns:
    bool: True if the system is online and the URL is accessible, False otherwise.
    """
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return True
        return False
    except Exception as e:
        print(f"[-] Exception occurred: {e}")
        return False


def get_random_mac():
    """
    Generate a random MAC address.

    Uses the 'mac-vendor.txt' file if it exists to get vendor-specific MAC address prefixes.
    Otherwise, returns False.

    Returns:
    str: A randomly generated MAC address in the format 'xx:xx:xx:xx:xx:xx', or False if the file is not found.
    """
    if os.path.exists("mac-vendor.txt"):
        with open("mac-vendor.txt", "r") as read_file:
            content = read_file.readlines()
            vendor_octets = random.choice(content)[:6]
            hex_num = hex(random.randint(0, 16**6))[2:].zfill(6).upper()
            return "{}:{}:{}:{}:{}:{}".format(
                vendor_octets[:2],
                vendor_octets[2:4],
                vendor_octets[4:6],
                hex_num[:2],
                hex_num[2:4],
                hex_num[4:6],
            ).lower()
    else:
        print("[-] 'mac-vendor.txt' file not found.")
        return False


def get_current_mac(interface):
    """
    Get the current MAC address of a specified network interface.

    Parameters:
    interface (str): The name of the network interface, e.g., 'eth0'.

    Returns:
    str: The current MAC address of the specified network interface, or False if no MAC address is found.
    """
    try:
        ifconfig_result = subprocess.check_output(
            ["ip", "link", "show", interface], encoding="utf-8"
        )
        mac_address_search_result = re.search(
            r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result
        )
        if mac_address_search_result:
            return mac_address_search_result.group(0)
        else:
            print(f"[-] No MAC address found on this interface: {interface}")
            return False
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to get current MAC address: {e}")
        return False


def change_mac_linux(interface, new_mac):
    """
    Change the MAC address of a specified network interface on Linux.

    Parameters:
    interface (str): The name of the network interface, e.g., 'eth0'.
    new_mac (str): The new MAC address to assign to the interface.

    Returns:
    None
    """
    print(f"[+] Changing MAC Address for {interface} to {new_mac}")

    try:
        subprocess.check_call(["sudo", "ip", "link", "set", interface, "down"])
        subprocess.check_call(
            ["sudo", "ip", "link", "set", interface, "address", new_mac]
        )
        subprocess.check_call(["sudo", "service", "networking", "restart"])

        print(f"[+] MAC address changed successfully to {new_mac}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to change MAC address: {e}")


class TunneledHTTPConnection(HTTPConnection):
    """
    Custom HTTP connection class that uses a specified transport (proxy).

    This class overrides the default HTTPConnection to connect through a provided proxy transport.

    Attributes:
    transport (socks.socksocket): The proxy socket through which connections are tunneled.
    """

    def __init__(self, transport, *args, **kwargs):
        self.transport = transport
        HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        """
        Establish a connection through the proxy transport.
        """
        self.transport.connect((self.host, self.port))
        self.sock = self.transport


class TunneledHTTPAdapter(requests.adapters.BaseAdapter):
    """
    Custom HTTP adapter for tunneling HTTP requests through a specified proxy.

    This adapter mounts an HTTP Connection using a proxy transport.

    Attributes:
    transport (socks.socksocket): The proxy socket through which requests are tunneled.
    """

    def __init__(self, transport):
        self.transport = transport

    def close(self):
        """
        Close the adapter and ensure any resources are released.
        """
        pass

    def send(self, request, **kwargs):
        """
        Send the request through the proxy transport and return the response.

        Parameters:
        request (requests.PreparedRequest): The prepared request to be sent.
        kwargs: Additional arguments passed to the send method.

        Returns:
        requests.Response: The response received from the request.
        """
        scheme, location, path, params, query, anchor = urlparse(request.url)
        if ":" in location:
            host, port = location.split(":")
            port = int(port)
        else:
            host = location
            port = 80

        connection = TunneledHTTPConnection(self.transport, host, port)
        connection.request(
            method=request.method,
            url=request.url,
            body=request.body,
            headers=request.headers,
        )
        r = connection.getresponse()
        resp = requests.Response()
        resp.status_code = r.status
        resp.headers = CaseInsensitiveDict(r.headers)
        resp.raw = r
        resp.reason = r.reason
        resp.url = request.url
        resp.request = request
        resp.connection = connection
        resp.encoding = requests.utils.get_encoding_from_headers(r.headers)
        requests.cookies.extract_cookies_to_jar(resp.cookies, request, r)
        return resp


def parse_wireguard_conf(file_path):
    """
    Parse a WireGuard configuration (.conf) file and extract its information.

    Parameters:
    file_path (str): The path to the WireGuard configuration file.

    Returns:
    dict: A dictionary with the configuration details.
    """
    parser = configparser.ConfigParser(allow_no_value=True)
    parser.read(file_path)

    # Convert the ConfigParser object to a dictionary
    conf_dict = {}
    for section in parser.sections():
        conf_dict[section] = {}
        for key, value in parser.items(section):
            conf_dict[section][key] = value

    return conf_dict


def unpack_wireguard_config(config):
    # Unpacking the dictionary
    interface_private_key = config["Interface"]["privatekey"]
    # interface_address = config["Interface"]["address"]
    # interface_dns = config["Interface"]["dns"]
    peer_public_key = config["Peer"]["publickey"]
    peer_allowed_ips = config["Peer"]["allowedips"]
    peer_endpoint = config["Peer"]["endpoint"]
    # peer_preshared_key = config["Peer"]["presharedkey"]

    # Returning the unpacked variables
    return (
        interface_private_key,
        # interface_address,
        # interface_dns,
        peer_public_key,
        peer_allowed_ips,
        peer_endpoint,
        # peer_preshared_key,
    )


def get_primary_network_interface():
    """
    Function to get the name of the primary network interface.
    On modern systems, 'ip route show' can be used to find the default gateway interface.
    """
    try:
        # Execute the command and get the output
        output = subprocess.check_output("ip route show default", shell=True, text=True)
        # Parse the output to find the primary interface
        for line in output.splitlines():
            if "default via" in line:
                parts = line.split()
                if "dev" in parts:
                    interface = parts[parts.index("dev") + 1]
                    return interface
    except subprocess.CalledProcessError as e:
        print(f"[-] Command failed: {e}")
        return None


if __name__ == "__main__":
    online_status = am_i_online()
    print(f"Online status: {online_status}")

    if not online_status:
        print("[-] Network is unreachable. Please check your network connection.")
    else:
        new_mac = get_random_mac()
        if new_mac:
            print(f"Generated Random MAC: {new_mac}")
            interface = get_primary_network_interface()
            current_mac = get_current_mac(interface)
            if current_mac:
                print(f"Current MAC address of {interface}: {current_mac}")
                change_mac_linux(interface, new_mac)
                updated_mac = get_current_mac(interface)
                if updated_mac:
                    print(f"Updated MAC address of {interface}: {updated_mac}")
                    # starting proxychains for socks proxy
                    with requests.Session() as session:
                        sock = socks.socksocket()
                        # Proxy setup using environment variables
                        proxy_type = getattr(
                            socks, SOCKS_TYPE
                        )  # Get the actual socks proxy type
                        sock.setproxy(
                            proxy_type,  # SOCKS type from the environment variable
                            SOCKS_HOST,  # Host from the environment variable
                            SOCKS_PORT,  # Port from the environment variable
                            True,  # remote_dns param is moved here as per the setproxy signature
                            SOCKS_USERNAME,  # Username from the environment variable
                            SOCKS_PASSWORD,  # Password from the environment variable
                        )
                        session.mount("http://", TunneledHTTPAdapter(sock))
                        session.mount("https://", TunneledHTTPAdapter(sock))
                        print(session.get("https://httpbin.org/ip").json()["origin"])

                        file_path = "/root/wireguard.conf"
                        config_data = parse_wireguard_conf(file_path)
                        (
                            interface_private_key,
                            # interface_address,
                            # interface_dns,
                            peer_public_key,
                            peer_allowed_ips,
                            peer_endpoint,
                            # peer_preshared_key,
                        ) = unpack_wireguard_config(config_data)
                        client_name = "wg0"
                        local_ip = "10.10.10.2/32"  # interface_address.split("/")[0]
                        try:
                            client_private_key = Key(interface_private_key)
                            peer_public_key = Key(peer_public_key)
                            # peer_preshared_key = Key(peer_preshared_key)

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

                            print("WireGuard client connected successfully.")

                            # Setup wg0 interface
                            setup_wireguard_interface()
                            print("Wireguard interface set up successfully")

                            # Route SSH traffic via eth0
                            route_ssh_via_eth0()

                        except ValueError as e:
                            print(f"Error: {e}")
                        except Exception as e:
                            print(f"Unexpected error: {e}")

        else:
            print("[-] Could not generate MAC address.")
