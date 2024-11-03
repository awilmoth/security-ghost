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
import requests


def run_shell_command(command):
    """
    Function to run shell commands and handle errors.
    """
    try:
        subprocess.check_call(command, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Command failed: {command}\nError: {e}")


def check_wireguard_installed():
    """
    Check if WireGuard is installed.
    """
    try:
        output = subprocess.check_output(["which", "wg"], encoding="utf-8").strip()
        if output:
            print(f"[+] WireGuard is installed at {output}")
            return True
        else:
            print("[-] WireGuard is not installed.")
            return False
    except subprocess.CalledProcessError:
        print("[-] WireGuard is not installed.")
        return False


def load_wireguard_module():
    """
    Load the WireGuard kernel module.
    """
    try:
        subprocess.check_call(["sudo", "modprobe", "wireguard"])
        print("[+] WireGuard kernel module loaded successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to load WireGuard kernel module: {e}")


def setup_wireguard_interface():
    """
    Setup WireGuard interface wg0 and configure routing.
    """
    commands = [
        "sudo ip -4 address add 10.10.10.2/24 dev wg0",
        "sudo ip link set mtu 1420 up dev wg0",
        "sudo wg set wg0 fwmark 51820",
        "sudo ip -4 route add 0.0.0.0/0 dev wg0 table 51820",
        "sudo ip -4 rule add not fwmark 51820 table 51820",
        "sudo ip -4 rule add table main suppress_prefixlength 0",  # Add this line to fix routing issues
    ]

    for command in commands:
        run_shell_command(command)


def add_ssh_route(primary_network_interface):
    """
    Add a specific route for SSH traffic to ensure it doesn't route through WireGuard.
    """
    try:
        # Get the default gateway IP associated with primary network interface
        gateway_ip = subprocess.check_output(
            "ip route show default | awk '/default/ {print $3}'", shell=True, text=True
        ).strip()

        print(f"[+] Default gateway IP: {gateway_ip}")

        # Create ip rule and ip route for the SSH traffic
        commands = [
            "sudo ip rule add fwmark 0x1 table 100",
            f"sudo ip route add default via {gateway_ip} dev {primary_network_interface} table 100",
        ]

        for command in commands:
            run_shell_command(command)

        print("[+] Successfully added IP rule and route for SSH traffic.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to add IP rule/route: {e}")


def route_ssh_via_primary_network_interface(primary_network_interface):
    """
    Ensure SSH traffic (port 22) uses the primary network interface interface.
    """
    commands = [
        "sudo iptables -t mangle -A OUTPUT -p tcp --sport 22 -j MARK --set-mark 0x1",
        "sudo iptables -t mangle -A OUTPUT -p tcp --dport 22 -j MARK --set-mark 0x1",
    ]

    for command in commands:
        run_shell_command(command)

    # Add specific routing rules for SSH
    add_ssh_route(primary_network_interface)


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


def check_mac_vendor_file():
    """Check if mac-vendor.txt exists in the package directory"""
    # Get the directory where the library.py file is located
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up to src directory and then into security_ghost
    vendor_file = os.path.join(os.path.dirname(current_dir), 'security_ghost', 'mac-vendor.txt')
    
    if not os.path.exists(vendor_file):
        raise FileNotFoundError("Required file 'mac-vendor.txt' not found at: " + vendor_file)
    
    print(f"[+] Found mac-vendor.txt at: {vendor_file}")  # Debug line
    return vendor_file


def get_random_mac():
    """
    Generate a random MAC address.

    Uses the 'mac-vendor.txt' file to get vendor-specific MAC address prefixes.

    Returns:
    str: A randomly generated MAC address in the format 'xx:xx:xx:xx:xx:xx'
    Raises:
    FileNotFoundError: If mac-vendor.txt file is not found
    """
    vendor_file = check_mac_vendor_file()  # Get the full path to the file
    
    with open(vendor_file, "r") as read_file:
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


def get_current_mac(interface):
    """
    Get the current MAC address of a specified network interface.

    Parameters:
    interface (str): The name of the network interface, e.g., 'primary network interface'.

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
    interface (str): The name of the network interface
    new_mac (str): The new MAC address to assign to the interface.

    Returns:
    None
    """
    if not new_mac:
        print("[-] Invalid MAC address provided. MAC address change aborted.")
        return

    print(f"[+] Changing MAC Address for {interface} to {new_mac}")

    try:
        subprocess.check_call(["sudo", "ip", "link", "set", interface, "down"])
        subprocess.check_call(
            ["sudo", "ip", "link", "set", interface, "address", new_mac]
        )
        subprocess.check_call(["sudo", "service", "networking", "restart"])

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


def parse_socks_config(config_path):
    """Parse SOCKS proxy configuration file"""
    config = {}
    with open(config_path) as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=')
                config[key.strip()] = value.strip()
    
    # Validate required fields in original format
    required_fields = ['SOCKS_TYPE', 'SOCKS_HOST', 'SOCKS_PORT', 'SOCKS_USERNAME', 'SOCKS_PASSWORD']
    missing_fields = [field for field in required_fields if field not in config]
    if missing_fields:
        raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
    
    return {
        'type': config['SOCKS_TYPE'],
        'host': config['SOCKS_HOST'],
        'port': int(config['SOCKS_PORT']),
        'username': config['SOCKS_USERNAME'],
        'password': config['SOCKS_PASSWORD']
    }


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
    interface_address = config["Interface"]["address"]
    peer_public_key = config["Peer"]["publickey"]
    peer_allowed_ips = config["Peer"]["allowedips"]
    peer_endpoint = config["Peer"]["endpoint"]

    # Returning the unpacked variables
    return (
        interface_private_key,
        interface_address,
        peer_public_key,
        peer_allowed_ips,
        peer_endpoint,
    )


def get_primary_network_interface():
    """
    Function to get the name of the primary network interface on Linux.
    Returns the interface used by the default route.
    """
    try:
        # Get the default route interface using ip command
        output = subprocess.check_output(
            "ip route show default | awk '/default/ {print $5}'",
            shell=True,
            text=True
        ).strip()
        
        if output:
            print(f"[+] Primary network interface: {output}")
            return output
        else:
            print("[-] No primary network interface found")
            return None
            
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to get primary network interface: {e}")
        return None


def setup_encrypted_dns(dns_provider="quad9"):
    """
    Setup encrypted DNS proxy using either Quad9 or Cloudflare.
    
    Parameters:
    dns_provider (str): The DNS provider to use ('quad9' or 'cloudflare'). Defaults to 'quad9'.
    
    Returns:
    bool: True if setup successful, False otherwise
    """
    dns_configs = {
        "quad9": {
            "ip": "9.9.9.9",
            "port": "853",
            "hostname": "dns.quad9.net"
        },
        "cloudflare": {
            "ip": "1.1.1.1",
            "port": "853",
            "hostname": "cloudflare-dns.com"
        }
    }
    
    if dns_provider.lower() not in dns_configs:
        print(f"[-] Invalid DNS provider. Choose either 'quad9' or 'cloudflare'")
        return False
    
    config = dns_configs[dns_provider.lower()]
    
    try:
        # Setup DNS-over-TLS using systemd-resolved
        commands = [
            f"sudo mkdir -p /etc/systemd/resolved.conf.d/",
            f"sudo bash -c 'cat > /etc/systemd/resolved.conf.d/encrypted-dns.conf << EOL\n"
            f"[Resolve]\n"
            f"DNS={config['ip']}\n"
            f"DNSOverTLS=yes\n"
            f"DNSSEC=yes\n"
            f"Domains=~.\n"
            f"EOL'",
            "sudo systemctl restart systemd-resolved"
        ]
        
        for command in commands:
            run_shell_command(command)
            
        print(f"[+] Encrypted DNS setup complete using {dns_provider}")
        print(f"[+] DNS Server: {config['ip']}")
        print(f"[+] Hostname: {config['hostname']}")
        return True
        
    except Exception as e:
        print(f"[-] Failed to setup encrypted DNS: {e}")
        return False
