import os
import random
import re
import subprocess
from requests.structures import CaseInsensitiveDict
from http.client import HTTPConnection
from urllib.parse import urlparse
from decouple import config
import socks
import configparser
import requests
import string
import sys

# At the top of the file, add HAS_WIREGUARD_LIB to __all__
__all__ = [
    'get_current_mac',
    'HAS_WIREGUARD_LIB',
    # ... other exports ...
]

# Keep the conditional import here
if sys.platform != "darwin":  # Ubuntu/Linux
    try:
        from python_wireguard import Key, Client, ServerConnection
        HAS_WIREGUARD_LIB = True
    except (OSError, ImportError) as e:
        print(f"[-] Warning: python_wireguard library not available, falling back to CLI tools: {e}")
        HAS_WIREGUARD_LIB = False
else:  # macOS
    print("[*] Running on macOS - python_wireguard library not supported")
    HAS_WIREGUARD_LIB = False


def run_shell_command(command):
    """
    Function to run shell commands and handle errors.
    """
    try:
        subprocess.check_call(command, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Command failed: {command}\nError: {e}")


def check_wireguard_installed():
    """Check if WireGuard is installed on Ubuntu or macOS."""
    try:
        if sys.platform == "darwin":  # macOS
            output = subprocess.check_output(["brew", "list", "wireguard-tools"], encoding="utf-8", stderr=subprocess.DEVNULL)
            print("[+] WireGuard is installed via Homebrew")
            return True
        else:  # Ubuntu
            output = subprocess.check_output(["which", "wg"], encoding="utf-8").strip()
            if output:
                print(f"[+] WireGuard is installed at {output}")
                return True
        return False
    except subprocess.CalledProcessError:
        print("[-] WireGuard is not installed")
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
    """Setup WireGuard interface wg0 and configure routing."""
    if sys.platform == "darwin":  # macOS
        # Clean up existing routes
        cleanup_commands = [
            "sudo route -n delete -inet 0.0.0.0/1 2>/dev/null || true",
            "sudo route -n delete -inet 128.0.0.0/1 2>/dev/null || true"
        ]
        
        for cmd in cleanup_commands:
            run_shell_command(cmd)

        # Ensure proper permissions on temp config
        if os.path.exists('/private/tmp/temp_wg0.conf'):
            os.chmod('/private/tmp/temp_wg0.conf', 0o600)

        # Setup WireGuard interface with IPv4 only
        commands = [
            "sudo wireguard-go utun4",  # Add -f flag to run in foreground
            "sudo ifconfig utun4 inet 10.10.10.2/32 10.10.10.2 alias",
            "sudo ifconfig utun4 up",
            "sudo route -n add -inet 0.0.0.0/1 -interface utun4",
            "sudo route -n add -inet 128.0.0.0/1 -interface utun4"
        ]

        for command in commands:
            run_shell_command(command)
    else:  # Ubuntu
        if HAS_WIREGUARD_LIB:
            try:
                # Use python_wireguard library
                client = Client()
                client.create_interface("wg0")
                # ... configure using library ...
                return
            except Exception as e:
                print(f"[-] Failed to setup WireGuard using library: {e}")
                print("[*] Falling back to CLI commands")
        
        # Fallback to CLI commands
        commands = [
            "sudo ip -4 address add 10.10.10.2/24 dev wg0",
            "sudo ip link set mtu 1420 up dev wg0",
            "sudo wg set wg0 fwmark 51820",
            "sudo ip -4 route add 0.0.0.0/0 dev wg0 table 51820",
            "sudo ip -4 rule add not fwmark 51820 table 51820",
            "sudo ip -4 rule add table main suppress_prefixlength 0",
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


def change_mac(interface, new_mac):
    """
    Change the MAC address of a specified network interface.
    Supports both macOS and Linux platforms.
    """
    print(f"[+] Attempting to change MAC Address for {interface} to {new_mac}")
    try:
        if sys.platform == "darwin":  # macOS
            print("[!] MAC address changing is restricted on modern macOS systems.")
            print("[*] Skipping MAC address change...")
            return False
            
        else:  # Linux
            subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", interface, "address", new_mac], check=True)
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
            return True
            
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to change MAC address: {e}")
        return False
    except Exception as e:
        print(f"[-] Error changing MAC address: {e}")
        return False


class TunneledHTTPConnection(HTTPConnection):
    """
    Custom HTTP connection class that uses a specified transport (proxy).

    This class overrides the default HTTPConnection to connect through a provided proxy transport.

    Attributes:
    transport (socks.socksocket): The proxy socket through which connections are tunneled.
    """

    def __init__(self, transport, *args, **kwargs):
        self.transport = transport
        super().__init__(*args, **kwargs)
        self.sock = None

    def connect(self):
        """
        Establish a connection through the proxy transport.
        """
        try:
            if not self.transport:
                raise ValueError("Transport not initialized")
                
            self.transport.connect((self.host, self.port))
            self.sock = self.transport
        except Exception as e:
            print(f"[-] Connection error: {e}")
            raise


class TunneledHTTPAdapter(requests.adapters.BaseAdapter):
    """
    Custom HTTP adapter for tunneling HTTP requests through a specified proxy.

    This adapter mounts an HTTP Connection using a proxy transport.

    Attributes:
    transport (socks.socksocket): The proxy socket through which requests are tunneled.
    """

    def __init__(self, transport):
        if transport is None:
            raise ValueError("Transport cannot be None")
        super().__init__()
        self.transport = transport

    def close(self):
        """
        Close the adapter and ensure any resources are released.
        """
        try:
            if hasattr(self.transport, 'close'):
                self.transport.close()
        except Exception as e:
            print(f"[-] Error closing transport: {e}")

    def send(self, request, **kwargs):
        """
        Send the request through the proxy transport and return the response.
        """
        try:
            parsed = urlparse(request.url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)

            connection = TunneledHTTPConnection(self.transport, host, port)
            
            # Add debug logging
            print(f"[*] Attempting connection to {host}:{port}")

            # Ensure connection is established
            if not connection:
                raise ValueError("Failed to create connection")

            connection.request(
                method=request.method,
                url=request.url,
                body=request.body,
                headers=request.headers,
            )
            
            r = connection.getresponse()
            if not r:
                raise ValueError("No response received")

            # Add debug logging
            print(f"[*] Response status: {r.status}")
            print(f"[*] Response headers: {r.headers}")

            resp = requests.Response()
            resp.status_code = r.status
            resp.headers = CaseInsensitiveDict(r.headers)
            resp.raw = r
            resp.reason = r.reason
            resp.url = request.url
            resp.request = request
            resp.connection = connection
            
            # Read and decode the response content
            content = r.read()
            print(f"[*] Response content: {content[:200]}...")  # Print first 200 chars
            
            resp.encoding = requests.utils.get_encoding_from_headers(r.headers)
            resp._content = content  # Set the response content
            
            requests.cookies.extract_cookies_to_jar(resp.cookies, request, r)
            
            return resp

        except Exception as e:
            print(f"[-] Error in HTTP adapter: {e}")
            raise


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
    """
    parser = configparser.ConfigParser(allow_no_value=True)
    parser.read(file_path)

    # Convert the ConfigParser object to a dictionary
    conf_dict = {}
    for section in parser.sections():
        conf_dict[section] = {}
        for key, value in parser.items(section):
            if key.lower() == 'allowedips' and sys.platform == "darwin":
                # Split the IPs and filter out IPv6 addresses
                ips = [ip.strip() for ip in value.split(',')]
                ipv4_ips = [ip for ip in ips if not ':' in ip]
                value = ', '.join(ipv4_ips)
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
    """Get the name of the primary network interface."""
    try:
        if sys.platform == "darwin":  # macOS
            cmd = "route get default | grep interface | awk '{print $2}'"
        else:  # Ubuntu
            cmd = "ip route show default | awk '/default/ {print $5}'"
            
        output = subprocess.check_output(cmd, shell=True, text=True).strip()
        
        if output:
            print(f"[+] Primary network interface: {output}")
            return output
        else:
            print("[-] No primary network interface found")
            return None
            
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to get primary network interface: {e}")
        return None


def cleanup_connection(interface):
    """Clean up the secure connection"""
    try:
        if sys.platform == "darwin":  # macOS
            cleanup_commands = [
                "sudo route delete -net 0.0.0.0/1 10.10.10.2",
                "sudo route delete -net 128.0.0.0/1 10.10.10.2",
                "sudo pkill wireguard-go",
                "sudo rm -f /tmp/wg0.conf /tmp/dante.conf",
                "sudo networksetup -setdnsservers Wi-Fi empty"  # Reset DNS
            ]
        else:  # Ubuntu
            cleanup_commands = [
                "sudo ip rule show | grep -v 'lookup local\\|lookup main\\|lookup default' | cut -d ':' -f 1 | xargs -r -L 1 sudo ip rule del prio",
                "sudo iptables -t mangle -F",
                "sudo iptables -t mangle -X",
                "sudo rm -f /etc/systemd/resolved.conf.d/encrypted-dns.conf",
                "sudo systemctl restart systemd-resolved",
                "sudo cp /etc/resolv.conf.backup /etc/resolv.conf 2>/dev/null || true",
                "sudo ip link del dev wg0 2>/dev/null || true"
            ]

        for cmd in cleanup_commands:
            subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if sys.platform != "darwin":  # Ubuntu-specific service restarts
            subprocess.run(['sudo', 'systemctl', 'restart', 'systemd-networkd'], check=False)
            subprocess.run(['sudo', 'systemctl', 'restart', 'systemd-resolved'], check=False)

        print("[+] Network cleanup completed")

    except Exception as e:
        print(f"[-] Error during cleanup: {e}")


def setup_wireguard_server(interface, port, subnet):
    """
    Setup WireGuard server configuration
    
    Args:
        interface (str): Network interface to use
        port (int): Port to listen on
        subnet (str): Subnet for WireGuard network
    """
    try:
        # Generate server keys
        private_key = subprocess.check_output(["wg", "genkey"], text=True).strip()
        public_key = subprocess.run(["wg", "pubkey"], input=private_key, text=True, capture_output=True).stdout.strip()
        
        # Create WireGuard configuration
        config = f"""[Interface]
PrivateKey = {private_key}
Address = {subnet.split('/')[0].rsplit('.', 1)[0]}.1/24
ListenPort = {port}
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o {interface} -j MASQUERADE"""

        # Write configuration
        with open('/tmp/wg0.conf', 'w') as f:
            f.write(config)
            
        commands = [
            "sudo mv /tmp/wg0.conf /etc/wireguard/wg0.conf",
            "sudo chmod 600 /etc/wireguard/wg0.conf",
            "sudo systemctl enable wg-quick@wg0",
            "sudo systemctl start wg-quick@wg0"
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True)
            
        print(f"[+] WireGuard server configured on port {port}")
        print(f"[+] Server public key: {public_key}")
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to setup WireGuard server: {e}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False


def generate_password(length=16):
    """Generate a secure random password"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(characters) for _ in range(length))


def setup_dante_proxy(port, interface):
    """
    Setup Dante SOCKS proxy with authentication
    
    Args:
        port (int): Port to listen on
        interface (str): Network interface to use
    """
    try:
        # Generate random password
        password = generate_password()
        
        # Create socks user
        commands = [
            "sudo useradd -r -s /bin/false socks_user",
            f"echo 'socks_user:{password}' | sudo chpasswd"
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True)
        
        # Configure Dante
        config = f"""logoutput: syslog
internal: {interface} port = {port}
external: {interface}

socksmethod: username
clientmethod: none

user.privileged: root
user.unprivileged: socks_user

client pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
}}

socks pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
    socksmethod: username
}}"""

        with open('/tmp/danted.conf', 'w') as f:
            f.write(config)
            
        commands = [
            "sudo apt-get install -y dante-server",
            "sudo mv /tmp/danted.conf /etc/danted.conf",
            "sudo systemctl restart danted"
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True)
            
        print(f"[+] Dante SOCKS proxy configured on port {port}")
        print(f"[+] SOCKS5 credentials:")
        print(f"    Username: socks_user")
        print(f"    Password: {password}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to setup Dante proxy: {e}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False


def check_dante_installed():
    """
    Check if Dante SOCKS proxy is installed.
    """
    try:
        output = subprocess.check_output(["which", "danted"], encoding="utf-8").strip()
        if output:
            print("[+] Dante SOCKS proxy is installed")
            return True
        else:
            print("[-] Dante SOCKS proxy is not installed")
            return False
    except subprocess.CalledProcessError:
        print("[-] Dante SOCKS proxy is not installed")
        return False


def generate_wireguard_config(private_key, address, public_key, endpoint, allowed_ips="0.0.0.0/0"):
    """Generate WireGuard client configuration"""
    # For macOS, ensure we only use IPv4 addresses
    if sys.platform == "darwin":
        allowed_ips = "0.0.0.0/0"  # Force IPv4 only
    
    config = f"""[Interface]
PrivateKey = {private_key}
Address = {address}
DNS = 10.10.10.1

[Peer]
PublicKey = {public_key}
Endpoint = {endpoint}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25"""

    # Write to temporary file with correct permissions
    temp_config_path = '/private/tmp/temp_wg0.conf'
    
    # Create the file with restricted permissions from the start
    with os.fdopen(os.open(temp_config_path, os.O_WRONLY | os.O_CREAT, 0o600), 'w') as f:
        f.write(config)
    
    return config


def generate_dante_config(username, password, proxy_host, proxy_port):
    """Generate Dante SOCKS proxy configuration"""
    return {
        'username': username,
        'password': password,
        'host': proxy_host,
        'port': proxy_port
    }

def combine_configs(wireguard_config, dante_config):
    """Combine WireGuard and Dante configurations and write to files"""
    # Write WireGuard config
    with open('/tmp/wg0.conf', 'w') as f:
        f.write(wireguard_config)
    
    # Set proper permissions (600) on WireGuard config
    os.chmod('/tmp/wg0.conf', 0o600)
    
    # Write Dante config
    with open('/tmp/dante.conf', 'w') as f:
        f.write(f"""username={dante_config['username']}
password={dante_config['password']}
host={dante_config['host']}
port={dante_config['port']}""")
    
    print("[+] Configurations written to /tmp/wg0.conf and /tmp/dante.conf")
    
    return {
        'wireguard': wireguard_config,
        'dante': dante_config
    }

def get_current_mac(interface):
    """
    Get the current MAC address of a specified network interface.
    
    Parameters:
    interface (str): The name of the network interface
    
    Returns:
    str: The current MAC address, or None if it couldn't be retrieved
    """
    try:
        if sys.platform == "darwin":  # macOS
            output = subprocess.check_output(["ifconfig", interface], encoding="utf-8")
            mac_search = re.search(r"ether\s+([0-9a-fA-F:]{17})", output)
        else:  # Ubuntu
            output = subprocess.check_output(["ip", "link", "show", interface], encoding="utf-8")
            mac_search = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", output)
        
        if mac_search:
            return mac_search.group(1)
        return None
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to get current MAC address: {e}")
        return None
