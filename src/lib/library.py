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

# Extracting SOCKS proxy variables from environment using decouple
SOCKS_TYPE = config("SOCKS_TYPE")
SOCKS_HOST = config("SOCKS_HOST")
SOCKS_PORT = config("SOCKS_PORT", cast=int)
SOCKS_USERNAME = config("SOCKS_USERNAME")
SOCKS_PASSWORD = config("SOCKS_PASSWORD")


def am_i_online(url="https://dns.google"):
    """
    Check if the system is online by making a GET request to a given URL.

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
    def __init__(self, transport, *args, **kwargs):
        self.transport = transport
        HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        self.transport.connect((self.host, self.port))
        self.sock = self.transport


class TunneledHTTPAdapter(requests.adapters.BaseAdapter):
    def __init__(self, transport):
        self.transport = transport

    def close(self):
        pass

    def send(self, request, **kwargs):
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


if __name__ == "__main__":
    online_status = am_i_online()
    print(f"Online status: {online_status}")
    print(
        f"SOCKS proxy type: {SOCKS_TYPE}, SOCKS host: {SOCKS_HOST}, SOCKS port: {SOCKS_PORT}"
    )
    if not online_status:
        print("[-] Network is unreachable. Please check your network connection.")
    else:
        new_mac = get_random_mac()
        if new_mac:
            print(f"Generated Random MAC: {new_mac}")
            interface = "eth0"
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
                        sock.addproxy(
                            socks.Proxy(
                                proxy_type,  # SOCKS type from the environment variable
                                SOCKS_HOST,  # Host from the environment variable
                                SOCKS_PORT,  # Port from the environment variable
                                remote_dns=False,
                                username=SOCKS_USERNAME,  # Username from the environment variable
                                password=SOCKS_PASSWORD,  # Password from the environment variable
                            )
                        )
                        session.mount("http://", TunneledHTTPAdapter(sock))
                        session.mount("https://", TunneledHTTPAdapter(sock))
                        print(session.get("https://httpbin.org/ip").json()["origin"])
        else:
            print("[-] Could not generate MAC address.")
