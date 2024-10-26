import requests
import os
import random
import re
import subprocess


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


if __name__ == "__main__":
    online_status = am_i_online()
    print(f"Online status: {online_status}")

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
        else:
            print("[-] Could not generate MAC address.")
