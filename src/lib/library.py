import requests
import os
import random
import re
import subprocess


def maximum(x, y):
    return max(x, y)


def am_i_online(url="https://dns.google"):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return True
        return False
    except:
        return False


def get_random_mac():
    if os.path.exists("mac-vendor.txt"):
        with open("mac-vendor.txt", "r") as read_file:
            content = read_file.readlines()
            vendor_octets = random.choice(content)[:6]
            hex_num = hex(random.randint(0, 16**6))[2:].zfill(6).upper()
            return "{}{}{}{}{}{}{}".format(vendor_octets, *hex_num)
    else:
        return False


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_address_search_reslut = re.search(
        r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result)
    )
    if mac_address_search_reslut:
        return mac_address_search_reslut.group(0)
    else:
        print("[-] No mac address found in this interface : " + str(interface))


if __name__ == "__main__":
    print(get_random_mac())
