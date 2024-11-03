import argparse
import subprocess
from lib.library import (
    check_wireguard_installed,
    check_dante_installed,
    load_wireguard_module,
    setup_wireguard_server,
    setup_dante_proxy
)

def setup_dnsmasq():
    """Setup dnsmasq DNS server"""
    try:
        # Install dnsmasq
        subprocess.run("sudo apt-get install -y dnsmasq", shell=True, check=True)
        
        # Configure dnsmasq
        config = """# DNS configuration
server=1.1.1.1
server=1.0.0.1
interface=wg0
bind-interfaces
domain-needed
bogus-priv
no-resolv
no-hosts"""
        
        with open('/tmp/dnsmasq.conf', 'w') as f:
            f.write(config)
            
        commands = [
            "sudo mv /tmp/dnsmasq.conf /etc/dnsmasq.conf",
            "sudo systemctl enable dnsmasq",
            "sudo systemctl restart dnsmasq"
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True)
            
        print("[+] DNSMasq configured successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to setup DNSMasq: {e}")
        return False

def setup_firewall(port):
    """Setup firewall rules"""
    try:
        commands = [
            f"sudo ufw allow {port}/udp",  # WireGuard port
            "sudo ufw allow 53/udp",       # DNS
            "sudo ufw allow 53/tcp",       # DNS
            "sudo ufw --force enable",
            "sudo ufw status"
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True)
            
        print(f"[+] Firewall configured - opened port {port}/udp")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to configure firewall: {e}")
        return False

def add_wireguard_peer():
    """Add initial WireGuard peer"""
    try:
        # Generate peer keys
        private_key = subprocess.check_output(["wg", "genkey"], text=True).strip()
        public_key = subprocess.run(["wg", "pubkey"], input=private_key, text=True, capture_output=True).stdout.strip()
        
        # Add peer to WireGuard
        peer_config = f"""[Peer]
PublicKey = {public_key}
AllowedIPs = 10.10.10.2/32"""
        
        with open('/etc/wireguard/wg0.conf', 'a') as f:
            f.write("\n\n" + peer_config)
            
        # Create client config
        server_pubkey = subprocess.check_output("sudo wg show wg0 public-key", shell=True, text=True).strip()
        server_endpoint = subprocess.check_output("curl -s ifconfig.me", shell=True, text=True).strip()
        
        client_config = f"""[Interface]
PrivateKey = {private_key}
Address = 10.10.10.2/24
DNS = 10.10.10.1

[Peer]
PublicKey = {server_pubkey}
Endpoint = {server_endpoint}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"""
        
        with open('client.conf', 'w') as f:
            f.write(client_config)
            
        subprocess.run("sudo systemctl restart wg-quick@wg0", shell=True, check=True)
        
        print("[+] WireGuard peer added successfully")
        print("[+] Client configuration saved to client.conf")
        print(f"[+] Client private key: {private_key}")
        print(f"[+] Client public key: {public_key}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to add WireGuard peer: {e}")
        return False

def connect_to_vpn(config_file):
    """Connect to WireGuard VPN server"""
    try:
        # Copy config file to WireGuard directory
        vpn_interface = "wg1"  # Use wg1 to avoid conflict with our server on wg0
        subprocess.run(f"sudo cp {config_file} /etc/wireguard/{vpn_interface}.conf", shell=True, check=True)
        subprocess.run(f"sudo chmod 600 /etc/wireguard/{vpn_interface}.conf", shell=True, check=True)
        
        # Start VPN connection
        subprocess.run(f"sudo systemctl enable wg-quick@{vpn_interface}", shell=True, check=True)
        subprocess.run(f"sudo systemctl start wg-quick@{vpn_interface}", shell=True, check=True)
        
        print(f"[+] Connected to VPN using config: {config_file}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to connect to VPN: {e}")
        return False

def run():
    parser = argparse.ArgumentParser(
        description="Security Ghost - Server Setup",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--port', '-p',
                       type=int,
                       default=51820,
                       help='WireGuard port (default: 51820)')
    parser.add_argument('--socks-port', '-s',
                       type=int,
                       default=1080,
                       help='SOCKS proxy port (default: 1080)')
    parser.add_argument('--interface', '-i',
                       default='eth0',
                       help='Network interface to use (default: eth0)')
    parser.add_argument('--subnet',
                       default='10.10.10.0/24',
                       help='Subnet for WireGuard network (default: 10.10.10.0/24)')
    parser.add_argument('--vpn',
                       help='WireGuard configuration file for upstream VPN connection')
    
    args = parser.parse_args()
    
    if not check_wireguard_installed():
        print("[-] Please install WireGuard first")
        return
        
    if not check_dante_installed():
        print("[-] Please install Dante SOCKS proxy first")
        return
    
    # Connect to VPN first if specified
    if args.vpn:
        print("[+] Connecting to upstream VPN...")
        if not connect_to_vpn(args.vpn):
            print("[-] Failed to connect to VPN, exiting...")
            return
        
        # Update interface to use VPN
        print("[+] Using VPN interface for outbound traffic")
        outbound_interface = "wg1"
    else:
        outbound_interface = args.interface
    
    print("[+] Setting up firewall rules...")
    setup_firewall(args.port)
    
    print("[+] Setting up DNSMasq...")
    setup_dnsmasq()
    
    print("[+] Setting up WireGuard server...")
    load_wireguard_module()
    setup_wireguard_server(
        interface=outbound_interface,  # Use VPN interface if connected
        port=args.port,
        subnet=args.subnet
    )
    
    print("[+] Adding WireGuard peer...")
    add_wireguard_peer()
    
    print("[+] Setting up Dante SOCKS proxy...")
    setup_dante_proxy(
        port=args.socks_port,
        interface=outbound_interface  # Use VPN interface if connected
    )

if __name__ == '__main__':
    run() 