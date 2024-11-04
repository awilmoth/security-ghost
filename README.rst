.. image:: https://img.shields.io/badge/-PyScaffold-005CA0?logo=pyscaffold
    :alt: Project generated with PyScaffold
    :target: https://pyscaffold.org/

|

==============
security_ghost
==============


# Security Ghost Features

## Overview
Security Ghost is a comprehensive security tool that provides secure networking capabilities through WireGuard VPN and SOCKS5 proxy integration. It supports both macOS and Linux (Ubuntu) platforms.

## Core Features

### 1. VPN Integration
- WireGuard VPN support
- Automatic interface configuration
- IPv4/IPv6 routing management
- Persistent connection handling
- Support for both CLI and library-based implementations

### 2. SOCKS5 Proxy Support
- Secure SOCKS5 proxy integration
- Authentication support
- Tunneled HTTP connections
- Custom HTTP adapter implementation
- Proxy configuration management

### 3. Network Interface Management
- MAC address spoofing (Linux only)
- Primary interface detection
- Interface routing control
- SSH traffic routing protection

### 4. Security Features
- Secure configuration file handling
- Permission management
- DNS leak prevention
- Network cleanup on shutdown

### 5. Platform Support
- macOS support with platform-specific optimizations
- Linux (Ubuntu) support with full feature set
- Conditional feature availability based on platform

## Command Line Interface

### Basic Commands

- **Start secure connection**:  
  `security-ghost up --vpn /path/to/wireguard.conf --socks /path/to/socks.conf`

- **Stop secure connection**:  
  `security-ghost down`

- **Additional Options**:
  - `--change_mac yes|no` : Enable/disable MAC address changing (default: yes)
  - `--version` : Display version information
  - `-v, --verbose` : Set loglevel to INFO
  - `-vv, --very-verbose` : Set loglevel to DEBUG

### Configuration Files

1. **WireGuard Configuration (wireguard.conf)**

   - `[Interface]`
     - `PrivateKey = <private_key>`
     - `Address = <ip_address>/32`
     - `DNS = 10.10.10.1`

   - `[Peer]`
     - `PublicKey = <public_key>`
     - `Endpoint = <endpoint>:<port>`
     - `AllowedIPs = 0.0.0.0/0`

2. **SOCKS Configuration (socks.conf)**

   - `SOCKS_TYPE=5`
   - `SOCKS_HOST=<host>`
   - `SOCKS_PORT=<port>`
   - `SOCKS_USERNAME=<username>`
   - `SOCKS_PASSWORD=<password>`

## Error Handling
- Comprehensive error reporting
- Platform-specific error handling
- Graceful connection cleanup
- Network state restoration

# Security Ghost Server Features

## Overview
Security Ghost Server is the server-side component that provides WireGuard VPN and SOCKS proxy services. It's designed to work seamlessly with the Security Ghost client.

## Core Features

### 1. WireGuard Server
- Automatic server configuration
- Key pair generation
- Interface management
- NAT and forwarding setup
- Client access control

### 2. SOCKS5 Proxy Server
- Dante SOCKS server integration
- User authentication
- Access control lists
- Connection logging
- Traffic management

### 3. Server Management
- Automatic installation of dependencies
- Service management
- Configuration generation
- Secure credential handling

### 4. Security Features
- Secure key storage
- Permission management
- Network isolation
- Service hardening

## Server Setup

### Installation

- **Install Security Ghost Server**:  
  `pip install security-ghost-server`

- **Initialize server**:  
  `security-ghost-server init`

### Configuration

1. **WireGuard Server Setup**

   - `security-ghost-server wireguard setup --interface eth0 --port 51820 --subnet 10.10.10.0/24`

2. **SOCKS Server Setup**

   - `security-ghost-server socks setup --interface eth0 --port 1080`

### Management Commands

- **Start services**:  
  `security-ghost-server start`

- **Stop services**:  
  `security-ghost-server stop`

- **Status check**:  
  `security-ghost-server status`

- **Add new client**:  
  `security-ghost-server add-client`

- **Remove client**:  
  `security-ghost-server remove-client`

## Server Requirements
- Ubuntu 20.04 LTS or later
- Python 3.8 or later
- Root/sudo access
- Public IP address
- Open ports (configurable)

## Security Considerations
- Firewall configuration
- Service hardening
- Access control
- Logging and monitoring
- Backup and recovery