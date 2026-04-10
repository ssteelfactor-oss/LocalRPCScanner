# RPC Scanner - Network RPC Service Discovery Tool

![C](https://img.shields.io/badge/Language-C-00599C?style=flat-square)
![Windows](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## Overview

**RPC Scanner** is a comprehensive C-based network reconnaissance tool designed to discover and identify RPC (Remote Procedure Call) services running on Windows systems within a local network. It uses heuristic detection with known RPC service signatures to identify services on common ports (135, 139, 445).

This tool is part of the extended NetEnum project and provides deep network visibility into RPC infrastructure, enabling security professionals to conduct thorough network assessments and identify potential security risks.

## Features

✅ **Automatic Network Detection** - Auto-detects local network prefix without manual configuration  
✅ **RPC Service Discovery** - Identifies 8+ known RPC services (EPMAP, SAMR, LSARPC, WINREG, SVCCTL, SPOOLSVC, NETLOGON, WINLOGON)  
✅ **Signature-Based Detection** - Uses byte-pattern matching for reliable service identification  
✅ **Full Subnet Scanning** - Scans entire /24 subnets (254 hosts) efficiently  
✅ **Low False Positive Rate** - Multi-layer verification with protocol headers and service signatures  
✅ **Detailed Reporting** - Clear output of discovered services with IP addresses and port information  
✅ **Pure C Implementation** - No external dependencies except Windows SDK  
✅ **Comprehensive Logging** - Detailed console output with [+], [-], [*] status indicators

## Quick Start

### Prerequisites

- **OS**: Windows 7 or later (Windows Server 2008R2+)
- **Compiler**: Visual Studio 2015+ or MSVC compiler
- **SDK**: Windows SDK (for Windows.h and networking headers)
- **Admin Rights**: Not required for basic scanning (may be needed for some advanced features)

### Compilation

**Using Visual Studio 2022/2019:**
cl.exe /O2 /W4 rpc_scanner.c /link ws2_32.lib iphlpapi.lib rpcrt4.lib ole32.lib advapi32.lib

```bash
# Open the solution in Visual Studio
# Build -> Build Solution (or Ctrl+Shift+B)
# Output: bin/Release/RpcScanner.exe

**Usage**
Auto-detect local network and scan:
RpcScanner.exe

**Output:**
=== RPC SERVER SCANNER WITH HEURISTIC DETECTION ===

[*] Auto-detecting local network...
[+] Detected network prefix: 192.168.1.0/24

=== RPC SERVICE DISCOVERY ===
[*] Scanning network: 192.168.1.0/24

[+] FOUND: 192.168.1.10:135 - Service: EPMAP (RPC Endpoint Mapper)
[+] FOUND: 192.168.1.10:445 - Service: SVCCTL (Service Control Manager)
[+] FOUND: 192.168.1.11:135 - Service: EPMAP (RPC Endpoint Mapper)
[+] FOUND: 192.168.1.20:139 - Service: SAMR (Security Account Manager)

=== SCAN RESULTS ===
[*] Total RPC servers found: 4
[*] Servers in list: 4

=== RPC SERVERS DISCOVERED ===
[1] 192.168.1.10:135
[2] 192.168.1.10:445
[3] 192.168.1.11:135
[4] 192.168.1.20:139

Detected RPC   Services
Service	Port	Description	        Security Impact
EPMAP	  135	  RPC Endpoint Mapper	Info disclosure, enumeration
SAMR	  139	  Security Account Manager	Account enumeration, credential attacks
LSARPC	139	  LSA Remote Procedure Call	Policy information leakage
WINREG	445	  Remote Registry	    System configuration access
SVCCTL	445	  Service Control     Manager	Service enumeration, DoS
SPOOLSVC	445	Print Spooler	      CVE-2021-1675 (PrintNightmare)
NETLOGON	139	Network Logon	      Domain trust enumeration
WINLOGON	445	Windows Logon	      Authentication information

**Detection Algorithm**
Network Enumeration: Iterate through all hosts in /24 subnet (1-254)
Port Scanning: Test common RPC ports (135, 139, 445)
RPC Probe: Send DCE/RPC BIND request to each host:port combination
Response Analysis:
Check for RPC protocol header (0x05 0x00)
Search for service-specific byte signatures
Service Identification: Match response patterns against known signatures
Result Recording: Add discovered services to results list
