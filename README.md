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

```bash
# Open the solution in Visual Studio
# Build -> Build Solution (or Ctrl+Shift+B)
# Output: bin/Release/RpcScanner.exe
