# NetScope

A small Python project for learning computer networking and cybersecurity fundamentals.

NetScope starts as a simple network inspection tool and will be developed step by step into a basic network security tool.

## Current Version

**v0.1 - Network Inspector**

The current version can:

* Detect the operating system
* Detect the hostname
* Find the active network interface
* Find the local IPv4 address
* Find the subnet mask
* Convert the subnet mask to CIDR
* Calculate the network address
* Calculate the broadcast address
* Calculate the number of usable hosts
* Find the default gateway
* Check gateway connectivity
* Check Internet connectivity

## Technologies

* Python
* IPv4 networking
* CIDR and subnetting
* Windows `ipconfig`
* ICMP ping
* Python `socket`
* Python `subprocess`
* Python `ipaddress`
* Regular expressions

## Running the Project

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Run the program:

```powershell
python network_inspector.py
```

NetScope will detect the network information of the computer running the program.

## Project Roadmap

* [x] v0.1 - Network Inspector
* [ ] v0.2 - Subnet Analyzer
* [ ] v0.3 - Host Discovery
* [ ] v0.4 - TCP Port Scanner
* [ ] v0.5 - Service Detection
* [ ] v0.6 - LAN Discovery
* [ ] v0.7 - Packet Analysis
* [ ] v0.8 - Security Analysis
* [ ] v1.0 - NetScope

## Purpose

This is a learning project focused on understanding networking, Python, and practical cybersecurity concepts.

Each version will introduce a new concept and build on the previous version.

Only scan networks and systems where there is permission to do so.
