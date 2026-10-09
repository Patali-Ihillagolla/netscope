# NetScope

NetScope is a Windows-oriented Python command-line project for learning network inspection and defensive security concepts. It gathers local IPv4 network information and offers bounded discovery, TCP scanning, service identification, packet metadata analysis, and rule-based security findings.

## Authorized Use and Privacy

Use scanning, discovery, and packet-capture features only on systems and networks you own or are explicitly authorized to assess. Follow applicable laws and organizational policies.

NetScope can display local IP/network details, interface names, discovered device IP and MAC addresses, remote service banners, and packet metadata. Packet payload previews are disabled. Treat output as sensitive: avoid publishing unredacted terminal output, logs, screenshots, or local network details. NetScope does not save captured packets to files.

## Features and Limitations

- **Network Information** — Reads Windows network details with `ipconfig` and calculates IPv4 network boundaries. It reports the detected interface, address, subnet, and gateway; detection depends on the local Windows configuration.
- **Host Discovery** — Pings addresses yielded by the local IPv4 subnet's host iterator. Hosts that filter or do not answer ICMP may not be discovered. Discovery rejects subnets larger than 256 total addresses (a `/24` or narrower) before scheduling host checks.
- **TCP Port Scan** — Checks the configured common TCP port list only; this is not a scan of every port. Targets must be valid IPv4 addresses. Scan only authorized systems.
- **Service Detection** — Checks its configured common TCP ports and may use remote-provided banners to identify likely services. Displayed banners are sanitized and limited to 50 characters. Identification can be incomplete or incorrect. This feature's list currently omits Telnet port 23, which is included by the TCP scanner and security analysis.
- **LAN Discovery** — Sends ARP requests on the detected local IPv4 LAN and displays responding IP and MAC addresses. It is limited to the local link and may require elevated privileges.
- **Packet Analysis** — Uses Scapy to capture up to 1,000 packets, with a default request of 20 and a 30-second timeout. It displays packet metadata (such as protocol, addresses, ports, flags, and length), not raw payloads or DNS query names. It does not store captured packets. Packet capture may require Npcap and elevated privileges on Windows.
- **Security Analysis** — Checks the configured common TCP ports and applies the project's configured rules to produce findings and a heuristic exposure score. The score is not a calibrated vulnerability score or standardized risk metric. An open port alone does not prove a vulnerability; no findings do not prove a device is secure.
- **Quick Local Assessment** — Runs Network Information and ICMP Host Discovery only. It does not run port scanning, service detection, ARP discovery, packet capture, or security analysis.

The TCP scanner and security analyzer each define a 14-port inventory, including Telnet (23). The service detector currently defines 13 ports and omits Telnet (23). These lists are separate in the current implementation.

## Project Structure

```text
netscope/
├── lan_discovery.py
├── network_inspector.py
├── netscope.py
├── packet_analyzer.py
├── requirements.txt
├── security_analyzer.py
├── service_detector.py
├── tcp_scanner.py
└── tests/
    ├── test_netscope.py
    ├── test_network_inspector.py
    ├── test_packet_analyzer.py
    └── test_security_analyzer.py
```

`netscope.py` is the main menu entry point. Each feature module can also be run independently where it provides a command-line entry point.

## Supported Platform and Prerequisites

- Windows, because local network detection uses `ipconfig` and host discovery uses Windows `ping` command options.
- Python 3 with `venv` and `pip`.
- Scapy, installed from `requirements.txt`.
- Npcap for Windows packet capture. Install it separately according to its official instructions if using Packet Analysis; packet capture may also need an elevated terminal.
- Elevated privileges may be needed for packet capture and ARP discovery. Availability depends on Windows, Npcap, network adapter, and permissions.

The Python environment used for development and tests was Python 3.11.9. The project does not currently declare a minimum Python version.

## Installation

Clone the repository and create a virtual environment in PowerShell:

```powershell
git clone https://github.com/Patali-Ihillagolla/netscope.git
cd netscope

python -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
```

`requirements.txt` installs Scapy. Npcap is a separate Windows prerequisite for packet capture and is not installed by pip.

## Launch

From the project root with the virtual environment activated:

```powershell
python netscope.py
```

Enter a menu number. Target-based scanning options request an IPv4 address; IPv6 and malformed targets are rejected before a scan begins.

## Menu Options

| Option | Description |
| --- | --- |
| `1` | Display local IPv4 network information. |
| `2` | Discover hosts that respond to ICMP ping within the detected subnet, subject to the 256-address limit. |
| `3` | Scan the TCP scanner's configured common ports on a supplied IPv4 target. |
| `4` | Detect likely services on the service detector's configured ports and display sanitized banner previews when available. |
| `5` | Discover responding devices on the local LAN using ARP. |
| `6` | Capture up to the requested packet count (maximum 1,000) or stop after 30 seconds; display packet metadata and protocol statistics. |
| `7` | Analyze the configured TCP ports against rule-based security findings and display the heuristic exposure score and risk-level label. |
| `8` | Run Quick Local Assessment: Network Information followed by ICMP Host Discovery only. |
| `0` | Exit NetScope. |

## Fictional Example

Example output below uses documentation-only addresses and sanitized values:

```text
NETWORK INFORMATION
Interface        : Example Ethernet
IPv4 Address     : 192.0.2.23
Subnet Mask      : 255.255.255.0
CIDR             : /24
Network          : 192.0.2.0
Broadcast        : 192.0.2.255
Gateway          : 192.0.2.1

HOST DISCOVERY
192.0.2.1         Reachable
Hosts found: 1
```

The example does not imply that every host will respond or be discovered.

## Tests

Run the offline unit tests from the project root:

```powershell
python -m unittest discover -s tests -v
```

The tests use synthetic packets and addresses and mock host-discovery operations. They do not scan real targets or capture real network traffic.

## Known Limitations

- NetScope is an educational project, not a complete network inventory or vulnerability scanner.
- ICMP filtering, host firewalls, subnet size, adapter selection, and permissions affect discovery results.
- TCP and service checks cover configured ports only. Banner-based identification is best-effort.
- ARP discovery works only on the local network segment and may not see devices on other routed networks.
- Packet analysis reports metadata rather than application payloads; results depend on capture permissions, adapter, and Npcap setup.
- Security findings reflect only the configured rules and checked ports. They do not confirm exploitability or the absence of vulnerabilities.
- Local network information and scan output may be sensitive. Review and redact it before sharing.

## License

No license file is currently present. Unless a license is added, do not assume that the repository grants permission to reuse, distribute, or modify its contents.
