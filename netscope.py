import ipaddress

from network_inspector import (
    get_network_info,
    get_network_details,
    discover_hosts,
)

from tcp_scanner import (
    COMMON_PORTS,
    scan_ports,
)

from service_detector import (
    sanitize_banner,
    scan_services,
)

from lan_discovery import (
    get_network,
    arp_scan,
)

from packet_analyzer import (
    main as packet_analysis_main,
)

from security_analyzer import (
    scan_ports as security_scan_ports,
    COMMON_PORTS as SECURITY_PORTS,
    analyze_security,
    calculate_risk_score,
    get_risk_level,
    print_findings,
)


def print_header():
    """Display the NetScope main header."""

    print()
    print("=" * 50)
    print("              NetScope v1.0")
    print("        Network Security Analyzer")
    print("=" * 50)
    print()


def get_target_ip():
    """Ask the user for a target IPv4 address."""

    target_ip = input(
        "Enter target IPv4 address: "
    ).strip()

    try:
        address = ipaddress.ip_address(target_ip)

    except ValueError:
        print("Invalid IPv4 address.")
        return None

    if not isinstance(address, ipaddress.IPv4Address):
        print("IPv6 addresses are not supported. Enter an IPv4 address.")
        return None

    return target_ip


def network_information():
    """Display local network information."""

    (
        interface,
        ip_address,
        subnet_mask,
        gateway
    ) = get_network_info()

    if not ip_address or not subnet_mask:
        print()
        print("Unable to detect network information.")
        return

    (
        cidr,
        network,
        network_address,
        broadcast,
        total_addresses,
        first_host,
        last_host,
        usable_hosts
    ) = get_network_details(
        ip_address,
        subnet_mask
    )

    address = ipaddress.ip_address(
        ip_address
    )

    network_type = (
        "Private IPv4"
        if address.is_private
        else "Public IPv4"
    )

    print()
    print("=" * 50)
    print("NETWORK INFORMATION")
    print("=" * 50)

    print(f"Interface        : {interface}")
    print(f"IPv4 Address     : {ip_address}")
    print(f"Subnet Mask      : {subnet_mask}")
    print(f"CIDR             : /{cidr}")
    print(f"Network          : {network_address}")
    print(f"Broadcast        : {broadcast}")
    print(f"Total Addresses  : {total_addresses}")
    print(f"Usable Hosts     : {usable_hosts}")
    print(f"First Host       : {first_host}")
    print(f"Last Host        : {last_host}")
    print(f"Network Type     : {network_type}")
    print(f"Gateway          : {gateway or 'Not detected'}")

    print("=" * 50)


def host_discovery():
    """Discover hosts that respond to ICMP ping."""

    (
        interface,
        ip_address,
        subnet_mask,
        gateway
    ) = get_network_info()

    if not ip_address or not subnet_mask:
        print()
        print("Unable to detect network information.")
        return

    (
        cidr,
        network,
        network_address,
        broadcast,
        total_addresses,
        first_host,
        last_host,
        usable_hosts
    ) = get_network_details(
        ip_address,
        subnet_mask
    )

    print()
    print("Starting host discovery...")
    print("Only hosts that respond to ICMP may be detected.")
    print()

    try:
        hosts = discover_hosts(network)

    except ValueError as error:
        print()
        print(error)
        return

    print("=" * 50)
    print("HOST DISCOVERY")
    print("=" * 50)

    if hosts:

        for host in hosts:
            print(f"{str(host):<18} Reachable")

    else:
        print("No responding hosts found.")

    print("-" * 50)
    print(f"Hosts found: {len(hosts)}")
    print("=" * 50)


def port_scan():
    """Scan common TCP ports on a target."""

    target_ip = get_target_ip()

    if not target_ip:
        return

    print()
    print(f"Scanning target: {target_ip}")
    print(f"Ports checked: {len(COMMON_PORTS)}")
    print()

    results = scan_ports(
        target_ip,
        COMMON_PORTS.keys()
    )

    print("=" * 55)
    print("TCP PORT SCAN")
    print("=" * 55)

    open_ports = []

    for port, is_open in results:

        if is_open:

            service = COMMON_PORTS[port]

            print(
                f"{port:<10}"
                f"{service:<22}"
                f"OPEN"
            )

            open_ports.append(port)

    if not open_ports:
        print("No open common TCP ports found.")

    print("-" * 55)
    print(f"Open ports found: {len(open_ports)}")
    print("=" * 55)


def service_detection():
    """Detect services on common TCP ports."""

    target_ip = get_target_ip()

    if not target_ip:
        return

    print()
    print(f"Target: {target_ip}")
    print("Starting service detection...")
    print()

    results = scan_services(
        target_ip,
        COMMON_PORTS.keys()
    )

    print("=" * 70)
    print("SERVICE DETECTION")
    print("=" * 70)

    found = 0

    for port, is_open, service, banner in results:

        if not is_open:
            continue

        found += 1

        if banner:
            banner_preview = sanitize_banner(banner)

        else:

            banner_preview = "No banner"

        print(
            f"{port:<8}"
            f"{service:<20}"
            f"{banner_preview}"
        )

    if found == 0:
        print("No open services detected.")

    print("-" * 70)
    print(f"Open services found: {found}")
    print("=" * 70)


def lan_discovery():
    """Discover devices on the local LAN using ARP."""

    print("\nStarting LAN discovery...")
    print("This uses ARP and works only on the local network.")

    print("\n" + "=" * 55)
    print("LAN DISCOVERY")
    print("=" * 55)

    try:
        interface, ip_address, subnet_mask, gateway = get_network_info()

        if not ip_address or not subnet_mask:
            print("\nUnable to detect local network information.")
            return

        network = get_network(
            ip_address,
            subnet_mask
        )

        print(f"Interface : {interface}")
        print(f"Network   : {network}")
        print("\nStarting ARP discovery...")
        print("This only works on the local LAN.")
        print()

        devices = arp_scan(network)

    except PermissionError:
        print("Permission denied.")
        print("Try running the terminal as Administrator.")
        return

    except OSError as error:
        print("ARP discovery failed.")
        print(f"Error: {error}")
        return

    if not devices:
        print("No devices discovered.")

    else:
        print(
            f"{'IP ADDRESS':<20}"
            f"{'MAC ADDRESS':<20}"
        )

        print("-" * 55)

        for device in devices:
            print(
                f"{str(device['ip']):<20}"
                f"{device['mac']:<20}"
            )

    print("-" * 55)
    print(f"Devices found: {len(devices)}")
    print("=" * 55)
    

def packet_analysis():
    """Run the packet analysis module."""

    packet_analysis_main()


def security_analysis():
    """Perform rule-based security analysis."""

    target_ip = get_target_ip()

    if not target_ip:
        return

    print()
    print(f"Target: {target_ip}")
    print("Starting security analysis...")
    print()

    scan_results = security_scan_ports(
        target_ip,
        SECURITY_PORTS.keys()
    )

    open_ports = [
        port
        for port, is_open in scan_results
        if is_open
    ]

    findings = analyze_security(
        scan_results
    )

    risk_score = calculate_risk_score(
        findings
    )

    risk_level = get_risk_level(
        risk_score
    )

    print()
    print("=" * 55)
    print("SECURITY ANALYSIS")
    print("=" * 55)

    print(f"Target       : {target_ip}")
    print(f"Open Ports   : {len(open_ports)}")
    print(f"Findings     : {len(findings)}")
    print(f"Heuristic Exposure Score : {risk_score}")
    print(f"Risk Level   : {risk_level}")

    print_findings(findings)

    print()
    print("=" * 55)


def quick_local_assessment():
    """Run a quick local network assessment."""

    print()
    print("=" * 55)
    print("         QUICK LOCAL ASSESSMENT")
    print("=" * 55)

    print()
    print("[1] Network Information")
    network_information()

    print()
    print("[2] Host Discovery")
    host_discovery()

    print()
    print("Quick Local Assessment completed.")
    print("=" * 55)


def show_menu():
    """Display the main menu."""

    print_header()

    print("1. Network Information")
    print("2. Host Discovery")
    print("3. TCP Port Scan")
    print("4. Service Detection")
    print("5. LAN Discovery")
    print("6. Packet Analysis")
    print("7. Security Analysis")
    print("8. Quick Local Assessment")
    print("0. Exit")

    print()


def main():
    """Run the NetScope main menu."""

    while True:

        show_menu()

        choice = input(
            "Select option: "
        ).strip()

        if choice == "1":

            network_information()

        elif choice == "2":

            host_discovery()

        elif choice == "3":

            print()
            print(
                "Only scan systems you own "
                "or have explicit permission to test."
            )

            port_scan()

        elif choice == "4":

            print()
            print(
                "Only scan systems you own "
                "or have explicit permission to test."
            )

            service_detection()

        elif choice == "5":

            lan_discovery()

        elif choice == "6":

            packet_analysis()

        elif choice == "7":

            print()
            print(
                "Only scan systems you own "
                "or have explicit permission to test."
            )

            security_analysis()

        elif choice == "8":

            quick_local_assessment()

        elif choice == "0":

            print()
            print("Exiting NetScope.")
            break

        else:

            print()
            print("Invalid option.")

        input(
            "\nPress Enter to return to the menu..."
        )


if __name__ == "__main__":
    main()