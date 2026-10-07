import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common TCP ports to check
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alternative",
}


def scan_port(target_ip, port, timeout=0.5):
    """Check whether a TCP port accepts a connection."""

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex(
                (target_ip, port)
            )

            if result == 0:
                return port, True

            return port, False

    except OSError:
        return port, False


def scan_ports(target_ip, ports):
    """Scan selected TCP ports on a target."""

    results = []

    with ThreadPoolExecutor(max_workers=20) as executor:

        futures = {
            executor.submit(
                scan_port,
                target_ip,
                port
            ): port
            for port in ports
        }

        for future in as_completed(futures):

            port, is_open = future.result()

            results.append((port, is_open))

    results.sort(key=lambda result: result[0])

    return results


def main():

    print("=" * 45)
    print("             NetScope v0.4")
    print("             TCP Port Scanner")
    print("=" * 45)

    print()
    print("Only scan devices you own or have")
    print("explicit permission to test.")
    print()

    target_ip = input("Enter target IPv4 address: ").strip()

    # Validate the IPv4 address
    try:
        socket.inet_aton(target_ip)

    except OSError:
        print("Invalid IPv4 address.")
        return

    print()
    print(f"Target: {target_ip}")
    print(f"Ports to scan: {len(COMMON_PORTS)}")
    print()

    print("Starting TCP port scan...")
    print()

    results = scan_ports(
        target_ip,
        COMMON_PORTS.keys()
    )

    print("-" * 45)
    print(f"{'PORT':<10} {'SERVICE':<22} STATUS")
    print("-" * 45)

    open_ports = []

    for port, is_open in results:

        service = COMMON_PORTS[port]

        if is_open:
            status = "OPEN"
            open_ports.append(port)
        else:
            status = "Not open"

        print(
            f"{port:<10} "
            f"{service:<22} "
            f"{status}"
        )

    print("-" * 45)
    print(f"Open ports found: {len(open_ports)}")
    print("=" * 45)


if __name__ == "__main__":
    main()