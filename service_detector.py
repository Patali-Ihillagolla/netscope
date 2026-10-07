import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
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


def check_port(target_ip, port, timeout=1):
    """Check whether a TCP port is open."""

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex(
                (target_ip, port)
            )

            return result == 0

    except OSError:
        return False


def grab_banner(target_ip, port, timeout=2):
    """Try to receive a service banner."""

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex(
                (target_ip, port)
            )

            if result != 0:
                return None

            if port in (80, 8080):
                request = (
                    "HEAD / HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )

                sock.sendall(request.encode())

            elif port == 443:
                return "HTTPS service detected"

            else:
                data = sock.recv(1024)

                if data:
                    return data.decode(
                        "utf-8",
                        errors="replace"
                    ).strip()

                return None

            data = sock.recv(1024)

            if data:
                return data.decode(
                    "utf-8",
                    errors="replace"
                ).strip()

            return None

    except (OSError, UnicodeDecodeError):
        return None


def identify_service(port, banner):
    """Identify a likely service from the port and banner."""

    if banner:
        banner_lower = banner.lower()

        if "openssh" in banner_lower:
            return "SSH"

        if "ftp" in banner_lower:
            return "FTP"

        if "smtp" in banner_lower:
            return "SMTP"

        if "apache" in banner_lower:
            return "HTTP / Apache"

        if "nginx" in banner_lower:
            return "HTTP / Nginx"

        if "microsoft-iis" in banner_lower:
            return "HTTP / IIS"

        if "mysql" in banner_lower:
            return "MySQL"

    return COMMON_PORTS.get(
        port,
        "Unknown"
    )


def scan_service(target_ip, port):
    """Check a port and attempt service detection."""

    if not check_port(target_ip, port):
        return port, False, None, None

    banner = grab_banner(
        target_ip,
        port
    )

    service = identify_service(
        port,
        banner
    )

    return port, True, service, banner


def scan_services(target_ip, ports):
    """Scan multiple ports concurrently."""

    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:

        futures = {
            executor.submit(
                scan_service,
                target_ip,
                port
            ): port
            for port in ports
        }

        for future in as_completed(futures):

            result = future.result()

            results.append(result)

    results.sort(
        key=lambda result: result[0]
    )

    return results


def main():

    print("=" * 60)
    print("                  NetScope v0.5")
    print("                  Service Detection")
    print("=" * 60)

    print()
    print("Only scan systems you own or have")
    print("explicit permission to test.")
    print()

    target_ip = input(
        "Enter target IPv4 address: "
    ).strip()

    try:
        socket.inet_aton(target_ip)

    except OSError:
        print("Invalid IPv4 address.")
        return

    print()
    print(f"Target: {target_ip}")
    print(
        f"Ports to scan: {len(COMMON_PORTS)}"
    )
    print()

    print("Starting service detection...")
    print()

    results = scan_services(
        target_ip,
        COMMON_PORTS.keys()
    )

    print("-" * 60)
    print(
        f"{'PORT':<8}"
        f"{'SERVICE':<20}"
        f"{'STATUS':<12}"
        f"BANNER"
    )
    print("-" * 60)

    for port, is_open, service, banner in results:

        if not is_open:
            continue

        if banner:
            banner_preview = banner.replace(
                "\r",
                " "
            ).replace(
                "\n",
                " "
            )

            banner_preview = banner_preview[:50]

        else:
            banner_preview = "No banner"

        print(
            f"{port:<8}"
            f"{service:<20}"
            f"{'OPEN':<12}"
            f"{banner_preview}"
        )

    print("-" * 60)

    open_ports = [
        result
        for result in results
        if result[1]
    ]

    print(
        f"Open services found: "
        f"{len(open_ports)}"
    )

    print("=" * 60)


if __name__ == "__main__":
    main()