import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


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


SECURITY_RULES = {
    21: {
        "severity": "MEDIUM",
        "title": "FTP service exposed",
        "description": (
            "FTP is an older file-transfer protocol "
            "and may transmit credentials without encryption."
        ),
        "recommendation": (
            "Prefer SFTP or another secure file-transfer method."
        ),
    },

    22: {
        "severity": "INFO",
        "title": "SSH service exposed",
        "description": (
            "SSH provides encrypted remote administration."
        ),
        "recommendation": (
            "Use strong authentication and restrict access "
            "to trusted systems where possible."
        ),
    },

    23: {
        "severity": "HIGH",
        "title": "Telnet service exposed",
        "description": (
            "Telnet does not provide secure encrypted "
            "communication."
        ),
        "recommendation": (
            "Disable Telnet and use SSH instead."
        ),
    },

    80: {
        "severity": "MEDIUM",
        "title": "HTTP service exposed",
        "description": (
            "HTTP traffic is not protected by TLS."
        ),
        "recommendation": (
            "Use HTTPS for applications that handle "
            "sensitive information."
        ),
    },

    445: {
        "severity": "HIGH",
        "title": "SMB service exposed",
        "description": (
            "SMB provides network file and printer sharing "
            "and should be restricted to trusted networks."
        ),
        "recommendation": (
            "Restrict SMB access with firewall rules and "
            "disable unnecessary file sharing."
        ),
    },

    3306: {
        "severity": "HIGH",
        "title": "MySQL service exposed",
        "description": (
            "A database service is directly reachable "
            "over the network."
        ),
        "recommendation": (
            "Restrict database access to trusted hosts "
            "and avoid unnecessary network exposure."
        ),
    },

    3389: {
        "severity": "HIGH",
        "title": "RDP service exposed",
        "description": (
            "Remote Desktop is reachable over the network."
        ),
        "recommendation": (
            "Restrict RDP access and use strong authentication."
        ),
    },

    5432: {
        "severity": "HIGH",
        "title": "PostgreSQL service exposed",
        "description": (
            "A PostgreSQL database service is directly "
            "reachable over the network."
        ),
        "recommendation": (
            "Restrict database access to trusted hosts."
        ),
    },

    8080: {
        "severity": "MEDIUM",
        "title": "Alternative HTTP service exposed",
        "description": (
            "An HTTP service is reachable on an "
            "alternative web port."
        ),
        "recommendation": (
            "Verify that the service is required and "
            "use HTTPS when sensitive data is involved."
        ),
    },
}


SEVERITY_POINTS = {
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0,
}


def check_port(target_ip, port, timeout=0.5):
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

            return result == 0

    except OSError:

        return False


def scan_ports(target_ip, ports):
    """Scan multiple TCP ports concurrently."""

    results = []

    with ThreadPoolExecutor(
        max_workers=20
    ) as executor:

        futures = {
            executor.submit(
                check_port,
                target_ip,
                port
            ): port
            for port in ports
        }

        for future in as_completed(futures):

            port = futures[future]

            try:

                is_open = future.result()

            except OSError:

                is_open = False

            results.append(
                (port, is_open)
            )

    results.sort(
        key=lambda result: result[0]
    )

    return results


def create_finding(port, service):
    """Create a security finding for an open port."""

    rule = SECURITY_RULES.get(port)

    if rule:

        return {
            "port": port,
            "service": service,
            "severity": rule["severity"],
            "title": rule["title"],
            "description": rule["description"],
            "recommendation": rule["recommendation"],
        }

    return {
        "port": port,
        "service": service,
        "severity": "LOW",
        "title": "Unknown service exposed",
        "description": (
            "An open TCP port was discovered, "
            "but NetScope could not classify it."
        ),
        "recommendation": (
            "Verify whether this service is required "
            "and restrict access if necessary."
        ),
    }


def analyze_security(scan_results):
    """Analyze open ports and generate security findings."""

    findings = []

    open_ports = [
        port
        for port, is_open in scan_results
        if is_open
    ]

    for port in open_ports:

        service = COMMON_PORTS.get(
            port,
            "Unknown"
        )

        finding = create_finding(
            port,
            service
        )

        findings.append(finding)

    if len(open_ports) >= 5:

        findings.append({
            "port": "-",
            "service": "Multiple",
            "severity": "MEDIUM",
            "title": "Multiple network services exposed",
            "description": (
                "Several TCP services are reachable on "
                "the target."
            ),
            "recommendation": (
                "Review each exposed service and disable "
                "services that are not required."
            ),
        })

    return findings


def calculate_risk_score(findings):
    """Calculate a simple rule-based risk score."""

    score = 0

    for finding in findings:

        severity = finding["severity"]

        score += SEVERITY_POINTS.get(
            severity,
            0
        )

    return min(score, 100)


def get_risk_level(score):
    """Convert a risk score into a risk level."""

    if score >= 30:
        return "HIGH"

    if score >= 15:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "MINIMAL"


def print_findings(findings):
    """Display security findings."""

    print()
    print("=" * 70)
    print("SECURITY FINDINGS")
    print("=" * 70)

    if not findings:

        print()
        print("No security findings were identified.")
        return

    for number, finding in enumerate(
        findings,
        start=1
    ):

        print()
        print(
            f"[{finding['severity']}] "
            f"{finding['title']}"
        )

        print(
            f"Port       : {finding['port']}"
        )

        print(
            f"Service    : {finding['service']}"
        )

        print(
            f"Description: "
            f"{finding['description']}"
        )

        print(
            f"Recommendation: "
            f"{finding['recommendation']}"
        )

        if number < len(findings):
            print("-" * 70)


def main():

    print("=" * 70)
    print("                    NetScope v0.8")
    print("                    Security Analysis")
    print("=" * 70)

    print()
    print(
        "This tool performs defensive security analysis "
        "of TCP services."
    )

    print(
        "Only scan systems you own or have "
        "explicit permission to test."
    )

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
        f"Ports to analyze: "
        f"{len(COMMON_PORTS)}"
    )

    print()
    print("Scanning TCP ports...")
    print()

    scan_results = scan_ports(
        target_ip,
        COMMON_PORTS.keys()
    )

    open_ports = [
        port
        for port, is_open in scan_results
        if is_open
    ]

    print("-" * 70)
    print(
        f"{'PORT':<10}"
        f"{'SERVICE':<22}"
        f"STATUS"
    )
    print("-" * 70)

    for port, is_open in scan_results:

        if not is_open:
            continue

        service = COMMON_PORTS.get(
            port,
            "Unknown"
        )

        print(
            f"{port:<10}"
            f"{service:<22}"
            f"OPEN"
        )

    print("-" * 70)

    print(
        f"Open ports found: "
        f"{len(open_ports)}"
    )

    findings = analyze_security(
        scan_results
    )

    risk_score = calculate_risk_score(
        findings
    )

    risk_level = get_risk_level(
        risk_score
    )

    print_findings(findings)

    print()
    print("=" * 70)
    print("SECURITY SUMMARY")
    print("=" * 70)

    print(
        f"Open Ports : {len(open_ports)}"
    )

    print(
        f"Findings   : {len(findings)}"
    )

    print(
        f"Risk Score : {risk_score}/100"
    )

    print(
        f"Risk Level : {risk_level}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()