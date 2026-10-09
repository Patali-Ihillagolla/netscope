from collections import Counter

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    DNS,
)


DEFAULT_PACKET_COUNT = 20
MAX_PACKET_COUNT = 1000
CAPTURE_TIMEOUT_SECONDS = 30


def get_protocol(packet):
    """Identify the main protocol in a packet."""

    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        if packet.haslayer(DNS):
            return "DNS"

        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(IP):
        return "IP"

    return "Other"


def get_packet_summary(packet):
    """Extract useful information from a packet."""

    protocol = get_protocol(packet)

    source = "-"
    destination = "-"
    source_port = "-"
    destination_port = "-"
    flags = "-"
    packet_length = len(packet)

    if packet.haslayer(IP):

        source = packet[IP].src
        destination = packet[IP].dst

    if packet.haslayer(TCP):

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        flags = str(packet[TCP].flags)

    elif packet.haslayer(UDP):

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    return {
        "protocol": protocol,
        "source": source,
        "destination": destination,
        "source_port": source_port,
        "destination_port": destination_port,
        "flags": flags,
        "length": packet_length
    }


def analyze_packet(packet, packet_number, statistics):
    """Analyze and display one captured packet."""

    summary = get_packet_summary(packet)

    protocol = summary["protocol"]

    statistics[protocol] += 1

    print(
        f"{packet_number:<6}"
        f"{protocol:<10}"
        f"{summary['source']:<18}"
        f"{summary['destination']:<18}"
        f"{str(summary['source_port']):<10}"
        f"{str(summary['destination_port']):<10}"
        f"{summary['flags']:<8}"
        f"{summary['length']}"
    )

def main():

    print("=" * 110)
    print("                         NetScope v0.7")
    print("                         Packet Analysis")
    print("=" * 110)
    print()

    print("Passive packet capture and analysis.")
    print("Only capture traffic on systems and networks")
    print("you own or have explicit permission to monitor.")
    print()

    try:
        packet_count = int(
            input(
                f"Number of packets to capture "
                f"[{DEFAULT_PACKET_COUNT}, max {MAX_PACKET_COUNT}]: "
            ).strip() or str(DEFAULT_PACKET_COUNT)
        )

    except ValueError:

        print("Invalid packet count.")
        return

    if not 1 <= packet_count <= MAX_PACKET_COUNT:

        print(
            f"Packet count must be between 1 and "
            f"{MAX_PACKET_COUNT}."
        )
        return

    print()
    print(f"Capturing {packet_count} packets...")
    print(
        f"Capture will stop after "
        f"{CAPTURE_TIMEOUT_SECONDS} seconds if the count is not reached."
    )
    print()

    statistics = Counter()

    print("-" * 110)

    print(
        f"{'#':<6}"
        f"{'PROTO':<10}"
        f"{'SOURCE':<18}"
        f"{'DESTINATION':<18}"
        f"{'SPORT':<10}"
        f"{'DPORT':<10}"
        f"{'FLAGS':<8}"
        f"LENGTH"
    )

    print("-" * 110)

    try:

        sniff(
            count=packet_count,
            prn=lambda packet: analyze_packet(
                packet,
                sum(statistics.values()) + 1,
                statistics
            ),
            store=False,
            timeout=CAPTURE_TIMEOUT_SECONDS
        )

    except PermissionError:

        print()
        print("Permission denied.")
        print("Try running the terminal as Administrator.")
        return

    except OSError as error:

        print()
        print("Packet capture failed.")
        print(f"Error: {error}")
        return

    print()
    print("=" * 60)
    print("PACKET STATISTICS")
    print("=" * 60)

    total_packets = sum(
        statistics.values()
    )

    if total_packets < packet_count:
        print(
            f"Capture timed out after {total_packets} of "
            f"{packet_count} requested packets."
        )

    for protocol, count in statistics.most_common():

        percentage = (
            count / total_packets
        ) * 100

        print(
            f"{protocol:<10}"
            f"{count:<8}"
            f"{percentage:.1f}%"
        )

    print("-" * 60)
    print(f"Total packets: {total_packets}")
    print("=" * 60)


if __name__ == "__main__":
    main()