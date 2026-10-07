import ipaddress
import platform
import re
import socket
import subprocess

from scapy.all import ARP, Ether, srp


def get_network_info():
    """Get active IPv4 network information from Windows."""

    result = subprocess.run(
        ["ipconfig"],
        capture_output=True,
        text=True
    )

    output = result.stdout

    interface = None
    ip_address = None
    subnet_mask = None

    current_interface = None

    for line in output.splitlines():

        interface_match = re.search(
            r"^\s*(Wireless LAN adapter|Ethernet adapter)\s+(.+):\s*$",
            line
        )

        if interface_match:
            current_interface = interface_match.group(2).strip()

        ip_match = re.search(
            r"IPv4 Address.*:\s*([\d.]+)",
            line
        )

        if ip_match and current_interface:
            ip_address = ip_match.group(1)
            interface = current_interface

        mask_match = re.search(
            r"Subnet Mask.*:\s*([\d.]+)",
            line
        )

        if mask_match and current_interface:
            subnet_mask = mask_match.group(1)

    return interface, ip_address, subnet_mask


def mask_to_cidr(subnet_mask):
    """Convert subnet mask to CIDR prefix length."""

    network = ipaddress.IPv4Network(
        "0.0.0.0/" + subnet_mask
    )

    return network.prefixlen


def get_network(ip_address, subnet_mask):
    """Calculate the local IPv4 network."""

    cidr = mask_to_cidr(subnet_mask)

    return ipaddress.ip_network(
        f"{ip_address}/{cidr}",
        strict=False
    )


def arp_scan(network):
    """Discover devices on the local LAN using ARP."""

    ethernet_frame = Ether(
        dst="ff:ff:ff:ff:ff:ff"
    )

    arp_request = ARP(
        pdst=str(network)
    )

    packet = ethernet_frame / arp_request

    answered, _ = srp(
        packet,
        timeout=2,
        verbose=False
    )

    devices = []

    for sent_packet, received_packet in answered:

        devices.append({
            "ip": received_packet.psrc,
            "mac": received_packet.hwsrc
        })

    devices.sort(
        key=lambda device: int(
            ipaddress.ip_address(
                device["ip"]
            )
        )
    )

    return devices


def main():

    operating_system = platform.system()
    hostname = socket.gethostname()

    (
        interface,
        ip_address,
        subnet_mask
    ) = get_network_info()

    if not ip_address or not subnet_mask:
        print("Unable to detect local network information.")
        print("Please check the network configuration.")
        return

    network = get_network(
        ip_address,
        subnet_mask
    )

    print()
    print("=" * 60)
    print("                  NetScope v0.6")
    print("                  LAN Discovery")
    print("=" * 60)
    print()

    print("SYSTEM")
    print("-" * 60)
    print(f"Operating System : {operating_system}")
    print(f"Hostname         : {hostname}")
    print()

    print("LOCAL NETWORK")
    print("-" * 60)
    print(f"Interface        : {interface}")
    print(f"IPv4 Address     : {ip_address}")
    print(f"Subnet Mask      : {subnet_mask}")
    print(f"Network          : {network}")
    print()

    print("DISCOVERY")
    print("-" * 60)
    print("Sending ARP requests...")
    print("Please wait...")
    print()

    try:
        devices = arp_scan(network)

    except PermissionError:
        print("Permission denied.")
        print("Try running the terminal as Administrator.")
        return

    except OSError as error:
        print("Unable to perform ARP discovery.")
        print(f"Error: {error}")
        return

    print("DISCOVERED DEVICES")
    print("-" * 60)

    if not devices:
        print("No devices discovered.")

    else:

        print(
            f"{'IP ADDRESS':<18}"
            f"{'MAC ADDRESS':<20}"
        )

        print("-" * 60)

        for device in devices:

            print(
                f"{device['ip']:<18}"
                f"{device['mac']:<20}"
            )

    print("-" * 60)
    print(f"Devices found: {len(devices)}")
    print()

    print("=" * 60)


if __name__ == "__main__":
    main()