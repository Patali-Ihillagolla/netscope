import platform
import socket
import subprocess
import ipaddress
import re


def get_network_info():
    """Get active network information from Windows ipconfig."""

    result = subprocess.run(
        ["ipconfig"],
        capture_output=True,
        text=True
    )

    output = result.stdout

    interface = None
    ip_address = None
    subnet_mask = None
    gateway = None

    current_interface = None

    for line in output.splitlines():

        # Find network interface
        interface_match = re.search(
            r"^\s*(Wireless LAN adapter|Ethernet adapter)\s+(.+):\s*$",
            line
        )

        if interface_match:
            current_interface = interface_match.group(2).strip()

        # Find IPv4 address
        ip_match = re.search(
            r"IPv4 Address.*:\s*([\d.]+)",
            line
        )

        if ip_match and current_interface:
            ip_address = ip_match.group(1)
            interface = current_interface

        # Find subnet mask
        mask_match = re.search(
            r"Subnet Mask.*:\s*([\d.]+)",
            line
        )

        if mask_match and current_interface:
            subnet_mask = mask_match.group(1)

        # Find default gateway
        gateway_match = re.search(
            r"Default Gateway.*:\s*([\d.]+)",
            line
        )

        if gateway_match and current_interface:
            gateway = gateway_match.group(1)

    return interface, ip_address, subnet_mask, gateway


def mask_to_cidr(subnet_mask):
    """Convert subnet mask to CIDR prefix length."""

    network = ipaddress.IPv4Network(
        "0.0.0.0/" + subnet_mask
    )

    return network.prefixlen


def get_network_details(ip_address, subnet_mask):
    """Calculate detailed subnet information."""

    cidr = mask_to_cidr(subnet_mask)

    network = ipaddress.ip_network(
        f"{ip_address}/{cidr}",
        strict=False
    )

    total_addresses = network.num_addresses

    # /31 and /32 networks are special cases.
    if network.prefixlen >= 31:
        first_host = network.network_address
        last_host = network.broadcast_address
        usable_hosts = total_addresses
    else:
        first_host = network.network_address + 1
        last_host = network.broadcast_address - 1
        usable_hosts = total_addresses - 2

    return (
        cidr,
        network,
        network.network_address,
        network.broadcast_address,
        total_addresses,
        first_host,
        last_host,
        usable_hosts
    )


def check_ping(address):
    """Check whether an address is reachable using ping."""

    if not address:
        return False

    result = subprocess.run(
        ["ping", "-n", "1", "-w", "1000", address],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def main():

    # --------------------------------------------
    # Get system information
    # --------------------------------------------

    operating_system = platform.system()
    hostname = socket.gethostname()

    # --------------------------------------------
    # Get network information
    # --------------------------------------------

    (
        interface,
        ip_address,
        subnet_mask,
        gateway
    ) = get_network_info()

    # Check whether required information was found
    if not ip_address or not subnet_mask:
        print("Unable to detect network information.")
        print("Please check the Windows network configuration.")
        return

    # --------------------------------------------
    # Calculate subnet information
    # --------------------------------------------

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

    # --------------------------------------------
    # Determine network type
    # --------------------------------------------

    address = ipaddress.ip_address(ip_address)

    if address.is_private:
        network_type = "Private IPv4"
    else:
        network_type = "Public IPv4"

    # --------------------------------------------
    # Check connectivity
    # --------------------------------------------

    gateway_status = check_ping(gateway)
    internet_status = check_ping("8.8.8.8")

    # --------------------------------------------
    # Display NetScope
    # --------------------------------------------

    print("============================================")
    print("               NetScope v0.2")
    print("              Subnet Analyzer")
    print("============================================")
    print()

    print("SYSTEM")
    print("--------------------------------------------")
    print(f"Operating System : {operating_system}")
    print(f"Hostname         : {hostname}")
    print()

    print("NETWORK")
    print("--------------------------------------------")
    print(f"Interface        : {interface}")
    print(f"IPv4 Address     : {ip_address}")
    print(f"Subnet Mask      : {subnet_mask}")
    print(f"CIDR             : /{cidr}")
    print(f"Network          : {network_address}")
    print(f"Broadcast        : {broadcast}")
    print(f"Total Addresses  : {total_addresses}")
    print(f"Usable Hosts     : {usable_hosts}")
    print()

    print("HOST RANGE")
    print("--------------------------------------------")
    print(f"First Host       : {first_host}")
    print(f"Last Host        : {last_host}")
    print(f"Host Range       : {first_host} - {last_host}")
    print()

    print("NETWORK TYPE")
    print("--------------------------------------------")
    print(f"Address Type     : {network_type}")
    print()

    print("ROUTING")
    print("--------------------------------------------")
    print(
        f"Default Gateway  : "
        f"{gateway if gateway else 'Not detected'}"
    )
    print()

    print("CONNECTIVITY")
    print("--------------------------------------------")
    print(
        f"Gateway          : "
        f"{'Reachable' if gateway_status else 'Unreachable'}"
    )
    print(
        f"Internet         : "
        f"{'Reachable' if internet_status else 'Unreachable'}"
    )
    print()

    print("============================================")


if __name__ == "__main__":
    main()