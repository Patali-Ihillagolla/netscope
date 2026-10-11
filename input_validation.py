import ipaddress


def prompt_for_ipv4(prompt):
    """Prompt until the user enters a valid dotted-decimal IPv4 address."""

    while True:
        target = input(prompt).strip()

        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            print("Invalid IPv4 address. Enter a dotted-decimal IPv4 address.")
            continue

        if not isinstance(address, ipaddress.IPv4Address):
            print("IPv6 addresses are not supported. Enter an IPv4 address.")
            continue

        return str(address)
