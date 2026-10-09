import ipaddress
import unittest
from unittest.mock import patch

import network_inspector


class NetworkInspectorTests(unittest.TestCase):
    def test_calculates_ipv4_subnet_boundaries(self):
        (
            cidr,
            network,
            network_address,
            broadcast,
            total_addresses,
            first_host,
            last_host,
            usable_hosts,
        ) = network_inspector.get_network_details(
            "192.168.1.20",
            "255.255.255.0",
        )

        self.assertEqual(cidr, 24)
        self.assertEqual(network, ipaddress.ip_network("192.168.1.0/24"))
        self.assertEqual(str(network_address), "192.168.1.0")
        self.assertEqual(str(broadcast), "192.168.1.255")
        self.assertEqual(total_addresses, 256)
        self.assertEqual(str(first_host), "192.168.1.1")
        self.assertEqual(str(last_host), "192.168.1.254")
        self.assertEqual(usable_hosts, 254)

    def test_calculates_point_to_point_and_single_address_subnets(self):
        subnet_31 = network_inspector.get_network_details(
            "192.0.2.0",
            "255.255.255.254",
        )
        self.assertEqual(subnet_31[0], 31)
        self.assertEqual(str(subnet_31[5]), "192.0.2.0")
        self.assertEqual(str(subnet_31[6]), "192.0.2.1")
        self.assertEqual(subnet_31[7], 2)

        subnet_32 = network_inspector.get_network_details(
            "192.0.2.8",
            "255.255.255.255",
        )
        self.assertEqual(subnet_32[0], 32)
        self.assertEqual(str(subnet_32[5]), "192.0.2.8")
        self.assertEqual(str(subnet_32[6]), "192.0.2.8")
        self.assertEqual(subnet_32[7], 1)

    def test_discovery_uses_ipaddress_host_rules_for_31_and_32(self):
        with patch.object(network_inspector, "discover_host", return_value=None) as discover:
            network_inspector.discover_hosts(
                ipaddress.ip_network("192.0.2.0/31")
            )
            self.assertEqual(
                [call.args[0] for call in discover.call_args_list],
                [ipaddress.ip_address("192.0.2.0"), ipaddress.ip_address("192.0.2.1")],
            )

            discover.reset_mock()
            network_inspector.discover_hosts(
                ipaddress.ip_network("192.0.2.8/32")
            )
            self.assertEqual(
                [call.args[0] for call in discover.call_args_list],
                [ipaddress.ip_address("192.0.2.8")],
            )

    def test_rejects_large_subnet_before_creating_executor(self):
        with patch.object(network_inspector, "ThreadPoolExecutor") as executor:
            with self.assertRaisesRegex(ValueError, "at most 256 addresses"):
                network_inspector.discover_hosts(
                    ipaddress.ip_network("192.0.2.0/23")
                )

            executor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
