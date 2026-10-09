import io
import unittest
from collections import Counter
from contextlib import redirect_stdout

from scapy.all import DNS, DNSQR, ICMP, IP, Raw, TCP, UDP

import packet_analyzer
from service_detector import sanitize_banner


class PacketAnalyzerTests(unittest.TestCase):
    def test_classifies_common_synthetic_protocols(self):
        packets = (
            (IP() / TCP(), "TCP"),
            (IP() / UDP(), "UDP"),
            (
                IP() / UDP() / DNS(
                    rd=1,
                    qd=DNSQR(qname="example.test"),
                ),
                "DNS",
            ),
            (IP() / ICMP(), "ICMP"),
            (IP(), "IP"),
        )

        for packet, expected_protocol in packets:
            with self.subTest(protocol=expected_protocol):
                self.assertEqual(
                    packet_analyzer.get_protocol(packet),
                    expected_protocol,
                )

    def test_displays_packet_metadata_without_payload_or_dns_query(self):
        secret_text = "synthetic-private-payload"
        packet = (
            IP(src="192.0.2.1", dst="198.51.100.2")
            / TCP(sport=12345, dport=80, flags="S")
            / Raw(load=secret_text.encode())
        )
        statistics = Counter()
        output = io.StringIO()

        with redirect_stdout(output):
            packet_analyzer.analyze_packet(packet, 1, statistics)

        displayed = output.getvalue()
        self.assertIn("192.0.2.1", displayed)
        self.assertIn("198.51.100.2", displayed)
        self.assertIn("12345", displayed)
        self.assertNotIn(secret_text, displayed)
        self.assertEqual(statistics["TCP"], 1)

        dns_name = "private-query.example"
        dns_packet = (
            IP()
            / UDP()
            / DNS(rd=1, qd=DNSQR(qname=dns_name))
        )
        output = io.StringIO()
        with redirect_stdout(output):
            packet_analyzer.analyze_packet(dns_packet, 2, statistics)

        self.assertNotIn(dns_name, output.getvalue())
        self.assertEqual(statistics["DNS"], 1)

    def test_sanitizes_banner_controls_and_limits_length(self):
        banner = "start\nmiddle\r\x1b[31mred\x1b[0m\x1b]0;title\x07end"

        sanitized = sanitize_banner(banner)

        self.assertEqual(sanitized, "start middle redend")
        self.assertNotIn("\n", sanitized)
        self.assertNotIn("\r", sanitized)
        self.assertNotIn("\x1b", sanitized)
        self.assertLessEqual(len(sanitize_banner("x" * 100)), 50)


if __name__ == "__main__":
    unittest.main()
