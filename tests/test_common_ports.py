import contextlib
import io
import unittest
from unittest.mock import patch

import netscope
import security_analyzer
import service_detector
import tcp_scanner
from common_ports import COMMON_PORTS


class CommonPortTests(unittest.TestCase):
    def test_scanners_share_the_same_inventory_including_telnet(self):
        self.assertIs(tcp_scanner.COMMON_PORTS, COMMON_PORTS)
        self.assertIs(service_detector.COMMON_PORTS, COMMON_PORTS)
        self.assertIs(security_analyzer.COMMON_PORTS, COMMON_PORTS)
        self.assertIs(netscope.COMMON_PORTS, COMMON_PORTS)
        self.assertEqual(len(COMMON_PORTS), 14)
        self.assertEqual(COMMON_PORTS[23], "Telnet")

    def test_standalone_scanners_retry_and_use_the_shared_inventory(self):
        cases = (
            (tcp_scanner, "scan_ports"),
            (service_detector, "scan_services"),
            (security_analyzer, "scan_ports"),
        )

        for module, scanner_name in cases:
            with self.subTest(module=module.__name__):
                scanner = getattr(module, scanner_name)
                with (
                    patch(
                        "builtins.input",
                        side_effect=["127.1", "192.0.2.10"],
                    ),
                    patch.object(module, scanner_name, return_value=[]) as scan,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    module.main()

                scan.assert_called_once_with(
                    "192.0.2.10",
                    COMMON_PORTS.keys(),
                )

    def test_menu_service_detection_uses_the_shared_inventory(self):
        with (
            patch.object(
                netscope,
                "get_target_ip",
                return_value="192.0.2.10",
            ),
            patch.object(netscope, "scan_services", return_value=[]) as scan,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            netscope.service_detection()

        scan.assert_called_once_with(
            "192.0.2.10",
            COMMON_PORTS.keys(),
        )


if __name__ == "__main__":
    unittest.main()
