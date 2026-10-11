import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import netscope


class TargetValidationTests(unittest.TestCase):
    def validate_target(self, *values):
        output = io.StringIO()
        with patch("builtins.input", side_effect=values), redirect_stdout(output):
            result = netscope.get_target_ip()

        return result, output.getvalue()

    def test_accepts_ipv4_target(self):
        result, message = self.validate_target("192.168.1.10")

        self.assertEqual(result, "192.168.1.10")
        self.assertEqual(message, "")

    def test_retries_after_ipv6_target(self):
        result, message = self.validate_target("2001:db8::1", "192.0.2.10")

        self.assertEqual(result, "192.0.2.10")
        self.assertIn("IPv6 addresses are not supported", message)

    def test_retries_after_malformed_and_abbreviated_targets(self):
        result, message = self.validate_target(
            "not-an-ip",
            "",
            "127.1",
            "192.0.2.10",
        )

        self.assertEqual(result, "192.0.2.10")
        self.assertEqual(message.count("Invalid IPv4 address"), 3)


if __name__ == "__main__":
    unittest.main()
