import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import netscope


class TargetValidationTests(unittest.TestCase):
    def validate_target(self, value):
        output = io.StringIO()
        with patch("builtins.input", return_value=value), redirect_stdout(output):
            result = netscope.get_target_ip()

        return result, output.getvalue()

    def test_accepts_ipv4_target(self):
        result, message = self.validate_target("192.168.1.10")

        self.assertEqual(result, "192.168.1.10")
        self.assertEqual(message, "")

    def test_rejects_ipv6_target(self):
        result, message = self.validate_target("2001:db8::1")

        self.assertIsNone(result)
        self.assertIn("IPv6 addresses are not supported", message)

    def test_rejects_malformed_and_empty_targets(self):
        for value in ("not-an-ip", ""):
            with self.subTest(value=value):
                result, message = self.validate_target(value)

                self.assertIsNone(result)
                self.assertIn("Invalid IPv4 address", message)


if __name__ == "__main__":
    unittest.main()
