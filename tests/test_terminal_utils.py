import unittest

from terminal_utils import sanitize_terminal_text


class TerminalTextTests(unittest.TestCase):
    def test_removes_terminal_sequences_and_control_characters(self):
        text = "name\x1b[31mred\x1b[0m\x1b]0;title\x07\tline\nend"

        self.assertEqual(
            sanitize_terminal_text(text),
            "namered line end",
        )

    def test_preserves_harmless_text_and_bounds_long_values(self):
        self.assertEqual(
            sanitize_terminal_text("Ethernet Adapter"),
            "Ethernet Adapter",
        )
        self.assertEqual(
            sanitize_terminal_text("x" * 200, max_length=20),
            "x" * 17 + "...",
        )


if __name__ == "__main__":
    unittest.main()
