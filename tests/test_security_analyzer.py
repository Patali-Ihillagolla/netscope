import unittest

import security_analyzer


class SecurityAnalyzerTests(unittest.TestCase):
    def test_classifies_known_and_unknown_open_ports(self):
        findings = security_analyzer.analyze_security(
            [
                (23, True),
                (80, True),
                (65000, True),
                (22, False),
            ]
        )

        self.assertEqual(
            [(finding["port"], finding["severity"]) for finding in findings],
            [(23, "HIGH"), (80, "MEDIUM"), (65000, "LOW")],
        )
        self.assertEqual(findings[0]["title"], "Telnet service exposed")
        self.assertEqual(findings[1]["title"], "HTTP service exposed")
        self.assertEqual(findings[2]["service"], "Unknown")

    def test_adds_multiple_services_finding_at_five_open_ports(self):
        findings = security_analyzer.analyze_security(
            [(port, True) for port in (21, 22, 23, 25, 53)]
        )

        self.assertEqual(len(findings), 6)
        self.assertEqual(findings[-1]["title"], "Multiple network services exposed")

    def test_calculates_heuristic_score_from_severities(self):
        findings = security_analyzer.analyze_security(
            [(23, True), (80, True), (65000, True), (22, True)]
        )

        self.assertEqual(
            security_analyzer.calculate_risk_score(findings),
            17,
        )

    def test_maps_risk_level_boundaries(self):
        expected_levels = {
            0: "MINIMAL",
            1: "LOW",
            14: "LOW",
            15: "MEDIUM",
            29: "MEDIUM",
            30: "HIGH",
        }

        for score, expected in expected_levels.items():
            with self.subTest(score=score):
                self.assertEqual(
                    security_analyzer.get_risk_level(score),
                    expected,
                )


if __name__ == "__main__":
    unittest.main()
