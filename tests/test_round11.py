# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 11 regressions: first-grade heading rule at any parenthetical
depth, doubly displaced post-name negation."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
from test_round3 import SAMPLE_REPORT  # noqa: E402
from test_round4 import cfg, findings, header, run  # noqa: E402


class TestRound11(unittest.TestCase):
    def test_two_level_nested_parenthetical_heading_is_checked(self):
        report = SAMPLE_REPORT + \
            "\nSEO / AEO — grade F (a (b (c) d) e)\n"
        problems = sh.validate_report(report, findings())
        self.assertTrue(any("seo" in p for p in problems), problems)

    def test_prose_after_closed_parenthetical_is_checked(self):
        report = SAMPLE_REPORT + \
            "\nSEO / AEO — grade F (draft) provisional\n"
        problems = sh.validate_report(report, findings())
        self.assertTrue(any("seo" in p for p in problems), problems)

    def test_parenthetical_phantom_still_impossible(self):
        report = SAMPLE_REPORT + \
            "\nSEO / AEO — grade A (the morning draft said grade F)\n"
        self.assertEqual(sh.validate_report(report, findings()), [])

    def test_doubly_displaced_negation_fails(self):
        line = ("Scanners of record: dependency scanning by Dependabot, "
                "code scanning by CodeQL it was really truly not used, "
                "secret scanning by GitHub Secret Scanning.\n")
        problems = run(cfg(), findings(), header() + line + SAMPLE_REPORT)
        self.assertTrue(any("sast" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
