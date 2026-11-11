# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ElectroHire Inc.
"""Round 10 regressions: parenthetical credit form, title-case prose
header lines, nested parenthetical heading tails, displaced post-name
negation."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
from test_round3 import SAMPLE_REPORT  # noqa: E402
from test_round4 import cfg, findings, header, run, SCANNERS_LINE  # noqa: E402


class TestRound10(unittest.TestCase):
    def test_parenthetical_credit_by_another_scanner_fails(self):
        line = ("Scanners of record: dependency scanning (Dependabot), "
                "secret scanning (Gitleaks), code scanning (CodeQL).\n")
        problems = run(cfg(), findings(), header() + line + SAMPLE_REPORT)
        self.assertTrue(any("secrets" in p for p in problems), problems)

    def test_parenthetical_credit_by_configured_scanners_passes(self):
        line = ("Scanners of record: dependency scanning (Dependabot), "
                "secret scanning (GitHub Secret Scanning), code scanning "
                "(CodeQL).\n")
        self.assertEqual(run(cfg(), findings(), header() + line + SAMPLE_REPORT),
                         [])

    def test_title_case_prose_cannot_satisfy_cc(self):
        c = cfg()
        c["recipients"] = {"to": ["owner@example.com"],
                           "cc": ["boss@example.com"]}
        report = header(cc=None) + "Copies To boss@example.com\n" + \
            SCANNERS_LINE + SAMPLE_REPORT
        problems = run(c, findings(), report)
        self.assertTrue(any("Cc" in p for p in problems), problems)

    def test_nested_parenthetical_heading_is_checked(self):
        report = SAMPLE_REPORT + \
            "\nSEO / AEO — grade F (draft (revised) notes)\n"
        problems = sh.validate_report(report, findings())
        self.assertTrue(any("seo" in p for p in problems), problems)

    def test_displaced_post_name_negation_fails(self):
        line = ("Scanners of record: dependency scanning by Dependabot, "
                "code scanning by CodeQL it was not used, secret scanning "
                "by GitHub Secret Scanning.\n")
        problems = run(cfg(), findings(), header() + line + SAMPLE_REPORT)
        self.assertTrue(any("sast" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
