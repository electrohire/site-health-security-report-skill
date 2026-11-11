# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 9 regressions: secrets attribution names the credited scanner,
unified heading tails, clause-scoped negation, all-caps header lines,
intervening labels, CLI argument shapes."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
from test_round3 import SAMPLE_REPORT  # noqa: E402
from test_round4 import cfg, findings, header, run, SCANNERS_LINE  # noqa: E402


class TestRound9(unittest.TestCase):
    def test_secret_scanning_by_another_scanner_fails(self):
        line = ("Scanners of record: dependency scanning by Dependabot, "
                "code scanning by CodeQL, secret scanning by Gitleaks.\n")
        problems = run(cfg(), findings(), header() + line + SAMPLE_REPORT)
        self.assertTrue(any("secrets" in p for p in problems), problems)

    def test_secret_scanning_by_the_configured_scanner_passes(self):
        self.assertEqual(
            run(cfg(), findings(), header() + SCANNERS_LINE + SAMPLE_REPORT), [])

    def test_gitlab_secret_detection_by_another_fails(self):
        c = cfg(code_host="gitlab", code_host_instance="saas")
        c["scanning"] = {"dependencies": "gitlab-dependency-scanning",
                         "sast": "gitlab-sast",
                         "secrets": "gitlab-secret-detection"}
        f = findings()
        f["security"]["scanners_used"] = {
            "dependencies": "gitlab-dependency-scanning",
            "sast": "gitlab-sast", "secrets": "gitlab-secret-detection"}
        line = ("Scanners of record: dependency scanning by GitLab "
                "Dependency Scanning, code scanning by GitLab SAST, "
                "secret detection by TruffleHog.\n")
        problems = run(c, f, header() + line + SAMPLE_REPORT)
        self.assertTrue(any("secrets" in p for p in problems), problems)

    def test_parenthetical_grade_text_does_not_phantom(self):
        report = SAMPLE_REPORT + \
            "\nSEO / AEO — grade A (the morning draft said grade F)\n"
        self.assertEqual(sh.validate_report(report, findings()), [])

    def test_unclosed_parenthetical_heading_is_checked(self):
        report = SAMPLE_REPORT + "\nSEO / AEO — grade F (provisional\n"
        problems = sh.validate_report(report, findings())
        self.assertTrue(any("seo" in p for p in problems), problems)

    def test_distant_negation_within_clause_fails(self):
        line = ("Scanners of record: not one single one of the following "
                "Dependabot, CodeQL, GitHub Secret Scanning.\n")
        self.assertTrue(run(cfg(), findings(), header() + line + SAMPLE_REPORT))

    def test_negation_does_not_bleed_across_clauses(self):
        line = ("Scanners of record: it is not true that these did not "
                "run; Dependabot, CodeQL, GitHub Secret Scanning.\n")
        self.assertEqual(run(cfg(), findings(), header() + line + SAMPLE_REPORT),
                         [])

    def test_never_enabled_is_negation(self):
        line = ("Scanners of record: Dependabot, CodeQL was never "
                "enabled, GitHub Secret Scanning.\n")
        problems = run(cfg(), findings(), header() + line + SAMPLE_REPORT)
        self.assertTrue(any("sast" in p for p in problems), problems)

    def test_all_caps_prose_cannot_satisfy_cc(self):
        c = cfg()
        c["recipients"] = {"to": ["owner@example.com"],
                           "cc": ["boss@example.com"]}
        report = header(cc=None) + "COPIES TO boss@example.com\n" + \
            SCANNERS_LINE + SAMPLE_REPORT
        problems = run(c, findings(), report)
        self.assertTrue(any("Cc" in p for p in problems), problems)

    def test_intervening_label_does_not_drop_block_cc(self):
        c = cfg()
        c["recipients"] = {"to": ["owner@example.com"],
                           "cc": ["boss@example.com"]}
        block = ("From: reports@send.example.com\nTo: owner@example.com\n"
                 "Cc:\nNotes: distribution below\n    boss@example.com\n")
        report = block + SCANNERS_LINE + SAMPLE_REPORT
        self.assertEqual(run(c, findings(), report), [])

    def test_kind_flag_does_not_eat_a_filename(self):
        kind, args = sh._split_kind(["report.md", "correction"])
        self.assertEqual(kind, "edition")
        self.assertEqual(args, ["report.md", "correction"])
        kind, args = sh._split_kind(["report.md", "--kind", "correction"])
        self.assertEqual(kind, "correction")
        self.assertEqual(args, ["report.md"])


if __name__ == "__main__":
    unittest.main()
