# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ElectroHire Inc.
"""Round 8 regressions: attribution separators, bullet variants,
negation shapes, label-shaped header lines, header past line 15,
heading prose false positives."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
from test_round3 import SAMPLE_REPORT  # noqa: E402
from test_round4 import cfg, findings, header, run, SCANNERS_LINE  # noqa: E402


class TestRound8(unittest.TestCase):
    def test_and_separated_slot_swap_fails(self):
        line = ("Scanners of record: dependency scanning by CodeQL and "
                "code scanning by Dependabot and secret scanning by "
                "GitHub Secret Scanning.\n")
        self.assertTrue(run(cfg(), findings(), header() + line + SAMPLE_REPORT))

    def test_bullet_record_line_recognized(self):
        line = "• Scanners of record: dependabot, codeql, secret-scanning.\n"
        self.assertEqual(run(cfg(), findings(), header() + line + SAMPLE_REPORT),
                         [])

    def test_distant_negation_fails(self):
        line = ("Scanners of record: not a single one of Dependabot, "
                "CodeQL or GitHub Secret Scanning ran today.\n")
        self.assertTrue(run(cfg(), findings(), header() + line + SAMPLE_REPORT))

    def test_post_name_negation_fails(self):
        line = ("Scanners of record: Dependabot, CodeQL, and GitHub "
                "Secret Scanning was not used.\n")
        problems = run(cfg(), findings(), header() + line + SAMPLE_REPORT)
        self.assertTrue(any("secrets" in p for p in problems), problems)

    def test_not_only_construction_passes(self):
        line = ("Scanners of record: not only Dependabot but also CodeQL "
                "and GitHub Secret Scanning.\n")
        self.assertEqual(run(cfg(), findings(), header() + line + SAMPLE_REPORT),
                         [])

    def test_label_shaped_line_cannot_satisfy_cc(self):
        c = cfg()
        c["recipients"] = {"to": ["owner@example.com"],
                           "cc": ["boss@example.com"]}
        report = header(cc=None) + "Notes: boss@example.com\n" + \
            SCANNERS_LINE + SAMPLE_REPORT
        problems = run(c, findings(), report)
        self.assertTrue(any("Cc" in p for p in problems), problems)

    def test_label_shaped_line_does_not_pollute_cc(self):
        report = header() + "Notes: auditor@vendor.example\n\n" + \
            SCANNERS_LINE + SAMPLE_REPORT
        self.assertEqual(run(cfg(), findings(), report), [])

    def test_header_may_extend_past_line_15(self):
        block = ("filler\n" * 14 +
                 "From: reports@send.example.com\n"
                 "To: owner@example.com\nCc: \n")
        self.assertEqual(run(cfg(), findings(), block + SCANNERS_LINE +
                             SAMPLE_REPORT), [])

    def test_prose_grade_sentence_is_not_a_heading(self):
        report = SAMPLE_REPORT + \
            "\nSecurity and GitHub — grade F was avoided only because " \
            "scanning came back.\n"
        self.assertEqual(sh.validate_report(report, findings()), [])

    def test_record_line_prose_continuation_not_absorbed(self):
        line = ("Scanners of record: dependency scanning by Dependabot.\n"
                "CodeQL and GitHub Secret Scanning are named in this "
                "separate prose sentence.\n")
        problems = run(cfg(), findings(), header() + line + SAMPLE_REPORT)
        self.assertTrue(problems, problems)


if __name__ == "__main__":
    unittest.main()
