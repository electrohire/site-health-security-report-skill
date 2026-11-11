# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 7 regressions: heading conjunctions, record-line attribution,
wrapped lines and fences, header prose isolation, DMARC tag edges."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
from test_round3 import SAMPLE_REPORT  # noqa: E402
from test_round4 import cfg, findings, header, run, SCANNERS_LINE  # noqa: E402


class TestRound7(unittest.TestCase):
    def test_conjunction_heading_variants_are_checked(self):
        for heading in ("SEO & AEO — grade F", "SEO AND AEO — grade F",
                        "TRAFFIC AND CLOUDFLARE — grade F",
                        "SECURITY AND GITHUB — grade F"):
            problems = sh.validate_report(SAMPLE_REPORT + "\n" + heading + "\n",
                                          findings())
            self.assertTrue(problems, heading)

    def test_second_contradictory_record_line_fails(self):
        report = header() + SCANNERS_LINE + SAMPLE_REPORT + \
            "\nScanners of record: renovate, semgrep, gitleaks.\n"
        self.assertTrue(run(cfg(), findings(), report))

    def test_record_line_inside_code_fence_does_not_count(self):
        report = header() + "```\n" + SCANNERS_LINE + "```\n" + SAMPLE_REPORT
        problems = run(cfg(), findings(), report)
        self.assertTrue(any("Scanners of record" in p for p in problems), problems)

    def test_slot_swapped_record_line_fails(self):
        line = ("Scanners of record: dependency scanning by CodeQL, "
                "code scanning by Dependabot, secret scanning by GitHub "
                "Secret Scanning.\n")
        problems = run(cfg(), findings(), header() + line + SAMPLE_REPORT)
        self.assertTrue(problems, problems)

    def test_negated_record_line_fails(self):
        line = ("Scanners of record: not Dependabot, not CodeQL, and not "
                "GitHub Secret Scanning (none of these ran).\n")
        problems = run(cfg(), findings(), header() + line + SAMPLE_REPORT)
        self.assertTrue(problems, problems)

    def test_wrapped_record_line_passes(self):
        line = ("Scanners of record: dependency scanning by Dependabot,\n"
                "code scanning by CodeQL, secret scanning by GitHub Secret "
                "Scanning.\n")
        self.assertEqual(run(cfg(), findings(), header() + line + SAMPLE_REPORT),
                         [])

    def test_bulleted_header_passes(self):
        block = (f"- From: reports@send.example.com\n"
                 f"- To: owner@example.com\n")
        self.assertEqual(run(cfg(), findings(), block + SCANNERS_LINE +
                             SAMPLE_REPORT), [])

    def test_body_prose_email_cannot_satisfy_cc(self):
        c = cfg()
        c["recipients"] = {"to": ["owner@example.com"],
                           "cc": ["boss@example.com"]}
        report = header() + \
            "Please loop in boss@example.com on this thread today.\n" + \
            SCANNERS_LINE + SAMPLE_REPORT
        problems = run(c, findings(), report)
        self.assertTrue(any("Cc" in p for p in problems), problems)

    def test_body_prose_email_does_not_pollute_cc(self):
        report = header() + \
            "Reviewed with auditor@vendor.example this morning.\n\n" + \
            SCANNERS_LINE + SAMPLE_REPORT
        self.assertEqual(run(cfg(), findings(), report), [])

    def test_dmarc_spaced_policy_tag(self):
        self.assertEqual(sh._norm_dmarc("v=DMARC1; p = reject"), "reject")

    def test_dmarc_conflicting_duplicate_policies_error(self):
        self.assertEqual(sh._norm_dmarc("v=DMARC1; p=none; p=reject"),
                         "v=dmarc1; p=none; p=reject")


if __name__ == "__main__":
    unittest.main()
