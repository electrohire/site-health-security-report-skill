# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ElectroHire Inc.
"""Round 14 regressions: the honest 'none' mirror value is not an
assertion, the dash-form record-line credit is caught for 'none'
kinds, and standing_items has an enforced shape."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
from test_round3 import SAMPLE_REPORT  # noqa: E402
from test_round4 import cfg, findings, header, run  # noqa: E402


def _none_setup():
    c = cfg()
    c["scanning"]["dependencies"] = "none"
    f = findings()
    for k in ("critical", "high", "medium", "low", "total_open"):
        f["security"][k] = None
    return c, f


class TestRound14(unittest.TestCase):
    def test_scanners_used_none_mirror_is_not_an_assertion(self):
        c, f = _none_setup()
        f["security"]["scanners_used"]["dependencies"] = "none"
        problems = run(c, f, header() + SAMPLE_REPORT)
        self.assertFalse(any("scanners_used names" in p for p in problems),
                         problems)

    def test_dash_form_credit_for_none_kind_is_flagged(self):
        c, f = _none_setup()
        del f["security"]["scanners_used"]["dependencies"]
        line = ("Scanners of record: dependency scanning — Dependabot; "
                "code scanning by CodeQL; secret scanning by GitHub "
                "Secret Scanning.\n")
        problems = run(c, f, header() + line + SAMPLE_REPORT)
        self.assertTrue(any("credits a dependencies scanner" in p
                            for p in problems), problems)

    def test_role_only_segment_for_none_kind_is_not_a_credit(self):
        c, f = _none_setup()
        del f["security"]["scanners_used"]["dependencies"]
        line = ("Scanners of record: code scanning by CodeQL; secret "
                "scanning by GitHub Secret Scanning.\n")
        problems = run(c, f, header() + line + SAMPLE_REPORT)
        self.assertFalse(any("credits a dependencies" in p
                             for p in problems), problems)

    def test_standing_items_shape_is_validated(self):
        c = cfg()
        c["standing_items"] = [{"item": "x"}]
        self.assertTrue(any("standing_items" in e
                            for e in sh.validate_config(c)))
        c["standing_items"] = "a bare string"
        self.assertTrue(any("standing_items" in e
                            for e in sh.validate_config(c)))
        c["standing_items"] = ["fine as a string"]
        self.assertFalse(any("standing_items" in e
                             for e in sh.validate_config(c)))


if __name__ == "__main__":
    unittest.main()
