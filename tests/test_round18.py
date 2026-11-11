# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 18 regressions: classification_pending is a real schema
state (traffic leg ungraded, overall incomplete), it contradicts a
present burst record, and the stack-selection page's WAF sentence is
qualified."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
import fixtures  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


def base_findings():
    return copy.deepcopy(fixtures.HEALTHY_GITHUB_CLOUDFLARE)


class TestRound18(unittest.TestCase):
    def test_pending_leaves_traffic_ungraded(self):
        f = base_findings()
        f["traffic"]["five_xx_share"] = 0.168
        f["traffic"]["classification_pending"] = True
        result = sh.compute_grades(f)
        self.assertIsNone(result["traffic"])
        self.assertFalse(result["complete"])

    def test_pending_with_a_burst_record_is_a_contradiction(self):
        f = base_findings()
        f["traffic"]["classification_pending"] = True
        f["traffic"]["burst"] = {
            "total_errors": 100, "top_single_ip_errors": 90,
            "primary_host_errors": 5, "top_single_host_errors": 90}
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_pending_contradiction_holds_on_the_outage_path(self):
        f = base_findings()
        f["traffic"]["outage_confirmed"] = True
        f["traffic"]["classification_pending"] = True
        f["traffic"]["burst"] = {
            "total_errors": 100, "top_single_ip_errors": 7,
            "primary_host_errors": 90, "top_single_host_errors": 90}
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_waf_sentence_is_qualified(self):
        page = open(os.path.join(ROOT, "docs", "stack-selection.md")).read()
        self.assertIn("the full managed WAF rulesets start at Pro",
                      page)


if __name__ == "__main__":
    unittest.main()
