# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 33 regressions: multi-marker emphasis (***F***, ** F **,
~~F~~) normalizes before every grade check; a sentence that merely
mentions an angle-bracketed address is prose and cannot satisfy a
header recipient set, while the 'Name <addr>' form still harvests;
traffic.side_host_outage is cross-checked against the config (not
the primary host, and one of the configured side hosts);
security.platform.source must be a non-empty string."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
import fixtures  # noqa: E402
from test_round4 import cfg, findings, header, SCANNERS_LINE  # noqa: E402
from fixtures import SAMPLE_REPORT  # noqa: E402

REPORT = header() + SCANNERS_LINE + SAMPLE_REPORT
GRADES = sh.compute_grades(findings())


def wrong(grade):
    return "A" if grade != "A" else "F"


def base():
    return copy.deepcopy(fixtures.HEALTHY_GITHUB_CLOUDFLARE)


class TestMultiMarkerEmphasis(unittest.TestCase):
    def test_base_report_is_clean(self):
        self.assertEqual(sh.validate_report(REPORT, findings()), [])

    def test_bold_italic_overall_is_checked(self):
        bad = f"Overall grade: ***{wrong(GRADES['overall'])}***\n"
        problems = sh.validate_report(bad + REPORT, findings())
        self.assertTrue(any("overall grade contradiction" in p
                            for p in problems))

    def test_spaced_bold_overall_is_checked(self):
        bad = f"Overall grade: ** {wrong(GRADES['overall'])} **\n"
        problems = sh.validate_report(bad + REPORT, findings())
        self.assertTrue(any("overall grade contradiction" in p
                            for p in problems))

    def test_struck_overall_is_checked(self):
        bad = f"Overall grade: ~~{wrong(GRADES['overall'])}~~\n"
        problems = sh.validate_report(bad + REPORT, findings())
        self.assertTrue(any("overall grade contradiction" in p
                            for p in problems))

    def test_correct_multi_marker_overall_passes(self):
        good = f"Overall grade: ***{GRADES['overall']}***\n"
        problems = sh.validate_report(good + REPORT, findings())
        self.assertFalse(any("overall grade contradiction" in p
                             for p in problems))


class TestAngleBracketProse(unittest.TestCase):
    def test_sentence_mentioning_an_address_is_not_addressish(self):
        line = ("Someone said the other recipient is somebody "
                "<bob@example.com> yesterday in a meeting")
        self.assertFalse(sh._addressish(line))

    def test_name_angle_form_still_harvests(self):
        self.assertTrue(sh._addressish("bob <bob@example.com>"))
        self.assertTrue(sh._addressish("Bob Smith <bob@example.com>"))

    def test_prose_cannot_satisfy_a_missing_recipient(self):
        c = cfg()
        c["recipients"] = {"to": ["owner@example.com"],
                           "cc": ["bob@example.com"]}
        prose = ("Someone said the other recipient is somebody "
                 "<bob@example.com> yesterday in a meeting\n")
        report = header() + prose + SCANNERS_LINE + SAMPLE_REPORT
        problems = sh.validate_run(c, findings(), report)[0]
        self.assertTrue(any("cc" in p.lower() for p in problems),
                        problems)


class TestSideHostOutageCrossCheck(unittest.TestCase):
    def _problems(self, host):
        f = base()
        f["traffic"]["side_host_outage"] = {"host": host,
                                            "note": "down 3h"}
        return sh.validate_run(cfg(), f, REPORT)[0]

    def test_primary_host_through_the_side_path_is_a_problem(self):
        problems = self._problems("example.com")
        self.assertTrue(any("side_host_outage" in p
                            and "primary" in p for p in problems),
                        problems)

    def test_unconfigured_host_is_a_problem(self):
        problems = self._problems("unrelated.example.org")
        self.assertTrue(any("side_host_outage" in p for p in problems),
                        problems)

    def test_configured_side_host_is_accepted(self):
        problems = self._problems("api.example.com")
        self.assertFalse(any("side_host_outage" in p
                             for p in problems), problems)


class TestPlatformSourceType(unittest.TestCase):
    def test_non_string_source_is_an_input_error(self):
        for bad in (123, ["feed"], {"x": 1}, True):
            f = base()
            f["security"]["platform"] = {"source": bad, "critical": 0,
                                         "high": 1}
            with self.assertRaises(sh.InputError, msg=repr(bad)):
                sh.compute_grades(f)

    def test_string_source_grades(self):
        f = base()
        f["security"]["platform"] = {"source": "vendor feed",
                                     "critical": 0, "high": 1}
        self.assertEqual(sh.compute_grades(f)["security"], "C")


if __name__ == "__main__":
    unittest.main()
