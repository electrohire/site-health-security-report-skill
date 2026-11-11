# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ElectroHire Inc.
"""Round 29 regressions: the never-a-traceback guarantee covers the
network command and pathological JSON too, and --kind accepts only
its two values."""

import http.client
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402


class TestRound29(unittest.TestCase):
    def test_fetch_headers_on_bad_status_line_is_a_clean_error(self):
        with mock.patch("urllib.request.urlopen",
                        side_effect=http.client.BadStatusLine("HELLO")):
            with self.assertRaises(sh.InputError):
                sh.fetch_headers("https://example.com/")

    def test_load_json_on_deeply_nested_input_is_a_clean_error(self):
        payload = '{"a": ' + "[" * 20000 + "]" * 20000 + "}"
        with mock.patch("builtins.open", return_value=io.StringIO(payload)):
            with self.assertRaises(sh.InputError):
                sh._load_json("findings.json")

    def test_split_kind_rejects_an_unknown_value(self):
        with self.assertRaises(sh.InputError):
            sh._split_kind(["report.md", "--kind", "banana"])

    def test_split_kind_rejects_a_dangling_flag(self):
        with self.assertRaises(sh.InputError):
            sh._split_kind(["report.md", "--kind"])

    def test_split_kind_still_accepts_both_kinds(self):
        self.assertEqual(sh._split_kind(["r", "--kind", "correction"]),
                         ("correction", ["r"]))
        self.assertEqual(sh._split_kind(["r"]), ("edition", ["r"]))
        self.assertEqual(sh._split_kind(["correction"]),
                         ("edition", ["correction"]))


if __name__ == "__main__":
    unittest.main()
