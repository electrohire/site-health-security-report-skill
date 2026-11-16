# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Fleet rule (owner, 2026-11-16): no requirement numbers or
development references in any user-facing surface. The skill's
templates are user-facing surfaces (white-label report copy an
owner reads), so they must never carry spec numbers, claim ids,
task ids, register ids, or development-methodology framing."""
import re
import unittest
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parent.parent / "skills" / \
    "site-health-security-report" / "templates"

USER_FACING = [
    "report-template.md",
    "report-email.html",
    "correction-template.md",
    "evidence-ledger.example.md",
]

DEV_REF = re.compile(
    r"FR-\d|\bGAP-\d|\bGR-\d{2}\b|\bspec \d{3}\b|\bclaim C\d\b"
    r"|\bAEE\b|spec-kit",
    re.IGNORECASE,
)


class TestNoDevRefsInTemplates(unittest.TestCase):
    def test_templates_exist(self):
        for name in USER_FACING:
            self.assertTrue((TEMPLATES / name).is_file(), name)

    def test_no_dev_references_in_user_facing_templates(self):
        for name in USER_FACING:
            text = (TEMPLATES / name).read_text(encoding="utf-8")
            hits = DEV_REF.findall(text)
            self.assertEqual(hits, [], f"{name} carries dev references: {hits}")


if __name__ == "__main__":
    unittest.main()
