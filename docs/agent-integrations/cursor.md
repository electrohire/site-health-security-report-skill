<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Cursor

Cursor does not read SKILL.md natively. Copy the skill folder into the project (for example `tools/site-health-report/`) and add a Cursor rule (`.cursor/rules/site-health-report.mdc`) whose body says: "When asked to produce or check the site health report, follow `tools/site-health-report/SKILL.md` exactly, including the stack intake, grading, and verification references it points to." Cursor agents then follow the same method, including the gate and validation steps.
