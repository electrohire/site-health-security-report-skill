<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Codex (OpenAI)

Copy `skills/site-health-security-report/` to `~/.codex/skills/site-health-security-report/` (or a project-local skills directory your Codex setup reads). Start a session and say: "Use the site-health-security-report skill. Run the stack intake first." Codex reads `SKILL.md` and pulls the reference files on demand. Scheduling: run the edition from a Codex automation or a plain cron entry that invokes your agent CLI with the prompt "Produce today's site health report edition from the saved config, gate it, validate it, and send it once under the standing authorization recorded in the signed-off config."
