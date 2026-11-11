<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
White-label report template. {{placeholders}} come from the config and
the run's evidence records. Delete this comment before sending.
-->
{{brand.display_name}} {{cadence}} report — {{weekday}}, {{date}} (covering {{covering_text}})
From: {{sender}} · To: {{recipients.to}} · Cc: {{recipients.cc}}
<!-- sender comes from the config's `sender` field; every placeholder in this template is filled by hand or by your own renderer from the config, the findings file, and the edition's evidence records (references/findings-schema.md says which is which). -->
Subject: {{brand.display_name}} {{cadence}} report — {{date_short}}: overall grade {{overall}} (when the overall is incomplete, the subject carries it too: "overall grade {{overall}} (incomplete)")

OVERALL GRADE: {{overall}}
{{one_line_summary}}

Sub-grades: Traffic & reliability {{traffic_grade}} · SEO/AEO {{seo_grade}} · Security & code health {{security_grade}}
<!-- If a leg is ungraded, its slot reads "not available" instead of a letter, and the line above the grades must present the overall as incomplete: "OVERALL GRADE: {{overall}} (incomplete: {{ungraded_leg}} not available)". An ungraded leg's section heading reads "## {{SECTION}} — grade not available", and its cause line states the reason in plain words (for traffic: the error spike is reported, its classification is pending, and a correction will follow). If the traffic leg ran at lower fidelity (no edge, or an edge that cannot segment), say so on its section line: "Fidelity: {{fidelity_note}}". -->
{{#each downgrade_causes}}Why a {{grade}}: {{cause}} <!-- one line per cause the grading tool returned; for a leg graded A, print "no downgrade causes" instead of a Why-a line -->
{{/each}}

WHAT CHANGED SINCE THE LAST REPORT
- {{change_1}}
- {{change_2}}

TRAFFIC & {{edge_name}} — grade {{traffic_grade}}
- Requests: {{requests}} ({{requests_avg_text}}). Unique visitors: {{uniques}} ({{previous_period}} {{uniques_previous}}). Page views: {{page_views}} ({{previous_period}} {{page_views_previous}}). (Cadence fills: {{cadence}} is "daily" or "weekly"; {{covering_text}} is the covering date, or the covering range at weekly cadence; {{previous_period}} is "yesterday" or "last week". Fill {{requests_avg_text}} at daily cadence with "7-day average {{requests_avg}}", or until a full week of editions exists "average of the last {{n}} editions" or "not available, first edition"; at weekly cadence with "previous week {{requests_previous_week}}; daily average {{requests_daily_avg}} (previous week {{requests_daily_avg_previous}})". On the first edition, omit every comparison parenthetical and the dependency delta: no comparison figures appear anywhere, and they are never invented to fill the line.)
- Responses: {{success_share}} success (2xx, the request worked); client errors (4xx, the request was refused or missing) {{four_xx}} — of those "not found" (404, the page or file does not exist) {{n404}}; server errors (5xx, the origin failed to answer) {{five_xx}}.
- {{burst_or_anomaly_paragraph — apply the burst rule before writing the word outage}}
- Top paths and countries: {{top_paths_countries}}
Why a {{traffic_grade}}: {{traffic_causes}}

SEO / AEO — grade {{seo_grade}}
- AEO score ({{aeo_checker}}, scan {{aeo_scan_id}}): {{aeo_score}}/100. {{aeo_detail}} (When a score is null, replace this bullet with "{{aeo_checker}}: not available. The checker returned no result for this run; no score is carried over." The leg grades from the remaining score; it is not available only when both scores are null.)
- SEO score ({{seo_source_label}}, {{seo_scan_ref}}): {{seo_score}}/100. {{seo_detail}}
- Self-run on-page audit: {{audit_passed}} of 15.
Why a {{seo_grade}}: {{seo_causes}}

SECURITY & {{code_host_name}} — grade {{security_grade}}
- Dependency alerts open: {{dep_total}} ({{crit}} critical, {{high}} high, {{med}} medium, {{low}} low) across {{repo_count}} repos. {{dep_delta}}
- Code scanning: {{sast_state}} · Secret scanning: {{secret_state}}.
- Scanners of record: dependency scanning by {{dependencies_scanner_display}}, code scanning by {{sast_scanner_display}}, secret scanning by {{secrets_scanner_display}} (display names; check-run accepts the display forms of the configured scanners).
- Activity: {{commits}} commits, {{ci_runs}} CI runs; deploys: {{deploys}}.
Why a {{security_grade}}: {{security_causes}}

WEBSITE SECURITY SCANS
- Mozilla Observatory: {{observatory_grade}}, {{observatory_score}}/100. {{observatory_note}}
- Security headers: {{headers_count}} of 6 present. Content-Security-Policy: {{csp_state}}. {{headers_note}}
- SSL Labs: {{ssl_grade}}; certificate expires {{cert_expiry}}. TLS: {{tls_versions}}.
- Email authentication: SPF {{spf_state}}; DMARC {{dmarc_state}}; MX {{mx_state}}.
- DDoS posture: edge {{ddos_edge_state}}; API host {{ddos_api_state}}; origin protection {{origin_protection_state}}.

PRIVACY & COMPLIANCE
- Privacy policy names the correct controller: {{privacy_controller}}
- Voice/AI-chat data covered (if applicable): {{privacy_ai_data}}
- AI disclosure at first interaction: {{ai_disclosure}}
- Cookie consent visible: {{cookies}}
- Data-request route published: {{data_rights}}

RECOMMENDATIONS (ranked)
<!-- Solo deployment (the owner is the operator): each recommendation
carries its procedure in plain steps — where to go, what to click,
back up first where the change can break the site, what to check
afterwards, what to do if it breaks. And the "Why a" cause lines
above are glossed into plain language, never the tool's raw strings,
for a non-technical reader. -->
1. ({{owner}}) {{recommendation_1}}
2. ({{owner}}) {{recommendation_2}}
3. ({{owner}}) {{recommendation_3}}

Follow-up on last edition's recommendations (one line per item):
- {{follow_up_item_1}} — done / in progress / no movement / withdrawn (by the correction of {{date}}) (evidence: {{evidence}})
- {{follow_up_item_2}} — done / in progress / no movement / withdrawn (evidence: {{evidence}})
Standing items: {{standing_items_open}} open; closed this edition: {{standing_items_closed}} (annotate the config entry closed with the closing edition's covering date; never delete it).
