<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
White-label report template. {{placeholders}} come from the config and
the run's evidence records. Delete this comment before sending.
-->
{{brand.display_name}} daily report — {{weekday}}, {{date}} (covering {{covering_date}})
From: {{sender}} · To: {{recipients.to}} · Cc: {{recipients.cc}}
<!-- sender comes from the config's `sender` field; every placeholder in this template is filled by hand or by your own renderer from the config, the findings file, and the edition's evidence records (references/findings-schema.md says which is which). -->
Subject: {{brand.display_name}} daily report — {{date_short}}: overall grade {{overall}}

OVERALL GRADE: {{overall}}
{{one_line_summary}}

Sub-grades: Traffic & reliability {{traffic_grade}} · SEO/AEO {{seo_grade}} · Security & code health {{security_grade}}
{{#each downgrade_causes}}Why a {{grade}}: {{cause}} <!-- one line per cause the grading tool returned; for a leg graded A, print "no downgrade causes" instead of a Why-a line -->
{{/each}}

WHAT CHANGED SINCE THE LAST REPORT
- {{change_1}}
- {{change_2}}

TRAFFIC & {{edge_name}} — grade {{traffic_grade}}
- Requests: {{requests}} (7-day average {{requests_avg}}). Unique visitors: {{uniques}}. Page views: {{page_views}}.
- Responses: {{success_share}} success (2xx, the request worked); client errors (4xx, the request was refused or missing) {{four_xx}} — of those "not found" (404, the page or file does not exist) {{n404}}; server errors (5xx, the origin failed to answer) {{five_xx}}.
- {{burst_or_anomaly_paragraph — apply the burst rule before writing the word outage}}
- Top paths and countries: {{top_paths_countries}}
Why a {{traffic_grade}}: {{traffic_causes}}

SEO / AEO — grade {{seo_grade}}
- AEO score ({{aeo_checker}}, scan {{aeo_scan_id}}): {{aeo_score}}/100. {{aeo_detail}}
- SEO score ({{seo_source_label}}, {{seo_scan_ref}}): {{seo_score}}/100. {{seo_detail}}
- Self-run on-page audit: {{audit_passed}} of 15.
Why a {{seo_grade}}: {{seo_causes}}

SECURITY & {{code_host_name}} — grade {{security_grade}}
- Dependency alerts open: {{dep_total}} ({{crit}} critical, {{high}} high, {{med}} medium, {{low}} low) across {{repo_count}} repos. {{dep_delta}}
- Code scanning: {{sast_state}} · Secret scanning: {{secret_state}}.
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
1. ({{owner}}) {{recommendation_1}}
2. ({{owner}}) {{recommendation_2}}
3. ({{owner}}) {{recommendation_3}}

Last edition's recommendations: {{follow_up}}
