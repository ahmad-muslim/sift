---
name: New Scanner Parser Request
about: Request or propose a new scanner adapter for sift
title: "[Parser]: "
labels: ["enhancement", "parser"]
---

## Scanner Name & Output Format
- **Scanner:** (e.g., Grype, OpenVAS, Nessus, Semgrep, Nikto)
- **Output format:** (e.g., JSON, JSONL, SARIF, XML)
- **CLI flag used to produce this output:**

## Sample Sanitized Output
Provide a small, anonymized sample of the scanner output (use RFC 5737 IPs like `192.0.2.10` and `.example` domains).

```
<paste sanitized sample here>
```

## Field Mapping Notes
How do the scanner's fields map to `target`, `port`, `service`, `cve_id`, `cvss_score`, `rule_id`, and `description`?
