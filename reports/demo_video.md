# Pentest report draft: ACME Retail lab

Run `demo_video`. Models that answered: gemini-3.5-flash-lite, openai/gpt-oss-20b, qwen2.5:14b. Total latency 67.9 s. Draft for analyst review; authorized assets only.

## Executive summary

9 findings across 3 hosts (6 critical, 3 high by CVSS band); 3 are listed in the CISA KEV catalog. Findings are ranked by fuzzy priority using each asset's simulated exposure and criticality. Top 3 by priority: CVE-2021-41773 on Public website (Apache httpd) (172.30.0.12:80, priority 88.3 urgent); CVE-2021-42013 on Public website (Apache httpd) (172.30.0.12:80, priority 88.3 urgent); CVE-2022-22965 on Customer portal (Spring WebMVC, Java) (172.30.0.18:8080, priority 88.3 urgent). Scenario: Simulated ACME Retail environment: public website, online shop, customer portal and public API are internet-facing; the corporate CMS, a partner portal and a staging app sit in the DMZ; CI, logging, search and file sharing are internal only. In reality all containers are isolated on a local Docker network without internet access.

## Assets in this run (simulated scenario)

| Host | Asset | Zone | Exposure | Criticality |
|---|---|---|---|---|
| lab-host-12 | Public website (Apache httpd) | internet | 9 | 6 |
| lab-host-18 | Customer portal (Spring WebMVC, Java) | internet | 9 | 9 |
| lab-host-20 | Public API (Flask/Werkzeug, Python) | internet | 9 | 7 |

## Findings (ordered by fuzzy priority)

| # | Host:port | Asset | PID | Service | CVE | CVSS | EPSS | KEV | Priority | Label |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 172.30.0.12:80 | Public website (Apache httpd) | 4009745 | Apache httpd 2.4.49 | CVE-2021-41773 | 9.8 | 1.000 | yes | 88.3 | urgent |
| 2 | 172.30.0.12:80 | Public website (Apache httpd) | 4009745 | Apache httpd 2.4.49 | CVE-2021-42013 | 9.8 | 1.000 | yes | 88.3 | urgent |
| 3 | 172.30.0.18:8080 | Customer portal (Spring WebMVC, Java) | 4009981 | Spring Framework 5.3.17 | CVE-2022-22965 | 9.8 | 0.996 | yes | 88.3 | urgent |
| 4 | 172.30.0.12:80 | Public website (Apache httpd) | 4009745 | Apache httpd 2.4.49 | CVE-2021-44790 | 9.8 | 0.968 | no | 88.3 | urgent |
| 5 | 172.30.0.18:8080 | Customer portal (Spring WebMVC, Java) | 4009981 | Spring Framework 5.3.17 | CVE-2016-1000027 | 9.8 | 0.332 | no | 77.4 | urgent |
| 6 | 172.30.0.18:8080 | Customer portal (Spring WebMVC, Java) | 4009981 | Spring Framework 5.3.17 | CVE-2023-44794 | 9.8 | 0.013 | no | 65.6 | high |
| 7 | 172.30.0.20:5000 | Public API (Flask/Werkzeug, Python) | 4009519 | Werkzeug httpd 2.2.2 | CVE-2024-34069 | 7.5 | 0.034 | no | 52.5 | high |
| 8 | 172.30.0.20:5000 | Public API (Flask/Werkzeug, Python) | 4009519 | Werkzeug httpd 2.2.2 | CVE-2023-25577 | 7.5 | 0.014 | no | 52.5 | high |
| 9 | 172.30.0.20:5000 | Public API (Flask/Werkzeug, Python) | 4009519 | Werkzeug httpd 2.2.2 | CVE-2023-46136 | 7.5 | 0.013 | no | 52.5 | high |

## Finding 1: Apache httpd 2.4.49 path traversal and information disclosure

- Evidence: lab-host-12:80/tcp running Apache httpd 2.4.49
- PID: 4009745 (host inventory (lab))
- Version source: network scan
- CWE: CWE-22
- ATT&CK: T1083 (File and Directory Discovery)
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent
  - R8 (1.00): IF cvss is critical AND exposure is internet THEN priority is urgent

Remediation: Upgrade Apache HTTP Server to version 2.4.51 or later, where path normalization flaws are resolved. Ensure path normalization checks properly handle URL-encoded sequences and traversal patterns. Sources: MITRE CWE (CWE-22 Improper Limitation of a Pathname to a Restricted Directory, CWE-26 Path Traversal: '/dir/../filename').

References:
- CWE-22: https://cwe.mitre.org/data/definitions/22.html

## Finding 2: Apache httpd 2.4.49 path traversal and remote code execution

- Evidence: lab-host-12:80/tcp running Apache httpd 2.4.49
- PID: 4009745 (host inventory (lab))
- Version source: network scan
- CWE: CWE-22
- ATT&CK: T1083 (File and Directory Discovery)
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent
  - R8 (1.00): IF cvss is critical AND exposure is internet THEN priority is urgent

Remediation: Upgrade Apache HTTP Server to version 2.4.51 or later to fully address the incomplete fix for CVE-2021-41773. Restrict access to directory handlers and verify that Require all denied or equivalent access controls are enforced on sensitive document roots. Sources: MITRE CWE (CWE-22 Improper Limitation of a Pathname to a Restricted Directory).

References:
- CWE-22: https://cwe.mitre.org/data/definitions/22.html

## Finding 3: CVE-2022-22965 (Spring Framework RCE / Spring4Shell)

- Evidence: host: lab-host-18, port: 8080, service: Spring WebMVC, version: 5.3.17
- PID: 4009981 (host inventory (lab))
- Version source: host inventory (lab)
- CWE: CWE-94
- ATT&CK: T1059: Command and Scripting Interpreter
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent
  - R7 (1.00): IF criticality is high AND epss is high THEN priority is urgent
  - R8 (1.00): IF cvss is critical AND exposure is internet THEN priority is urgent

Remediation: Upgrade Spring Framework to version 5.3.18+, 5.2.20+, or later. Apply workarounds such as upgrading Tomcat if immediate patching is not possible. Sources: MITRE CWE (CWE-94 Improper Control of Generation of Code, https://cwe.mitre.org/data/definitions/94.html)

References:
- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- https://attack.mitre.org/techniques/T1059
- https://attack.mitre.org/techniques/T1190
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 4: Apache httpd 2.4.49 buffer overflow in mod_lua

- Evidence: lab-host-12:80/tcp running Apache httpd 2.4.49
- PID: 4009745 (host inventory (lab))
- Version source: network scan
- CWE: CWE-787
- ATT&CK: T1203 (Exploitation for Client Execution)
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent
  - R8 (1.00): IF cvss is critical AND exposure is internet THEN priority is urgent

Remediation: Upgrade Apache HTTP Server to version 2.4.52 or later to mitigate the mod_lua multipart parser buffer overflow. Disable mod_lua if Lua scripts are not actively required by the web application. Sources: MITRE CWE (CWE-787 Out-of-bounds Write).

References:
- CWE-787: https://cwe.mitre.org/data/definitions/787.html

## Finding 5: CVE-2016-1000027 (Pivotal Spring Framework RCE)

- Evidence: host: lab-host-18, port: 8080, service: Spring Framework, version: through 5.3.16
- PID: 4009981 (host inventory (lab))
- Version source: host inventory (lab)
- CWE: CWE-502
- ATT&CK: T1190: Exploit Public-Facing Application
- Fuzzy rules fired:
  - R8 (1.00): IF cvss is critical AND exposure is internet THEN priority is urgent
  - R9 (0.89): IF cvss is critical AND epss is medium THEN priority is high

Remediation: Upgrade Spring Framework to patched versions addressing remote code execution vulnerabilities in data binding/deserialization. Sources: MITRE CWE (CWE-502 Deserialization of Untrusted Data, https://cwe.mitre.org/data/definitions/502.html), OWASP WSTG (WSTG-INJT-22 Insecure Deserialization, https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization)

References:
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization
- https://attack.mitre.org/techniques/T1190

## Finding 6: CVE-2023-44794 (Dromara Sa-Token Privilege Escalation)

- Evidence: host: lab-host-18, port: 8080, service: Dromara Sa-Token, version: 1.36.0 and before
- PID: 4009981 (host inventory (lab))
- Version source: host inventory (lab)
- CWE: CWE-284
- ATT&CK: T1190: Exploit Public-Facing Application
- Fuzzy rules fired:
  - R8 (1.00): IF cvss is critical AND exposure is internet THEN priority is urgent
  - R10 (1.00): IF cvss is critical AND epss is low THEN priority is medium

Remediation: Update Dromara Sa-Token to versions after 1.36.0 where privilege escalation handling is corrected. Ensure explicit access control and trust zones are configured. Sources: MITRE CWE (CWE-284 Improper Access Control, https://cwe.mitre.org/data/definitions/284.html)

References:
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
- https://attack.mitre.org/techniques/T1190
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 7: CVE-2024-34069 Vulnerability

- Evidence: CVE-2024-34069
- PID: 4009519 (host inventory (lab))
- Version source: network scan
- CWE: CWE-352
- ATT&CK: T1185 Browser Session Hijacking
- Fuzzy rules fired:
  - R2 (0.75): IF exposure is internet AND cvss is high THEN priority is high
  - R13 (0.75): IF cvss is high AND epss is low THEN priority is medium
  - R20 (0.50): IF criticality is high AND cvss is high THEN priority is high

Remediation: Apply vendor patches or updates. Reference CWE-352: Cross-Site Request Forgery (https://cwe.mitre.org/data/definitions/352.html).

References:
- https://attack.mitre.org/techniques/T1185
- CWE-352: https://cwe.mitre.org/data/definitions/352.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 8: CVE-2023-25577 Vulnerability

- Evidence: CVE-2023-25577
- PID: 4009519 (host inventory (lab))
- Version source: network scan
- CWE: CWE-770
- ATT&CK: T1499 Endpoint Denial of Service
- Fuzzy rules fired:
  - R2 (0.75): IF exposure is internet AND cvss is high THEN priority is high
  - R13 (0.75): IF cvss is high AND epss is low THEN priority is medium
  - R20 (0.50): IF criticality is high AND cvss is high THEN priority is high

Remediation: Apply vendor patches or updates. Reference CWE-176: Improper Handling of Unicode Encoding (https://cwe.mitre.org/data/definitions/176.html).

References:
- https://attack.mitre.org/techniques/T1499
- https://cwe.mitre.org/data/definitions/176.html
- CWE-770: https://cwe.mitre.org/data/definitions/770.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 9: CVE-2023-46136 Vulnerability

- Evidence: CVE-2023-46136
- PID: 4009519 (host inventory (lab))
- Version source: network scan
- CWE: CWE-400, CWE-407, CWE-787
- ATT&CK: T1499 Endpoint Denial of Service
- Fuzzy rules fired:
  - R2 (0.75): IF exposure is internet AND cvss is high THEN priority is high
  - R13 (0.75): IF cvss is high AND epss is low THEN priority is medium
  - R20 (0.50): IF criticality is high AND cvss is high THEN priority is high

Remediation: Apply vendor patches or updates. Reference CWE-351: Insufficient Type Distinction (https://cwe.mitre.org/data/definitions/351.html).

References:
- https://attack.mitre.org/techniques/T1499
- https://cwe.mitre.org/data/definitions/351.html
- CWE-400: https://cwe.mitre.org/data/definitions/400.html
- CWE-407: https://cwe.mitre.org/data/definitions/407.html
- CWE-787: https://cwe.mitre.org/data/definitions/787.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization
