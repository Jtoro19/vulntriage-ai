# Pentest report draft: VulnTriage isolated lab (simulated ACME Retail)

Run `sample_full_lab`. Models that answered: gemini-3.5-flash-lite, openai/gpt-oss-20b. Total latency 227.9 s. Draft for analyst review; authorized assets only.

## Executive summary

16 findings across 11 hosts (11 critical, 1 high, 4 medium by CVSS band); 6 are listed in the CISA KEV catalog. Findings are ranked by fuzzy priority using each asset's simulated exposure and criticality. Top 3 by priority: CVE-2021-41773 on Public website (Apache httpd) (172.30.0.12:80, priority 88.3 urgent); CVE-2021-42013 on Public website (Apache httpd) (172.30.0.12:80, priority 88.3 urgent); CVE-2025-24813 on Partner portal (Tomcat) (172.30.0.13:8080, priority 88.3 urgent). Scenario: Simulated ACME Retail environment: public website, online shop, customer portal and public API are internet-facing; the corporate CMS, a partner portal and a staging app sit in the DMZ; CI, logging, search and file sharing are internal only. In reality all containers are isolated on a local Docker network without internet access.

## Assets in this run (simulated scenario)

| Host | Asset | Zone | Exposure | Criticality |
|---|---|---|---|---|
| lab-host-10 | Staging web app (DVWA) | dmz | 6 | 3 |
| lab-host-11 | Online shop (Juice Shop) | internet | 9 | 8 |
| lab-host-12 | Public website (Apache httpd) | internet | 9 | 6 |
| lab-host-13 | Partner portal (Tomcat) | dmz | 6 | 7 |
| lab-host-14 | Corporate CMS (Drupal) | dmz | 6 | 5 |
| lab-host-15 | File share (Samba) | internal | 2 | 6 |
| lab-host-16 | CI server (Jenkins) | internal | 2 | 9 |
| lab-host-17 | Log search (Elasticsearch) | internal | 2 | 7 |
| lab-host-18 | Customer portal (Spring WebMVC, Java) | internet | 9 | 9 |
| lab-host-19 | Product search (Apache Solr, Java) | internal | 2 | 6 |
| lab-host-20 | Public API (Flask/Werkzeug, Python) | internet | 9 | 7 |

## Findings (ordered by fuzzy priority)

| # | Host:port | Asset | PID | Service | CVE | CVSS | EPSS | KEV | Priority | Label |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 172.30.0.12:80 | Public website (Apache httpd) | 184072 | Apache httpd 2.4.49 | CVE-2021-41773 | 9.8 | 1.000 | yes | 88.3 | urgent |
| 2 | 172.30.0.12:80 | Public website (Apache httpd) | 184072 | Apache httpd 2.4.49 | CVE-2021-42013 | 9.8 | 1.000 | yes | 88.3 | urgent |
| 3 | 172.30.0.13:8080 | Partner portal (Tomcat) | 183583 | Apache Tomcat 8.5.19 | CVE-2025-24813 | 9.8 | 0.999 | yes | 88.3 | urgent |
| 4 | 172.30.0.17:9200 | Log search (Elasticsearch) | 190429 | Elasticsearch REST API 1.4.2 | CVE-2015-1427 | 9.8 | 0.999 | yes | 88.3 | urgent |
| 5 | 172.30.0.18:8080 | Customer portal (Spring WebMVC, Java) | 228610 | Spring Framework 5.3.17 | CVE-2022-22965 | 9.8 | 0.996 | yes | 88.3 | urgent |
| 6 | 172.30.0.13:8080 | Partner portal (Tomcat) | 183583 | Apache Tomcat 8.5.19 | CVE-2020-1938 | 9.8 | 0.993 | yes | 88.3 | urgent |
| 7 | 172.30.0.10:80 | Staging web app (DVWA) | 184359 | Apache httpd 2.4.25 | CVE-2021-44790 | 9.8 | 0.968 | no | 88.3 | urgent |
| 8 | 172.30.0.14:80 | Corporate CMS (Drupal) | 184000 | Apache httpd 2.4.25 | CVE-2021-44790 | 9.8 | 0.968 | no | 88.3 | urgent |
| 9 | 172.30.0.19:8983 | Product search (Apache Solr, Java) | 228777 | Apache Solr 8.11.0 | CVE-2024-45216 | 9.8 | 0.927 | no | 88.3 | urgent |
| 10 | 172.30.0.10:80 | Staging web app (DVWA) | 184359 | Apache httpd 2.4.25 | CVE-2023-25690 | 9.8 | 0.840 | no | 88.3 | urgent |
| 11 | 172.30.0.14:80 | Corporate CMS (Drupal) | 184000 | Apache httpd 2.4.25 | CVE-2023-25690 | 9.8 | 0.840 | no | 88.3 | urgent |
| 12 | 172.30.0.16:8080 | CI server (Jenkins) | 200426 | CI server (Jenkins) (http) | CVE-2019-10405 | 5.4 | 0.653 | no | 53.1 | high |
| 13 | 172.30.0.20:5000 | Public API (Flask/Werkzeug, Python) | 231471 | Werkzeug httpd 2.2.2 | CVE-2024-34069 | 7.5 | 0.034 | no | 52.5 | high |
| 14 | 172.30.0.18:8080 | Customer portal (Spring WebMVC, Java) | 228610 | Spring Framework 5.3.17 | CVE-2023-45648 | 5.3 | 0.059 | no | 37.5 | medium |
| 15 | 172.30.0.13:8080 | Partner portal (Tomcat) | 183583 | Partner portal (Tomcat) (http) | CVE-2023-45648 | 5.3 | 0.059 | no | 13.7 | low |
| 16 | 172.30.0.16:8080 | CI server (Jenkins) | 200426 | CI server (Jenkins) (http) | CVE-2020-2103 | 5.4 | 0.070 | no | 13.7 | low |

## Finding 1: Apache HTTP Server Path Traversal and RCE

- Evidence: lab-host-12:80/tcp running Apache httpd 2.4.49
- PID: 184072 (host inventory (lab))
- Version source: network scan
- CWE: CWE-22
- ATT&CK: T1083 (File and Directory Discovery) / T1574 (Path Interception / Execution)
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent
  - R8 (1.00): IF cvss is critical AND exposure is internet THEN priority is urgent

Remediation: Upgrade Apache HTTP Server to version 2.4.51 or later, or properly configure Require all denied on directory blocks and ensure Alias directives are tightly scoped. Sources: MITRE CWE: CWE-22 Improper Limitation of a Pathname to a Restricted Directory (https://cwe.mitre.org/data/definitions/22.html); OWASP Web Security Testing Guide (WSTG) / CWE Catalog: Inputs should be decoded and canonicalized to the application's internal representation before validation. Use vetted libraries or frameworks that do not allow path traversal constructs.

References:
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- https://attack.mitre.org/techniques/T1083

## Finding 2: Apache HTTP Server Insufficient Fix Path Traversal and RCE

- Evidence: lab-host-12:80/tcp running Apache httpd 2.4.49 (vulnerable to the related follow-on issue affecting 2.4.49/2.4.50)
- PID: 184072 (host inventory (lab))
- Version source: network scan
- CWE: CWE-22
- ATT&CK: T1083 (File and Directory Discovery) / T1574 (Path Interception / Execution)
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent
  - R8 (1.00): IF cvss is critical AND exposure is internet THEN priority is urgent

Remediation: Upgrade Apache HTTP Server to version 2.4.51 or later to address incomplete fixes for path normalization and URL-encoding bypasses. Ensure mod_alias and directory access controls are strictly enforced. Sources: MITRE CWE: CWE-22 Improper Limitation of a Pathname to a Restricted Directory (https://cwe.mitre.org/data/definitions/22.html); OWASP Web Security Testing Guide (WSTG) / CWE Catalog: Ensure that application input validation canonicalizes paths correctly and avoids double-decoding flaws.

References:
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- https://attack.mitre.org/techniques/T1083

## Finding 3: Apache Tomcat 8.5.19 CVE-2025-24813

- Evidence: Apache Tomcat 8.5.19 exposed on port 8080.
- PID: 183583 (host inventory (lab))
- Version source: network scan
- CWE: CWE-44, CWE-502, CWE-706
- ATT&CK: T1190 (Exploit Public-Facing Application)
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent
  - R7 (0.50): IF criticality is high AND epss is high THEN priority is urgent

Remediation: Upgrade Apache Tomcat to a patched version or disable write-enabled Default Servlet features. Sources: MITRE CWE (CWE-502 Deserialization of Untrusted Data), OWASP WSTG (WSTG-INJT-22 Insecure Deserialization).

References:
- MITRE CWE (CWE-502 Deserialization of Untrusted Data)
- OWASP WSTG (WSTG-INJT-22 Insecure Deserialization)
- CWE-44: https://cwe.mitre.org/data/definitions/44.html
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- CWE-706: https://cwe.mitre.org/data/definitions/706.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 4: Elasticsearch REST API 1.4.2 remote code execution

- Evidence: Nmap scan identified Elasticsearch REST API version 1.4.2 running on port 9200/tcp.
- PID: 190429 (host inventory (lab))
- Version source: network scan
- CWE: n/a
- ATT&CK: T1648 Serverless Execution / T1203 Exploitation for Client Execution
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent
  - R7 (0.50): IF criticality is high AND epss is high THEN priority is urgent

Remediation: Upgrade Elasticsearch to version 1.4.3 (or later) where the Groovy sandbox vulnerability is resolved. Disable dynamic scripting in Elasticsearch configuration (script.groovy.inline: off or script.disable_inline: true) if upgrading immediately is not feasible. Sources: OWASP WSTG, CWE Catalog.

References:
- https://owasp.org/www-project-web-security-testing-guide/latest/17-WebAssembly_Testing/03-WebAssembly_Dynamic_Analysis
- https://owasp.org/www-project-web-security-testing-guide/latest/17-WebAssembly_Testing/02-WebAssembly_Static_Analysis
- https://attack.mitre.org/techniques/T1677
- https://attack.mitre.org/techniques/T1203
- https://attack.mitre.org/techniques/T1127
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 5: Spring Framework Remote Code Execution

- Evidence: lab-host-18:8080/tcp (Spring Framework 5.3.17 detected in host inventory)
- PID: 228610 (host inventory (lab))
- Version source: host inventory (lab)
- CWE: CWE-94
- ATT&CK: T1059: Command and Scripting Interpreter
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent
  - R7 (1.00): IF criticality is high AND epss is high THEN priority is urgent
  - R8 (1.00): IF cvss is critical AND exposure is internet THEN priority is urgent

Remediation: Upgrade Spring Framework to versions 5.3.18+ or 5.2.20+ (or apply Spring Boot patches 2.6.6+ / 2.5.11+). Refactor applications to avoid unsafe data binding patterns and run processes with restricted privileges. Source: MITRE CWE-94

References:
- MITRE CWE-94
- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 6: Apache Tomcat 8.5.19 CVE-2020-1938 Ghostcat

- Evidence: Apache Tomcat 8.5.19 exposed on port 8080.
- PID: 183583 (host inventory (lab))
- Version source: network scan
- CWE: n/a
- ATT&CK: T1190 (Exploit Public-Facing Application)
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent
  - R7 (0.50): IF criticality is high AND epss is high THEN priority is urgent

Remediation: Upgrade Apache Tomcat to version 8.5.51 or later, or disable/secure the AJP connector by setting a strong requiredSecret. Sources: MITRE CWE (CWE-20 Improper Input Validation).

References:
- MITRE CWE (CWE-20 Improper Input Validation)
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 7: CVE-2021-44790 (Apache HTTP Server mod_lua Buffer Overflow)

- Evidence: lab-host-10:80/tcp running Apache httpd 2.4.25. A carefully crafted request body can trigger a buffer overflow in the mod_lua multipart parser (r:parsebody()).
- PID: 184359 (host inventory (lab))
- Version source: network scan
- CWE: CWE-787
- ATT&CK: T1203 (Exploitation for Client Execution)
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent

Remediation: Upgrade Apache HTTP Server to version 2.4.52 or later, or disable mod_lua if not required. Ensure proper bounds checking and validation on buffer sizes and length arguments. Sources: MITRE CWE (CWE-787 Out-of-bounds Write, https://cwe.mitre.org/data/definitions/787.html).

References:
- CWE-787: https://cwe.mitre.org/data/definitions/787.html

## Finding 8: Apache HTTP Server mod_lua Buffer Overflow

- Evidence: lab-host-14:80/tcp running Apache httpd 2.4.25. Vulnerability in mod_lua multipart parser (r:parsebody()).
- PID: 184000 (host inventory (lab))
- Version source: network scan
- CWE: CWE-787
- ATT&CK: T1203 (Exploitation for Client Execution)
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent

Remediation: Upgrade Apache HTTP Server to version 2.4.52 or later to patch the mod_lua multipart parser buffer overflow. Source: MITRE CWE (CWE-787 Out-of-bounds Write) ,  Ensure bounds checking and proper buffer size calculations when handling parsed input parameters.

References:
- CWE-787: https://cwe.mitre.org/data/definitions/787.html
- https://attack.mitre.org/techniques/T1203
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 9: Apache Solr CVE-2024-45216

- Evidence: lab-host-19:8983/tcp Apache Solr (Version 8.11.0 inventory)
- PID: 228777 (host inventory (lab))
- Version source: host inventory (lab)
- CWE: CWE-287, CWE-863
- ATT&CK: T1078 (Valid Accounts), T1550 (Use Alternate Authentication Material)
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent

Remediation: Upgrade Apache Solr to the patched version addressing CVE-2024-45216. Review and harden authentication configurations, ensuring that robust authentication frameworks and mechanisms are properly enforced across all Solr nodes. Cite MITRE CWE-287: Improper Authentication.

References:
- https://attack.mitre.org/techniques/T1078
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
- CWE-863: https://cwe.mitre.org/data/definitions/863.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 10: CVE-2023-25690 (Apache HTTP Server mod_proxy Request Smuggling)

- Evidence: lab-host-10:80/tcp running Apache httpd 2.4.25. Certain mod_proxy configurations allow HTTP Request Smuggling due to discrepancies in parsing Content-Length and Transfer-Encoding headers.
- PID: 184359 (host inventory (lab))
- Version source: network scan
- CWE: CWE-444
- ATT&CK: T1027 (Obfuscated Files or Information / HTTP/Request Smuggling context)
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent

Remediation: Upgrade Apache HTTP Server to version 2.4.56 or later. Carefully review and restrict mod_proxy configurations to prevent inconsistent interpretation of malformed HTTP requests between intermediaries and backends. Sources: MITRE CWE (CWE-444 Inconsistent Interpretation of HTTP Requests, https://cwe.mitre.org/data/definitions/444.html).

References:
- CWE-444: https://cwe.mitre.org/data/definitions/444.html

## Finding 11: Apache HTTP Server HTTP Request Smuggling

- Evidence: lab-host-14:80/tcp running Apache httpd 2.4.25 with vulnerable mod_proxy configurations.
- PID: 184000 (host inventory (lab))
- Version source: network scan
- CWE: CWE-444
- ATT&CK: n/a
- Fuzzy rules fired:
  - R1 (1.00): IF cvss is critical AND epss is high THEN priority is urgent

Remediation: Upgrade Apache HTTP Server to version 2.4.56 or later, and review/harden mod_proxy configurations to prevent request desynchronization and header discrepancies. Source: OWASP Web Security Testing Guide (WSTG-INJT-15 HTTP Request Smuggling) ,  Enforce strict RFC-compliant parsing, normalize request handling across all proxies/intermediaries, and terminate or revalidate backend connections upon parsing errors.

References:
- https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/15-HTTP_Request_Smuggling
- CWE-444: https://cwe.mitre.org/data/definitions/444.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 12: Jenkins CVE-2019-10405: Cookie Header Disclosure

- Evidence: Jenkins 2.196 and earlier / LTS 2.176.3 and earlier printed the value of the "Cookie" HTTP request header.
- PID: 200426 (host inventory (lab))
- Version source: network scan
- CWE: CWE-79
- ATT&CK: T1189
- Fuzzy rules fired:
  - R7 (0.84): IF criticality is high AND epss is high THEN priority is urgent
  - R14 (0.80): IF cvss is medium AND epss is high THEN priority is high
  - R21 (0.80): IF exposure is internal AND cvss is medium THEN priority is low

Remediation: Upgrade Jenkins to a fixed version beyond 2.196 / LTS 2.176.3. Source: MITRE CWE, CWE-79 Improper Neutralization of Input During Web Page Generation (https://cwe.mitre.org/data/definitions/79.html).

References:
- https://attack.mitre.org/techniques/T1189
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 13: Werkzeug Debugger / Cross-Site Request Forgery (CVE-2024-34069)

- Evidence: lab-host-20:5000/tcp running Werkzeug httpd version=2.2.2 (Flask/Python Public API)
- PID: 231471 (host inventory (lab))
- Version source: network scan
- CWE: CWE-352
- ATT&CK: T1185
- Fuzzy rules fired:
  - R2 (0.75): IF exposure is internet AND cvss is high THEN priority is high
  - R13 (0.75): IF cvss is high AND epss is low THEN priority is medium
  - R20 (0.50): IF criticality is high AND cvss is high THEN priority is high

Remediation: Upgrade Werkzeug to the patched version (>= 3.0.3 or latest secure release), disable debug mode in production (debug=False), and implement robust anti-CSRF tokens as outlined in OWASP WSTG-SESS-05 and MITRE CWE-352.

References:
- https://owasp.org/www-project-web-security-testing-guide/latest/10-Session_Management/05-Cross_Site_Request_Forgery
- CWE-352: https://cwe.mitre.org/data/definitions/352.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 14: Apache Tomcat Improper Input Validation

- Evidence: lab-host-18:8080/tcp (Apache Tomcat / web application service)
- PID: 228610 (host inventory (lab))
- Version source: host inventory (lab)
- CWE: CWE-20
- ATT&CK: T1190: Exploit Public-Facing Application
- Fuzzy rules fired:
  - R3 (0.85): IF criticality is high AND cvss is medium AND exposure is internet THEN priority is high
  - R16 (0.85): IF cvss is medium AND epss is low THEN priority is low

Remediation: Review input handling and validate that all incoming data falls within expected allowable ranges and formats. Ensure inputs are decoded and canonicalized correctly prior to validation. Source: MITRE CWE-20

References:
- MITRE CWE-20
- CWE-20: https://cwe.mitre.org/data/definitions/20.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 15: Apache Tomcat CVE-2023-45648

- Evidence: HTTP service running on port 8080.
- PID: 183583 (host inventory (lab))
- Version source: network scan
- CWE: CWE-20
- ATT&CK: T1190 (Exploit Public-Facing Application), T1674 (Input Injection)
- Fuzzy rules fired:
  - R16 (0.85): IF cvss is medium AND epss is low THEN priority is low

Remediation: Upgrade Tomcat to a patched release where HTTP request parsing has been corrected. Sources: MITRE CWE (CWE-20 Improper Input Validation).

References:
- MITRE CWE (CWE-20 Improper Input Validation)
- CWE-20: https://cwe.mitre.org/data/definitions/20.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization

## Finding 16: Jenkins CVE-2020-2103: Session Identifier Exposure

- Evidence: Jenkins 2.218 and earlier / LTS 2.204.1 and earlier exposed session identifiers on a user's detail object.
- PID: 200426 (host inventory (lab))
- Version source: network scan
- CWE: CWE-200
- ATT&CK: T1005
- Fuzzy rules fired:
  - R5 (0.86): IF epss is low AND exposure is internal THEN priority is low
  - R16 (0.80): IF cvss is medium AND epss is low THEN priority is low
  - R21 (0.80): IF exposure is internal AND cvss is medium THEN priority is low

Remediation: Upgrade Jenkins to a version later than 2.218 or LTS 2.204.1 to prevent session identifier exposure. Source: MITRE CWE, CWE-200 / CWE-1230 Exposure of Sensitive Information Through Metadata (https://cwe.mitre.org/data/definitions/200.html).

References:
- https://attack.mitre.org/techniques/T1005
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- https://cwe.mitre.org/data/definitions/1230.html
- OWASP WSTG WSTG-INJT-22 Insecure Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/11-Injection/22-Insecure_Deserialization
