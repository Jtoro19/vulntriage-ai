# Ethical and legal scope

VulnTriage-AI is an academic project. It analyzes, prioritizes and recommends;
it never attacks.

## What is scanned
- Only intentionally vulnerable containers started by the team on its own
  machine: DVWA, OWASP Juice Shop and Vulhub images (Apache httpd 2.4.49,
  Tomcat 8.5.19, Drupal 8.5.0, Samba 4.6.3, Jenkins 2.46.1, Elasticsearch 1.4.2).
- They run on a Docker bridge network declared `internal: true`
  (172.30.0.0/24): the containers have no route to the internet and no port is
  published on the host interfaces.
- `scripts/scan_lab.sh` reads its targets from the running lab containers and
  refuses any address outside 172.30.0.0/24. There is no option to pass an
  arbitrary target.

## What is never done
- No external, public or third-party host is scanned.
- No exploit is executed by the system. Nuclei runs its CVE detection
  templates with a rate limit, only against the lab, and with the `dos`,
  `intrusive` and `fuzz` tags excluded. Some detection templates confirm a
  vulnerability with a harmless proof request (for example reading a known
  file); that happens only inside the isolated lab.
- No autonomous active action: the n8n workflow and the LangChain agent only
  read scan reports and public threat intelligence (NVD, FIRST EPSS, CISA KEV,
  MITRE ATT&CK). Any active test is a human decision outside the system.
- The agent prompt forbids generating exploit code.

## Data handling
- Lab IP addresses are replaced by placeholders (`lab-host-N`) before scan
  reports are saved in `data/lab_scans/`.
- API keys live only in `.env` (git-ignored). Workflow nodes read them at
  runtime with `$env`, so the exported workflow JSON contains no secrets.
  `scripts/check_secrets.sh` runs before every push and blocks it if a key
  pattern or a value from `.env` appears in a tracked file.
- Only finding metadata and short summaries are sent to cloud LLMs. A local
  Ollama model can be selected (`VULNTRIAGE_LLM_PROVIDER=ollama`) so that
  engagement data never leaves the machine.

## Stopping the lab
```bash
docker compose -f lab/docker-compose.lab.yml down
```
