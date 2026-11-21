# Ethical and legal scope

VulnTriage-AI is an academic project. It analyzes, prioritizes and recommends;
it never attacks.

## What is scanned
- Only intentionally vulnerable containers started by the team on its own
  machine: DVWA, OWASP Juice Shop, Vulhub images (Apache httpd 2.4.49,
  Tomcat 8.5.19, Drupal 8.5.0, Samba 4.6.3, Jenkins 2.46.1, Elasticsearch 1.4.2,
  Spring WebMVC 5.3.17 and Apache Solr 8.11.0 as Java services) and a minimal
  Flask app pinned to Werkzeug 2.2.2 and Jinja2 3.1.2 as a Python service.
- They run on a Docker bridge network declared `internal: true`
  (172.30.0.0/24): the containers have no route to the internet and no port is
  published on the host interfaces.
- `scripts/scan_lab.sh` reads its targets from the running lab containers and
  refuses any address outside 172.30.0.0/24. There is no option to pass an
  arbitrary target.

## What is never done
- No external, public or third-party host is scanned.
- No exploit is executed. Nuclei runs its CVE templates with a rate limit, only
  against the lab, with every template that confirms a vulnerability by
  exploiting it excluded (tags `rce`, `lfi`, `traversal`, `sqli`, `xss`, `ssrf`,
  `xxe`, `deserialization`, `injection`, `file-upload`, `oast`, plus `dos`,
  `intrusive`, `fuzz`), and with `-omit-raw` so no request or response body is
  stored. During development one unfiltered run showed that a CVE template
  (CVE-2015-1427) executes a command to confirm the bug; that is why the
  exclusion list exists. Those raw outputs were discarded.
- No autonomous active action: the n8n workflow and the LangChain agent only
  read scan reports and public threat intelligence (NVD, FIRST EPSS, CISA KEV,
  MITRE ATT&CK). Any active test is a human decision outside the system.
- The agent prompt forbids generating exploit code.

## Host inventory (lab)
A network scan cannot see which process owns a port. Alerts and reports include
the PID of the vulnerable service, taken from a host-side inventory step
(`vulntriage/inventory.py`) that runs on the machine hosting the lab: it maps
each lab IP and port to its container with the Docker API and reads the owning
process (`docker inspect`, `docker top`, the container's `/proc` socket table).
Every PID is labeled "host inventory (lab)". It works here only because the
team owns the Docker host. In a real engagement the same data requires host
access granted by the client, through an authenticated (credentialed) scan or
an endpoint agent; it is never obtained from the network side.

## Data handling
- Lab IP addresses are replaced by placeholders (`lab-host-N`) before scan
  reports are saved in `data/lab_scans/`. The private lab addresses
  (172.30.0.0/24) do appear in the host inventory, alerts and reports: they
  identify containers on an internal network and are not sensitive.
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
