# NOX Subprocess Plugin Contract

NOX plugins are executables that read one JSON request from stdin and write one JSON response to stdout.

## Request

```json
{
  "version": "1",
  "session_id": "uuid",
  "target": {
    "id": "uuid",
    "host": "example.com",
    "ip": "93.184.216.34",
    "port": 443,
    "protocol": "https"
  },
  "prior_findings": [],
  "prior_technologies": [],
  "config": {}
}
```

## Response

```json
{
  "version": "1",
  "findings": [],
  "new_targets": [],
  "technologies": [],
  "error": null
}
```

Plugins must not scan outside the target or scope context passed by NOX. Findings should include enough evidence to reproduce and validate the issue.

