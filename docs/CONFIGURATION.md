# Configuration Guide

MCP Shield is configured via a single YAML file. This document explains every option.

## Minimal Configuration

```yaml
upstream_servers:
  filesystem:
    command: npx
    args: ["@modelcontextprotocol/server-filesystem", "/home/user"]

policies:
  default:
    action: ask
```

## Full Configuration Reference

### `upstream_servers`

Define the MCP servers that Shield proxies to.

```yaml
upstream_servers:
  # Each key is a server name
  filesystem:
    command: npx                                    # Command to start the server
    args: ["@modelcontextprotocol/server-filesystem", "/home/user"]  # Arguments
    env:                                           # Optional environment variables
      SOME_VAR: "value"

  github:
    command: npx
    args: ["@modelcontextprotocol/server-github"]
    env:
      GITHUB_TOKEN_ENV: "GITHUB_TOKEN"             # References env var on host
```

### `mothership`

Threat intelligence auto-update settings.

```yaml
mothership:
  url: "https://shield-mothership.example.com/api/v1"  # Mothership API endpoint
  update_interval_seconds: 3600                         # How often to check (default: 1hr)
  auth_token_env: "SHIELD_MOTHERSHIP_TOKEN"             # Env var holding auth token
```

### `policies`

Declarative rules for tool access control.

```yaml
policies:
  default:
    action: ask       # Default action: allow | deny | ask
    log: true         # Log all actions

  tools:
    read_file:
      action: allow
      constraints:
        blocked_paths:
          - "/etc/shadow"
          - "/etc/passwd"
          - "~/.ssh/*"
          - "~/.aws/*"

    write_file:
      action: ask
      constraints:
        blocked_paths:
          - "/etc/*"
          - "/usr/*"

    execute_command:
      action: deny    # Never allow command execution

    send_email:
      action: ask
      constraints:
        block_bcc: true   # Prevent supply chain BCC attacks
```

**Actions:**
| Action | Behavior |
|--------|----------|
| `allow` | Pass through, subject to constraints |
| `deny` | Always block |
| `ask` | Log and allow (future: interactive approval) |

**Constraints:**
| Constraint | Description |
|-----------|-------------|
| `blocked_paths` | Glob patterns for paths that should never be accessed |
| `block_bcc` | Block BCC field in email tools (supply chain prevention) |

### `discovery`

Controls how tool descriptions are inspected.

```yaml
discovery:
  block_hidden_instructions: true     # Enable injection detection
  max_description_length: 2000        # Flag overly long descriptions
  suspicious_patterns:                 # Additional patterns to flag
    - "ignore previous"
    - "do not tell the user"
    - "secretly"
    - "override"
    - "system prompt"
    - "<IMPORTANT>"
```

### `invocation`

Controls argument validation.

```yaml
invocation:
  block_shell_injection: true          # Detect shell metacharacters
  block_path_traversal: true           # Detect ../ patterns
  block_credential_patterns: true      # Detect API keys, private keys
  rate_limit:
    max_calls_per_minute: 30           # Global rate limit
    max_calls_per_tool_per_minute: 10  # Per-tool rate limit
```

### `response`

Controls response scanning.

```yaml
response:
  scan_for_injection: true             # Detect prompt injection in responses
  scan_for_data_leakage: true          # Detect sensitive data patterns
  sensitive_patterns:                   # Regex patterns for sensitive data
    - "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"  # Emails
    - "\\b\\d{3}-\\d{2}-\\d{4}\\b"                                 # SSN
    - "AKIA[0-9A-Z]{16}"                                           # AWS key
    - "sk-[a-zA-Z0-9]{48}"                                         # OpenAI key
```

### `audit`

Audit logging configuration.

```yaml
audit:
  enabled: true
  file: "/var/log/mcp-shield/audit.jsonl"
  log_arguments: true      # Include tool arguments in logs
  log_responses: true      # Include tool responses in logs
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SHIELD_MOTHERSHIP_TOKEN` | Auth token for mothership API |
| `GITHUB_TOKEN` | (Example) Token for upstream GitHub MCP server |
