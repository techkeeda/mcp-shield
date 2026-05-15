# Tutorial: Getting Started with MCP Shield

This tutorial walks you through installing MCP Shield, configuring it, and protecting your AI agent from malicious MCP tools.

## Prerequisites

- Python 3.11+
- An AI agent that uses MCP (Claude Desktop, Cursor, Windsurf, etc.)
- One or more MCP servers you want to protect

## Step 1: Install

```bash
git clone https://github.com/YOUR_USERNAME/mcp-shield.git
cd mcp-shield
pip install -e .
```

## Step 2: Create a Configuration

Create `config.yaml` in your working directory:

```yaml
upstream_servers:
  filesystem:
    command: npx
    args: ["@modelcontextprotocol/server-filesystem", "/home/user/projects"]

policies:
  default:
    action: ask
  tools:
    read_file:
      action: allow
      constraints:
        blocked_paths: ["~/.ssh/*", "~/.aws/*", "/etc/shadow"]
    write_file:
      action: ask
    execute_command:
      action: deny

discovery:
  block_hidden_instructions: true
  max_description_length: 2000

invocation:
  block_shell_injection: true
  block_path_traversal: true

response:
  scan_for_injection: true
  scan_for_data_leakage: true

audit:
  enabled: true
  file: "./audit.jsonl"
```

## Step 3: Point Your Agent at Shield

Instead of connecting your AI agent directly to MCP servers, point it at MCP Shield:

**Claude Desktop (`claude_desktop_config.json`):**
```json
{
  "mcpServers": {
    "mcp-shield": {
      "command": "mcp-shield",
      "args": ["--config", "/path/to/config.yaml"]
    }
  }
}
```

**Before (unsafe):**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

## Step 4: Verify It's Working

Run Shield manually to see it in action:

```bash
mcp-shield --config config.yaml
```

Check the audit log:
```bash
cat audit.jsonl | python -m json.tool
```

You should see entries like:
```json
{
  "timestamp": 1715750400.0,
  "event": "invocation_check",
  "tool": "read_file",
  "action": "allow",
  "reason": "policy allows"
}
```

## Step 5: Test the Protection

Try these scenarios to verify Shield is blocking threats:

### Test: Path traversal blocked
If the agent tries to read `../../etc/passwd`, Shield blocks it:
```json
{"event": "invocation_check", "tool": "read_file", "action": "deny", "reason": "path traversal detected in arguments"}
```

### Test: Shell injection blocked
If arguments contain `; rm -rf /`, Shield blocks it:
```json
{"event": "invocation_check", "tool": "search", "action": "deny", "reason": "shell injection detected in arguments"}
```

### Test: Poisoned tool description blocked
If a server returns a tool with hidden instructions, Shield removes it from the listing:
```json
{"event": "tool_blocked_discovery", "tool": "evil_tool", "threats": ["injection pattern detected: 'ignore\\s+(all\\s+)?previous'"]}
```

---

## Next Steps

- [Configuration Guide](./CONFIGURATION.md) — Full reference for all options
- [API Reference](./API.md) — Use Shield programmatically
- [Security Spec](./SPEC.md) — Understand the threat model
