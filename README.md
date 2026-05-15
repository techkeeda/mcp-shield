# MCP Shield — AI-Powered MCP Security Gateway

An intelligent security layer that sits between AI agents and MCP tool servers, protecting against tool poisoning, prompt injection via tools, unauthorized data exfiltration, supply chain attacks, and dangerous tool invocations.

## The Problem

MCP (Model Context Protocol) connects AI agents to external tools — but with 17,000+ servers and 150M+ package downloads, the attack surface is massive:

- **Tool Poisoning** — Malicious tool descriptions that inject hidden instructions into the AI
- **Data Exfiltration** — Tools that silently leak sensitive data (emails, credentials, files)
- **Supply Chain Attacks** — Trusted MCP servers get compromised via updates (e.g., the Postmark BCC incident)
- **Unauthorized Actions** — Tools that execute shell commands, modify system files, or escalate privileges
- **Shadow Tools** — Hidden tool capabilities not visible in the declared schema

## How MCP Shield Works

```
┌──────────┐     ┌─────────────┐     ┌────────────┐
│ AI Agent │────▶│  MCP Shield │────▶│ MCP Server │
└──────────┘     └─────────────┘     └────────────┘
                       │
                 ┌─────┴──────┐
                 │  Policies  │
                 │  AI Model  │
                 │  Threat DB │
                 └────────────┘
```

**Three enforcement points:**

1. **Discovery Gate** — Inspects tool listings before the agent sees them. Detects poisoned descriptions, hidden instructions, and suspicious schemas.
2. **Invocation Gate** — Validates every tool call against policy before execution. Blocks dangerous arguments, rate-limits sensitive operations.
3. **Response Gate** — Scans tool responses for data leakage, injected prompts, and unexpected payloads.

## Features

- 🛡️ **Policy Engine** — Declarative YAML rules for allow/deny/ask per tool
- 🧠 **AI Analyzer** — Detects prompt injection and social engineering in tool descriptions
- 🔒 **Argument Sanitizer** — Blocks shell injection, path traversal, credential exposure
- 📊 **Behavioral Baseline** — Learns normal tool usage patterns, flags anomalies
- 🔄 **Mothership Updates** — Auto-pulls latest threat signatures for known-bad MCP servers
- 🪝 **Supply Chain Monitor** — Detects when a previously-safe server changes behavior
- 📋 **Audit Log** — Full trace of every tool discovery, call, and response

## Quick Start

```bash
pip install -e .
mcp-shield --config config.yaml
```

## Integration

MCP Shield acts as a proxy — point your AI agent's MCP client at Shield, and Shield connects to the real servers:

```yaml
# Before (direct, unsafe)
mcpServers:
  filesystem:
    command: npx
    args: ["@modelcontextprotocol/server-filesystem", "/home"]

# After (through Shield)
mcpServers:
  mcp-shield:
    command: mcp-shield
    args: ["--config", "config.yaml"]
```

## Architecture

```
mcp_shield/
├── proxy.py           # MCP proxy — intercepts all traffic
├── gates/
│   ├── discovery.py   # Inspects tool listings for poisoning
│   ├── invocation.py  # Validates tool calls against policy
│   └── response.py    # Scans responses for leaks/injection
├── analyzer.py        # AI-powered threat analysis
├── policy.py          # Policy engine (YAML rules)
├── baseline.py        # Behavioral anomaly detection
├── threat_db.py       # Known-bad servers, hashes, patterns
├── updater.py         # Mothership auto-update
└── main.py            # Entry point
```
