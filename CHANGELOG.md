# Changelog

All notable changes to MCP Shield will be documented in this file.

## [0.1.0] - 2026-05-15

### Added
- Initial release
- Three-gate architecture: Discovery, Invocation, Response
- Policy engine with allow/deny/ask actions per tool
- Discovery gate: prompt injection detection, invisible character scanning, description length limits
- Invocation gate: shell injection blocking, path traversal prevention, credential detection, rate limiting
- Response gate: data leakage scanning, prompt injection in responses
- Supply chain monitor: server fingerprinting, change detection
- Behavioral baseline: learns normal usage patterns, flags anomalies
- Mothership auto-updater for threat intelligence
- JSONL audit logging
- YAML-based configuration
