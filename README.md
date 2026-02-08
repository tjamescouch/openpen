# openpen

Open source CLI for API fuzzing and penetration testing.

## Features

- **API fuzzing** — Automated endpoint discovery and input mutation
- **Authentication testing** — Token handling, session management, auth bypass checks
- **Rate limit detection** — Identifies rate limiting behavior and thresholds
- **WebSocket testing** — Protocol-level security checks for WS endpoints
- **YAML configs** — Define scan targets and test suites declaratively
- **OWASP coverage** — Tests aligned with OWASP API Security Top 10

## Quick Start

```bash
npm install
npm run build

# Run a scan
openpen scan target.yaml
```

## Responsible Use

This software is intended for authorized security testing, research, and development only. Do not use it against systems you do not own or have explicit written permission to test. Users are solely responsible for ensuring their use complies with all applicable laws and regulations. Unauthorized access to computer systems is illegal.

## License

MIT
