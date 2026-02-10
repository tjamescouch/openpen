# constraints

## technology

- use typescript with strict mode, targeting es2022.
- use esm modules (type: module, nodenext resolution).
- use native fetch (no axios or node-fetch).
- use commander for cli argument parsing.
- use the yaml package for yaml spec parsing.
- use chalk for terminal colors (currently using raw ansi codes).
- use the ws package for websocket connections.
- require node >= 18.

## security

- never store or cache credentials from target apis.
- never exfiltrate data from scanned targets beyond what is needed for findings.
- truncate response bodies to 500 characters in stored results.
- set a clearly identifiable user-agent header on all requests.

## performance

- enforce per-scan concurrency limits via semaphore.
- enforce per-scan rate limits via token-bucket rate limiter.
- support configurable per-request timeouts.
- default concurrency to 10, rate limit to 50 rps, timeout to 10 seconds.

## output

- support terminal and json output formats.
- terminal output groups findings by severity, critical first.
- json output is valid json with 2-space indentation.
- support writing reports to files via --output flag.
- support disabling color via --no-color flag.

## checks

- each check module extends BaseCheck and implements the run method.
- each check returns a CheckResult with a findings array and request count.
- each finding includes severity, endpoint, method, evidence, description, remediation, and owasp category.
- severity levels are critical, high, medium, low, info.
- payload volume scales with depth setting: shallow sends fewer payloads, deep sends all.
- unknown check ids produce an error, never silently skip.

## spec parsing

- support openapi 3.x and swagger 2.x formats.
- support json and yaml spec files.
- support loading specs from local files or http urls.
- support manual endpoint specification via --paths flag.
- strip trailing slashes from base urls.

## websocket testing

- auto-upgrade http/https urls to ws/wss.
- each websocket check manages its own connections.
- distinguish rate-limit disconnections from test failures.
- clean up all connections after each check completes.
