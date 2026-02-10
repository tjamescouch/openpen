# components

## cli

the cli is the entry point. it parses command-line arguments, orchestrates scans, and coordinates output.

### state

- parsed command and options (target url, spec path, auth config, depth, concurrency, rate limit, timeout, output format).
- selected check modules for the current run.

### capabilities

- accepts `scan`, `fuzz`, `info`, `ws-test`, and `list-checks` commands.
- parses auth headers and bearer tokens into a unified auth config.
- loads a scan target from spec or manual paths, then runs selected checks sequentially.
- assembles a scan report from all check results and delegates to the reporter.
- the `fuzz` command drives the fuzzer against a single url with a chosen wordlist.
- the `info` command performs reconnaissance by listing endpoints and fingerprinting server headers.
- the `ws-test` command runs websocket security checks against a ws/wss url.

### interfaces

- input: command-line arguments via commander.
- output: terminal stdout, json file, or json stdout.

### invariants

- the cli exits with code 1 if no endpoints are found and no manual paths are provided.
- auth config is optional; checks adapt when auth is absent.

---

## spec-parser

the spec parser loads api endpoint definitions from openapi specs, urls, or manually provided paths.

### state

- the loaded scan target: base url, endpoint list, auth config, global headers.

### capabilities

- fetches specs from http urls or reads from local files.
- parses openapi 3.x and swagger 2.x documents (json or yaml).
- extracts endpoints with their http methods, path/query/header/cookie parameters, and request body schemas.
- merges manually specified paths with spec-defined endpoints without duplication.
- filters endpoints by http method when requested.

### interfaces

- input: `loadTarget(baseUrl, options)` where options include spec path, methods filter, manual paths, auth.
- output: a `ScanTarget` containing base url, endpoints, auth, and global headers.

### invariants

- the base url has trailing slashes stripped.
- unrecognized spec formats produce an error.
- manual paths are only added if not already present in the spec.

---

## check-engine

the check engine is a registry of security check modules. each check module extends a base class and targets a specific vulnerability category.

### state

- a fixed registry of all available check modules.
- each check holds its id, name, description, and owasp category.

### capabilities

- returns all checks, checks by id list, or check metadata for listing.
- each check receives a scan target and config, sends requests, analyzes responses, and returns findings with request counts.
- available http checks:
  - **security-headers**: detects missing security headers (hsts, csp, x-frame-options, x-content-type-options, referrer-policy) and information leakage headers (server, x-powered-by).
  - **sqli**: sends sql injection payloads to query parameters and body fields, detects sql error patterns and time-based blind injection.
  - **xss**: sends xss payloads to query parameters on get endpoints, detects unescaped reflection in responses.
  - **auth-bypass**: compares responses with valid auth, no auth, and invalid tokens to detect missing authentication enforcement.
  - **bac**: tests for idor by sending multiple id values to path parameters, and tests for http method override acceptance.
  - **ssrf**: sends internal/metadata urls to url-like parameters, detects ssrf indicators in responses and differential behavior.
  - **sensitive-data**: scans responses for leaked secrets (jwts, api keys, aws keys, private keys, passwords, ssns, credit cards), internal ips, stack traces, and probes common leak paths (.env, .git/config, debug endpoints).
  - **mass-assignment**: injects undocumented privilege fields into request bodies on write endpoints, detects acceptance and reflection, tests for prototype pollution.
  - **prompt-injection**: sends prompt injection payloads to llm-facing input fields, uses canary strings and compliance detection to identify when injected instructions override system prompts.
  - **llm-leak**: probes for system prompt extraction, tool/function schema leakage, and internal configuration disclosure using extraction payloads with multi-indicator detection.

### interfaces

- input: `check.run(target, config)` returns `CheckResult` with findings array and request count.
- output: findings typed as `Finding` with severity, endpoint, method, parameter, payload, evidence, description, remediation, and owasp category.

### invariants

- requesting an unknown check id produces an error.
- each finding has a unique id within its check run.
- payload volume scales with depth setting (shallow, normal, deep).

---

## fuzzer

the fuzzer sends mutated attack payloads to a target url and detects response anomalies.

### state

- concurrency semaphore and rate limiter.
- optional baseline response for comparison.
- built-in payload dictionaries: sqli, xss, path-traversal, ssrf, nosql, command-injection, prompt-injection, llm-leak.

### capabilities

- replaces `FUZZ` placeholders in urls and request bodies with each payload from the selected wordlist.
- sends a clean baseline request when requested, then compares subsequent responses.
- detects four anomaly types: status code changes (especially 5xx), response length deviation (>50%), timing anomalies (>3x baseline and >3s), and error string patterns (sql errors, stack traces, system paths).
- detects payload reflection in response bodies.
- mutates payloads using url-encoding, double-encoding, unicode escapes, case-swapping, null-byte appending, and string concatenation splitting.

### interfaces

- input: `FuzzEngine.fuzz(request)` with url, method, body, headers, wordlist selection, detection methods, and baseline flag.
- output: array of `FuzzResult` with payload, request/response summaries, anomaly list, and optional baseline.

### invariants

- the original unmodified payload is always included alongside mutations.
- payloads in urls are uri-encoded; payloads in bodies are injected raw.
- concurrency and rate limits are enforced across all fuzz requests.

---

## ws-tester

the websocket tester runs security checks against websocket endpoints.

### state

- a registry of websocket check modules.
- each check holds connection state and collected messages.

### capabilities

- available websocket checks:
  - **ws-unauth**: probes for unauthenticated command acceptance by sending common protocol messages without credentials.
  - **ws-enum**: enumerates valid message types by probing a dictionary of common protocol commands.
  - **ws-size**: tests message size limits by sending progressively larger payloads (1kb to 5mb).
  - **ws-rate**: tests rate limiting by sending a burst of 20 rapid messages.
  - **ws-flood**: tests connection limits by opening up to 15 concurrent connections.
  - **ws-invalid**: tests handling of malformed json, injection payloads, type confusion, and prototype pollution attempts.

### interfaces

- input: `check.run(url, timeout)` for each websocket check.
- output: `WsTestResult` with check id, status (pass/fail/warn/error), severity, description, evidence, and remediation.
- the ws engine provides `connect`, `sendAndWait`, `sendRaw`, `close`, `waitForMessages`, and `parseJson` primitives.

### invariants

- auto-upgrades http/https urls to ws/wss scheme.
- each check opens its own connections and cleans up on completion.
- rate-limited disconnections are distinguished from actual failures.

---

## reporter

the reporter formats scan results for consumption.

### state

- none (stateless formatters).

### capabilities

- terminal reporter prints color-coded output with severity grouping, finding details, payloads, evidence, and remediation advice.
- json reporter outputs structured json to stdout or to a file.
- color can be disabled via flag.

### interfaces

- input: `ScanReport` or `WsTestReport`.
- output: terminal stdout or json file.

### invariants

- findings are grouped by severity in terminal output (critical first).
- json output is pretty-printed with 2-space indentation.

---

## http-client

the http client provides low-level request execution with concurrency and rate control.

### state

- semaphore tracks active concurrent requests.
- rate limiter tracks minimum interval between requests.

### capabilities

- sends http requests using native fetch with configurable method, headers, body, and timeout.
- sets a default user-agent header (`openpen/0.1.0`).
- defaults content-type to `application/json` when a body is present.
- captures request summary (url, method, headers, body) and response summary (status, headers, body snippet, response time).
- body snippets are truncated to 500 characters.
- follows redirects.

### interfaces

- input: `sendRequest(options)` with url, method, headers, body, timeout.
- output: `HttpResponse` with request summary, response summary, and raw headers.
- `Semaphore` class for concurrency limiting (acquire/release).
- `RateLimiter` class for token-bucket rate limiting (wait).

### invariants

- requests abort after the configured timeout via `AbortSignal.timeout`.
- the semaphore queues requests when the concurrency limit is reached.
- the rate limiter enforces a minimum interval derived from max-requests-per-second.
