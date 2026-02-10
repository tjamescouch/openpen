# openpen

openpen is an open-source CLI tool that performs automated API security scanning, fuzzing, and penetration testing against HTTP and WebSocket endpoints.

## components

- [cli](#cli)
- [spec-parser](#spec-parser)
- [check-engine](#check-engine)
- [fuzzer](#fuzzer)
- [ws-tester](#ws-tester)
- [reporter](#reporter)
- [http-client](#http-client)

## behaviors

- the cli accepts a target url and runs security checks against it, producing a findings report.
- the spec parser loads endpoint definitions from openapi 3.x or swagger 2.x specs, or from manually specified paths.
- each check module sends crafted requests to target endpoints and analyzes responses for vulnerability indicators.
- the fuzzer replaces placeholder tokens in urls and bodies with attack payloads, detects anomalies by comparing responses to a baseline.
- the websocket tester opens connections and probes for authentication gaps, message handling flaws, rate limiting, and size limits.
- the reporter formats findings as color-coded terminal output or structured json.
- scan depth (shallow, normal, deep) controls how many payloads each check sends.

## constraints

- [constraints](constraints.md)
