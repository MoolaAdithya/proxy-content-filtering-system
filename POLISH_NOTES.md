# Project 28 polish notes

## Changes in this update

- Hardened HTTP request framing in `proxy.py`.
- Added support for reading `Transfer-Encoding: chunked` request bodies and decoding them before policy evaluation.
- Chunked bodies are forwarded to the backend using a normalized `Content-Length` header.
- Rejects conflicting/duplicate framing headers, duplicate Host headers, malformed header lines, unsupported transfer encodings, oversized headers, and request bodies larger than 2 MiB.
- Returns explicit HTTP error responses for malformed and oversized requests instead of silently dropping them.
- Added `test_proxy_http.py` with focused request-framing tests.
- Updated README with the new test command and the proxy's supported scope/limitations.

## Validation performed in this package build

- Python syntax compilation: all project Python files passed.
- `python3 test_rules.py`: 36/36 passed.
- `python3 test_proxy_http.py`: 7/7 passed.

## Still required on the Ubuntu Mininet lab PC

- Run `sudo python3 run_tests.py` with the OS-Ken controller running.
- Run `sudo python3 run_experiments.py` (or `--quick`) and retain the generated results.
- Verify switch block/unblock, per-source port filtering, and flow counters in the live Mininet/OVS environment.

## Scope note

This remains the original Project 28 proxy/content-filtering system. It is not a rewrite into a distributed worker system. The proxy still processes one HTTP request per client connection and does not implement HTTPS CONNECT/TLS interception.
