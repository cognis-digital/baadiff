# Ports of baadiff

The same HIPAA Security Rule scan logic, ported across languages so you can drop
`baadiff` into any stack — a Node service, a Go/Rust static binary, or a tiny
shell-only / air-gapped image with no language runtime at all.

Every port is **passive and offline**: it only reads local files and never
touches the network. Each one mirrors the Python reference's core check IDs and
the same scoring rules (severity-weighted deductions, a per-check cap of 30, and
a hard rule that any open **critical** finding blocks `shippable`; threshold 80).

## Checks shared by all ports

| ID | Safeguard | What it flags |
|---|---|---|
| BD001 | 164.312(a)(2)(i) | Hardcoded secret / credential (ignores env refs + placeholders) |
| BD002 | 164.312(e)(1) | Plaintext `http://` (not localhost) or disabled TLS verification |
| BD003 | 164.312(c)(1) | Weak hash (MD5/SHA1) used for ePHI integrity |
| BD004 | 164.312(a)(1) | Wildcard IAM `*` or `0.0.0.0/0` ingress (config files only) |
| BD005 | 164.312(a)(2)(iv) | *presence* — encryption at rest configured |
| BD006 | 164.312(b) | *presence* — audit controls / logging |
| BD007 | 164.312(d) | *presence* — authentication / access control |
| BD008 | 164.308(a)(7) | *presence* — backup / contingency |
| BD009 | 164.312(c)(2) | *presence* — integrity verification (SHA-256/HMAC) |

> The Python reference adds further checks (BD010–BD015: debug mode, encryption
> explicitly disabled, public buckets, PHI-in-logs, auto-logoff, retention) and
> SARIF output. The ports cover the BD001–BD009 core so their JSON stays
> comparable across languages.

## Run each port

| Language | Path | Run | Smoke test |
|---|---|---|---|
| Python (reference) | `../baadiff/` | `baadiff scan .` | `pytest` (repo root) |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js . --json` | `node ports/javascript/test.js` |
| Go | `go/` | `cd ports/go && go run . .. --json` | `cd ports/go && go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- .. --json` | `cd ports/rust && cargo test` |
| POSIX shell | `shell/` | `sh ports/shell/baadiff.sh . --json` | `sh ports/shell/test.sh` |

All ports accept a path argument and a `--json` flag, print a human table by
default, and exit non-zero when the target is **not shippable** (so they gate CI
the same way the Python CLI does).

Every port is built and tested on each push by
[`.github/workflows/ports.yml`](../.github/workflows/ports.yml) — JS + shell run
on Node/`sh`, Go via `go test`, Rust via `cargo test` (std-only, no external
crates, so it builds offline).

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
../CONTRIBUTING.md.
