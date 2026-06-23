# baadiff — Advanced usage

## CI gate (fail the build on findings)
```yaml
- run: pip install cognis-baadiff
- run: baadiff scan . --sarif baadiff.sarif --threshold 80   # non-zero below 80 or on any critical
- uses: github/codeql-action/upload-sarif@v3
  if: always()                                                # upload even when the gate fails
  with: { sarif_file: baadiff.sarif }
```

## Pipe into a SIEM / webhook
```bash
baadiff scan . --format json | python integrations/webhook.py --url "$COGNIS_WEBHOOK_URL"
```

## Drive it from an AI agent (MCP)
```jsonc
// claude_desktop_config.json
{ "mcpServers": { "baadiff": { "command": "baadiff", "args": ["mcp"] } } }
```

## Run a language port instead of Python
All ports take a path + optional `--json` and exit non-zero when not shippable.
```bash
node ports/javascript/index.js . --json     # Node
( cd ports/go && go run . .. --json )         # Go single binary
( cd ports/rust && cargo run -- .. --json )   # Rust (std-only, builds offline)
sh ports/shell/baadiff.sh . --json            # POSIX shell, no runtime needed
```
See [`ports/README.md`](../ports/README.md) for the shared check IDs and the
`ports.yml` CI that builds/tests every port on push.
