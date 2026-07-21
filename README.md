# Gofing

macOS-native local network discovery and device diagnostics — a Fing-like tool that runs as a single Go binary with an embedded web UI.

**Platform:** macOS only.

## Quick start

```bash
make build    # go build -o gofing .
make run      # ./gofing -port 8080
make test     # go test -v ./...
```

Or directly:

```bash
go test ./...
go build -o gofing .
./gofing -port 8080
```

Flags:

| Flag | Default | Description |
|---|---|---|
| `-port` | `8080` | Web UI / API port |
| `-interval` | `30s` | Background subnet rescan interval |
| `-open` | `true` | Open the browser on startup |
| `-data-dir` | Application Support | Directory for `gofing.db` / caches |

## Data directory

Persistent data lives under:

```text
~/Library/Application Support/Gofing/
```

| File | Purpose |
|---|---|
| `gofing.db` | BoltDB device inventory, events, settings (`pkg/store`) |
| `oui_cache.json` | OUI vendor lookup cache (`pkg/oui`) |

## Roadmap

Implementation work is tracked in [ROADMAP.md](ROADMAP.md). Agents and contributors should implement one roadmap task at a time and keep `go test ./...` + `go build` green.
