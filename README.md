# Gofing

macOS-native local network discovery and device diagnostics — a Fing-like tool that runs as a single Go binary with an embedded web UI.

**Platform:** macOS only.

## Quick start

```bash
make build    # CGO_ENABLED=1 go build -o gofing .
make run              # ./gofing -port 8080  (opens go-webui desktop window)
make run PORT=8081    # if 8080 is already in use
make app              # build Gofing.app for Dock / Finder
make test     # go test -v ./...
```

### Desktop app (Dock)

```bash
make app
open Gofing.app
# optional install:
cp -R Gofing.app /Applications/
```

Then right-click the Dock icon → **Options → Keep in Dock**.

Optional icon: drop `build/Gofing.icns` in the repo before `make app` (same pattern as PrayerList). No AppleScript required — the `.app` bundle wraps the Go binary.

Or directly:

```bash
go test ./...
CGO_ENABLED=1 go build -o gofing .
./gofing -port 8080
./gofing -port 8080 -open=false   # headless (API only)
./gofing -port 8080 -browser=brave
```

Flags:

| Flag | Default | Description |
|---|---|---|
| `-port` | `8080` | Web UI / API port |
| `-interval` | `30s` | Background subnet rescan interval |
| `-open` | `true` | Open a [go-webui](https://github.com/webui-dev/go-webui) desktop window (Brave/Chrome app profile); use `-open=false` for headless |
| `-browser` | `auto` | Preferred GUI browser: `brave`, `chrome`, `webview`, or empty for auto |
| `-data-dir` | Application Support | Directory for `gofing.db` / caches |
| `-dhcp-file` | `<data-dir>/dhcp-clients.txt` | Poll this DHCP client-list export (created if you save one there) |
| `-dhcp-url` | empty | HTTP GET of JSON or client-list text to poll |
| `-dhcp-interval` | `60s` | How often to re-read DHCP leases |

## Data directory

Persistent data lives under:

```text
~/Library/Application Support/Gofing/
```

| File | Purpose |
|---|---|
| `gofing.db` | BoltDB device inventory, events, settings (`pkg/store`) |
| `oui_cache.json` | OUI vendor lookup cache (`pkg/oui`) |
| `dhcp-clients.txt` | Optional DHCP client-list export, polled automatically |

## Roadmap

Implementation work is tracked in [ROADMAP.md](ROADMAP.md). Agents and contributors should implement one roadmap task at a time and keep `go test ./...` + `go build` green.
