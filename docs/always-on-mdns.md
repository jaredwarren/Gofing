# Always-on mDNS listener

Design for a process-lifetime Bonjour listener so Gofing learns device names when they actually appear on the wire, then **never forgets them**.

DHCP import (router client list → BoltDB) already covers sleeping devices that are not advertising. This doc is the other half: catch names the next time a device (or a sleep proxy) speaks mDNS, and persist them by MAC.

---

## Why the current browse is not enough

macOS `arp -a` returns `?` for almost every host. Gofing therefore depends on mDNS.

Today [`pkg/mdns/browse.go`](../pkg/mdns/browse.go) starts `dns-sd -B <type> local`, kills it after **3–5 seconds**, then does short `dns-sd -L` / `dns-sd -G` lookups. That is a **poll**, not a listener.

Measured on this LAN (Amy’s MacBook, `192.168.0.142` / `8C:85:90:24:10:B7`):

| Probe | Result |
|---|---|
| `arp -a` | MAC present, name `?` |
| `ping Amys-MBP.local` | unknown host |
| reverse PTR (`142.0.168.192.in-addr.arpa`) | No Such Record |
| `dns-sd -B _companion-link._tcp` (seconds) | this Mac + iPads only — not Amy’s MBP |
| ICMP ping of `.142` | replies (device is up) |
| `tcpdump` udp/5353 from that MAC | short **LKDC TXT** burst, then silence; **no hostname** |
| Ping does not provoke a name announcement | |

Fing still shows `Amys-MBP` while the laptop is “asleep” because it **already stored** the DHCP/mDNS name against the MAC. A 3-second browse during a subnet scan cannot recreate that.

A listener that runs for the life of `gofing` will see the occasional burst (LKDC, wake, AirDrop, sleep-proxy answer) and can map it to an IP, then a MAC, then BoltDB.

---

## Goals

1. Join mDNS multicast (`224.0.0.251:5353` / `ff02::fb`) when Gofing starts and **leave the socket open** until shutdown.
2. Parse announcements (PTR, SRV, A/AAAA, TXT). Record `hostname ↔ IPv4`.
3. After each scan (and immediately when a packet maps to a known IP), attach the name to the inventory device via `PreferHostname`.
4. Persist by **MAC** in BoltDB. An empty later scan must not clear a learned name.
5. Emit SSE `device_updated` when a name is newly applied so the UI updates without waiting for `-interval`.
6. Stay macOS-only, no CGO, no extra daemons.

## Non-goals

- Replacing DHCP import. Router leases remain the way to name a device that **never** announces while Gofing is running.
- Reading the TP-Link admin API in this task.
- Using names from LKDC SHA1 hashes (`LKDC:SHA1.…`) as display names — those are not hostnames.
- Windows/Linux portability.
- Promiscuous DHCP sniffing (ports 67/68) in this task.

---

## Name-source ranks (unchanged policy)

From [`pkg/mdns/namesource.go`](../pkg/mdns/namesource.go):

| Source | Rank | Role |
|---|---|---|
| `host` | 90 | This Mac’s ComputerName |
| `dhcp` | 85 | Router DHCP client list (already imported) |
| `arp` / **`mdns`** | 80 | Bonjour hostname from packets or `dns-sd` |
| `dns` | 70 | Reverse unicast DNS |
| `cast` / `http` | 50 / 40 | Weak probes |

Always-on mDNS should use a dedicated `NameSourceMDNS = "mdns"` at **rank 80** (same as ARP). It may fill empty names and replace DNS/HTTP junk. It must **not** overwrite `dhcp` or `host`.

`PreferHostname` already implements stickiness: empty candidate → keep existing.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────┐
│  Gofing process                                         │
│                                                         │
│  UDP 224.0.0.251:5353  ──►  mdns.Listener               │
│  (en0, lifetime)              parse PTR/SRV/A/TXT       │
│                                    │                    │
│                                    ▼                    │
│                             ipNames[ip] = hostname      │
│                             (existing Resolver cache)   │
│                                    │                    │
│                    on packet / end of scan              │
│                                    ▼                    │
│                             engine.applyCachedHostnames │
│                             + apply to MAC via ARP/IP   │
│                                    │                    │
│                                    ▼                    │
│                             BoltDB Device.Hostname      │
│                             SSE device_updated          │
└─────────────────────────────────────────────────────────┘
```

**Scan** still owns presence (online/offline, IP, MAC). **Listener** only owns names and fingerprint hints.

```text
Scan (ARP/ping)      → IP + MAC + online
mDNS listener (24/7) → hostname for an IP
DHCP import          → hostname for a MAC (already done)
                     ↓
BoltDB keyed by MAC: better source wins; missing name never deletes
```

---

## Recommended implementation: in-process multicast (not `dns-sd -B`)

Keep shelling out to `dns-sd` for on-demand “Resolve name”. Do **not** use more short `dns-sd -B` passes as the always-on path.

| Approach | Verdict |
|---|---|
| Periodic `dns-sd -B` (today) | Misses quiet devices; 3s window; many sequential types |
| Long-lived `dns-sd -B` per service type | ~15 subprocesses; still misses A records that are not tied to a browsed type; awkward to parse forever |
| **Listen on 5353 in Go** | One socket; sees A/PTR/SRV including sleep-proxy and late bursts; pure Go; matches “no CGO” |

### Socket

- `net.ListenMulticastUDP("udp4", iface, &net.UDPAddr{IP: 224.0.0.251, Port: 5353})` on the **active** interface (`network.Info.InterfaceName`, usually `en0`).
- Optionally the same for `udp6` / `ff02::fb`.
- `ReadFromUDP` loop in a goroutine started from `mdns.New()` (or `Listener.Start(ctx)` from `main` so shutdown cancels it).
- SO_REUSEPORT/REUSEADDR if needed so `dns-sd` and Gofing can coexist (macOS typically allows multiple mDNS listeners).
- Cap packet size (~9k); ignore truncated garbage.

Rebind when the active interface/SSID changes (`SetActiveNetwork`).

### Parse (RFC 6762 / 1035)

Minimum records to handle:

| Type | Use |
|---|---|
| **A** | `Amys-MBP.local` → `192.168.0.142` (the payoff) |
| **PTR** | instance / service; then we already know to expect an A/SRV in the same packet |
| **SRV** | instance → hostname + port |
| **TXT** | model / fingerprint only (existing `hintsFromTXT`); skip `LKDC:SHA1.*` as a hostname |
| **AAAA** | ignore for inventory (IPv4-only devices today) |

Sanitize with existing `normalizeResolvedName` / `SanitizeHostname`. Reject denylisted tokens (`local`, `ptr`, `workgroup`, …).

Store with `rememberIPName(ip, host, NameSourceMDNS)`.

Additional-section A records in the same packet as a PTR/SRV are how many Apple devices publish `Name.local` without a reverse PTR. The listener must read **answers and additionals**, not questions.

Amy’s Mac’s LKDC packets were **questions** plus a TXT whose owner is a hash, not `Amys-MBP`. Parsing them must not create a device named `6C287FBD…`.

### Map IP → MAC → device

`ipNames` is IP-keyed. Inventory is MAC-keyed.

1. On A-record: `rememberIPName`.
2. Look up devices with that IP (`applyCachedHostnames` already does this).
3. If no device yet, wait until the next scan sees the MAC in ARP; then apply.
4. Persist immediately when applied (do not wait for scan batch) so a crash does not lose a rare announcement.

Optional later: also cache `MAC → hostname` when ARP is already known for that IP, so a DHCP renew that changes IP keeps the name.

### Engine hook

Today `applyCachedHostnames()` runs only at the **end of `PerformScan`**. Add:

- `Resolver` callback or channel `NameLearned{IP, Hostname, Source}`
- Engine applies `PreferHostname`, `persistDevice`, `emitEvent("device_updated")` if the display name changed

Keep end-of-scan apply as a backstop.

### Process lifetime

Start the listener in `mdns.New()` or `main` after `GetActiveNetworkInfo()`. Cancel on SIGINT/SIGTERM with the existing shutdown context. Do not start a second listener.

Replace `backgroundDiscovery()`’s 90s `dns-sd -B` ticker **or** leave it as a low-priority supplement for a release, then delete it once the socket path is proven. Prefer **replace** so we do not spawn `dns-sd` storms.

---

## Sleep, sleep proxy, and DHCP

```text
Device awake + sharing on     → A/PTR on 5353 → listener names it
Device awake, Sharing off     → maybe only LKDC; no hostname (DHCP still wins)
Device asleep, no sleep proxy → no mDNS; DHCP / last persisted name
Device asleep + Apple TV/etc  → sleep proxy may answer Amys-MBP.local
                                 (listener will see it; 3s browse often will not)
```

Gofing should treat “last good name for this MAC” as the display name while the device is offline. That is the Fing sleep-mode behavior. The listener fills the cache; stickiness keeps it.

---

## Files to touch (when implementing)

| File | Change |
|---|---|
| [`pkg/mdns/namesource.go`](../pkg/mdns/namesource.go) | `NameSourceMDNS = "mdns"`, rank 80 |
| [`pkg/mdns/listen.go`](../pkg/mdns/listen.go) (new) | Multicast join, read loop, packet parse |
| [`pkg/mdns/listen_test.go`](../pkg/mdns/listen_test.go) (new) | Golden packets: A, PTR+A additional, LKDC TXT ignored |
| [`pkg/mdns/browse.go`](../pkg/mdns/browse.go) | Stop or shrink `backgroundDiscovery` once listener is on |
| [`pkg/mdns/mdns.go`](../pkg/mdns/mdns.go) | Start/stop listener from `New`; `ResolveDevice` already reads `cachedForIP` |
| [`pkg/engine/engine.go`](../pkg/engine/engine.go) | Subscribe to name events; persist + SSE |
| [`web/static/app.js`](../web/static/app.js) | `formatNameSource('mdns')` → `Bonjour` |
| [`main.go`](../main.go) | Pass cancel ctx / iface into resolver if not already |

No new HTTP endpoints required. Names show up on existing `/api/devices` and SSE.

---

## Implementation order

1. **Parser + tests** — fixture UDP payloads (Amy LKDC should not yield a hostname; a synthetic `Amys-MBP.local A 192.168.0.142` should).
2. **`NameSourceMDNS` + rememberIPName** — unit tests that DHCP (85) is not demoted.
3. **Listener goroutine** — join multicast on `en0`; log learned `ip → name` at info level.
4. **Engine apply-on-learn** — persist + SSE; confirm UI updates while a scan is not running.
5. **Remove timed `dns-sd -B` loop** — keep on-demand `LookupHostnameDeep` / Resolve name button.
6. **Interface change** — rejoin multicast when `SetActiveNetwork` sees a new iface.

Do not implement TP-Link scraping or DHCP sniffing in this work.

---

## Acceptance

- Gofing running for several minutes learns a name for a device that was missing at startup **if** that device (or a sleep proxy) sends an A/SRV with a sane `.local` name.
- Learned names survive `gofing` restart (BoltDB) and survive a scan where `arp -a` is still `?`.
- `dhcp` names from the router import are not replaced by weaker mDNS instance strings (e.g. `iPad (73)` must not beat `Amys-MBP` if DHCP already set it — instance names are not A-record hostnames; do not write instance names into `Hostname` unless no hostname exists).
- LKDC-only traffic does not create garbage hostnames.
- `go test ./...` and `go build -o gofing .` pass.
- Manual: leave Gofing up, wake Amy’s Mac (open lid / use it), confirm `Amys-MBP` appears without clicking Resolve name. If it still never publishes an A record, DHCP import remains the name — that is expected.

---

## Manual check (after implementation)

```bash
# Terminal 1: Gofing
make run

# Terminal 2: confirm multicast is flowing
sudo tcpdump -ni en0 -c 20 udp port 5353

# Wake a quiet Apple device, then:
# UI should update; or
curl -s localhost:8080/api/devices | python3 -c "import json,sys; \
  [print(d.get('hostname'), d.get('ip'), d.get('name_source')) \
   for d in json.load(sys.stdin)]"
```

---

## Relation to DHCP import

| Source | When it wins |
|---|---|
| Router DHCP (`importdhcp.go` / future poll) | Device already leased; may be asleep; no mDNS |
| Always-on mDNS | Device (or sleep proxy) announces while Gofing is running |
| Custom name in the UI | User override; already highest display priority |

Both caches key off MAC. DHCP import was the bootstrap for this LAN. Always-on mDNS is how names stay current without pasting `sample.log` again.
