# Shadowbroker ↔ deep-eye Integration — Design Spec

**Status:** Approved (brainstorming phase complete)
**Date:** 2026-05-05
**Author:** Dezirae-Stark
**Repos in scope:** [`zakirkun/deep-eye`](https://github.com/zakirkun/deep-eye) (forked), [`BigBodyCobain/Shadowbroker`](https://github.com/BigBodyCobain/Shadowbroker) (forked)

---

## 1. TL;DR

Integrate Shadowbroker's OSINT feeds into deep-eye such that:

1. Every deep-eye scan can be enriched with Shadowbroker intel (Shodan, region dossier, geopolitics, CT logs).
2. deep-eye gains a non-URL input mode — IP, CIDR, ASN, or Shadowbroker pin — using Shadowbroker as the discovery layer.
3. Shadowbroker's map gains a vulnerability layer; right-clicking any pin can launch a deep-eye scan and findings render back on the map in real time.

The integration is **bidirectional**, communicates over **HMAC-signed HTTP/JSON** mirroring Shadowbroker's existing OpenClaw agentic channel, and is gated by a **mandatory authorization scope manifest** validated on three layers (frontend, bridge, deep-eye daemon).

---

## 2. Goals & Non-Goals

### Goals

- A: Pre-scan target enrichment for the existing deep-eye CLI workflow.
- B: New CLI input modes (IP / CIDR / ASN) that use Shadowbroker for HTTP-service discovery.
- C: Two-way bridge — Shadowbroker right-click → deep-eye scan → findings rendered on map.
- Authorization scope manifest as a first-class object, with mandatory expiry and three-layer validation.
- Forks of both repos remain *additive only* — no edits to existing files where avoidable; new code lives in new files / new routers / new components.
- Existing deep-eye standalone CLI (`deep_eye.py -u <url>`) and existing Shadowbroker Docker workflow (`docker compose up -d`) keep working unchanged when the integration is not configured.

### Non-Goals

- Replacing or refactoring deep-eye's existing `osint_enhanced.py`. It remains the fallback when Shadowbroker is unreachable.
- Replacing Shadowbroker's existing feeds. We *consume* them, we don't reimplement them.
- Submitting upstream PRs to either project. The fork is a private maintenance contract.
- Changing deep-eye's standalone report formats (PDF/HTML/JSON). Findings still write to disk for the CLI workflow; the bridge submission is in addition, not instead.
- A "scan everything" mode. There is no UI affordance to scan a country, a continent, or "all pins of type X" without a per-target scope check.
- Offline mode for deep-eye that bypasses the bridge's scope check when the bridge is unreachable. **No fallback bypasses scope.**

---

## 3. Architecture & Topology

Hybrid (T4) deployment:
- **Shadowbroker** runs as a persistent service (Docker compose, always on, owns the map UI and the findings store).
- **deep-eye** runs on-demand. Two modes:
  - **CLI mode** (existing + enhanced): `deep_eye.py -u <url> [--enrich-from-shadowbroker] [--scope-token <id>]`
  - **Daemon mode** (new): `deep_eye.py --shadowbroker` — long-running FastAPI app that listens for scan jobs from the bridge.
- **Same-host** dev: both processes on `127.0.0.1`, HMAC keys in a shared `.env`. **Remote** ops: deep-eye on a separate host, points its config at Shadowbroker's public URL, HMAC keys exchanged out-of-band. The HTTP contract is identical in both topologies.

```
┌──────────────────────────────────────────────────────────────────────┐
│                     SHADOWBROKER (forked)                            │
│  ┌─────────────────┐     ┌────────────────────────────────────────┐  │
│  │  Frontend       │     │  Backend (FastAPI)                     │  │
│  │  Next.js + Map  │ ──► │                                        │  │
│  │  + Vuln Layer   │     │  Existing routers (unchanged):         │  │
│  │  + Right-click  │     │    /ai_intel, /sar, /sigint, ...       │  │
│  │    "Scan" item  │     │                                        │  │
│  └────────┬────────┘     │  ┌─────────────────────────────────┐   │  │
│           │              │  │ NEW: routers/recon_bridge.py    │   │  │
│           │              │  │   POST /bridge/scan             │   │  │
│           │              │  │   GET  /bridge/findings         │   │  │
│           │              │  │   GET  /bridge/enrich/{target}  │   │  │
│           │              │  │   POST /bridge/scope/check      │   │  │
│           │  WS/SSE      │  └─────────────┬───────────────────┘   │  │
│           ▼              │                │                       │  │
│   findings layer ◄───────┤  NEW: services/recon_bridge/           │  │
│   updates live           │    scope_manifest.py                   │  │
│                          │    findings_store.py (SQLite)          │  │
│                          │    deep_eye_client.py  ◄──┐            │  │
│                          │    hmac_auth.py            │            │  │
│                          │    pin_target_resolver.py  │            │  │
│                          └────────────────────────────┼────────────┘  │
└──────────────────────────────────────────────────────┬┴──────────────┘
                                                       │
                              HMAC-signed HTTP/JSON    │
                              (mirror OpenClaw pattern)│
                                                       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     DEEP-EYE (forked)                                │
│  Existing CLI:                                                       │
│    deep_eye.py -u https://target.com                                 │
│                                                                      │
│  + NEW: deep_eye.py --shadowbroker (daemon mode)                     │
│         Listens for scan jobs from Shadowbroker, returns findings    │
│                                                                      │
│  modules/reconnaissance/                                             │
│    + shadowbroker_client.py                                          │
│    + sb_target_resolver.py                                           │
│                                                                      │
│  core/                                                               │
│    + shadowbroker_daemon.py                                          │
│    + scope_enforcer.py                                               │
│                                                                      │
│  config/                                                             │
│    + shadowbroker.example.yaml                                       │
└──────────────────────────────────────────────────────────────────────┘
```

### Topology principles

1. **Shadowbroker is the system of record for findings.** It owns the SQLite store, renders the map layer, and presents results. deep-eye is stateless: it scans, posts, forgets.
2. **Either side can initiate.** Flow A (CLI enrichment) — deep-eye initiates. Flow B (CLI infra-scan) — deep-eye initiates, but uses Shadowbroker as discovery. Flow C (right-click scan) — Shadowbroker initiates.
3. **Two transports, one contract.** The HTTP API is identical whether processes are co-located or remote.
4. **deep-eye CLI mode still works standalone.** Integration is gated behind explicit flags (`--enrich-from-shadowbroker`, `--shadowbroker`).
5. **Findings flow asynchronously.** Scans push findings as they're discovered; Shadowbroker frontend receives them via SSE. No polling.

---

## 4. Component Breakdown

### New files in the **Shadowbroker fork**

```
backend/
├── routers/
│   └── recon_bridge.py            ← NEW: ~200 lines, FastAPI router
└── services/
    └── recon_bridge/              ← NEW: matches services/infonet/, services/sar/ pattern
        ├── __init__.py
        ├── scope_manifest.py      ← Loads scope.yml, validates targets
        ├── findings_store.py      ← SQLite-backed: findings, scan_jobs tables
        ├── deep_eye_client.py     ← HMAC HTTP client to deep-eye daemon
        ├── hmac_auth.py           ← Shared signing/verifying (mirrors openclaw_channel.py)
        └── pin_target_resolver.py ← Map any pin's payload → scannable target dict

frontend/src/
├── components/
│   ├── VulnLayer/                 ← NEW: map layer for finding pins
│   │   ├── VulnLayer.tsx
│   │   ├── FindingPin.tsx
│   │   └── FindingDetailPanel.tsx
│   └── ScanLauncher/               ← NEW: right-click "Scan" menu + dialog
│       ├── ScanContextMenu.tsx
│       └── ScanDialog.tsx
└── lib/
    └── reconBridge.ts             ← Frontend client for /bridge/* endpoints
```

Backend `main.py` requires one line: include the new router. No edits to existing routers, services, or frontend components — the vulnerability layer is added as a sibling layer alongside existing ones.

### New files in the **deep-eye fork**

```
core/
├── shadowbroker_daemon.py         ← NEW: FastAPI app, exposes /agent/scan, /agent/health, /agent/cancel
└── scope_enforcer.py              ← NEW: client-side scope check (defense in depth)

modules/reconnaissance/
├── shadowbroker_client.py         ← NEW: HMAC HTTP client → /bridge/enrich/*
└── sb_target_resolver.py          ← NEW: IP/CIDR/ASN → list of HTTP-reachable URLs

config/
└── shadowbroker.example.yaml      ← NEW: bridge_url, hmac_key_id, scope_manifest_path
```

`deep_eye.py` (existing) gets two new flags:
- `--shadowbroker` — daemon mode (mutually exclusive with `-u`)
- `--enrich-from-shadowbroker` — CLI flag, enables flow A
- `--target-ip <ip|cidr>`, `--target-asn <asn>` — flow B inputs (mutually exclusive with `-u`)
- `--scope-token <manifest_id>` — required for any non-URL input or when `--enrich-from-shadowbroker` is set

### Stateless deep-eye

`findings_store.py` lives **only** on the Shadowbroker side. deep-eye writes its existing report files to disk for the CLI workflow; Shadowbroker remembers findings for the map. Stateless agents simplify horizontal scaling — multiple deep-eye workers can sit behind one Shadowbroker.

### Pin target resolver — the only S4-aware component

`pin_target_resolver.py` is the *only* place that knows Shadowbroker pin semantics. It encodes the S4 mapping for each pin type:

| Pin type | Scannable target | Notes |
|---|---|---|
| Shodan device | `https://{ip}:{port}/` from pin payload | direct |
| CCTV camera | HTTP URL from pin payload | direct |
| Aircraft (ADS-B) | airline web domains via lookup table | indirect, table-driven |
| Ship (AIS) | operator web domains via lookup table | indirect |
| Power plant / data center | operating company web domains via lookup table | indirect |
| Satellite | *no scannable target* | filtered out before scope check |
| Mesh radio node | *no scannable target* | filtered out |
| ... | ... | ... |

The rest of the pipeline downstream of the resolver only sees `{kind: "url"|"ip", value: "..."}` — same shape as flows A and B. New pin types (Shadowbroker ships fast) only require updates to this single file.

---

## 5. API Contract

### Shadowbroker bridge endpoints (`backend/routers/recon_bridge.py`)

#### `POST /bridge/scan`
Triggers a scan via deep-eye. Called by frontend (right-click flow) or by external scripts.

**Request** (HMAC-signed):
```json
{
  "target": {
    "kind": "url" | "ip" | "cidr" | "asn" | "pin",
    "value": "https://target.com" | "1.2.3.4" | "1.2.3.0/24" | "AS15169" | "{pin_id}",
    "pin_payload": { ... }
  },
  "scope_token": "engagement-acme-2026-q1",
  "scan_profile": "quick" | "full" | "api-only" | "auth-only",
  "callback_session": "sse-session-uuid"
}
```

`scan_profile` values:
- `quick` — existing deep-eye quick mode (low-depth crawl, common vuln classes only).
- `full` — existing deep-eye full mode (45+ attack methods, deeper crawl).
- `api-only` — runs only the `modules/api_security/` and `modules/business_logic/` checks; assumes target is a JSON/GraphQL API.
- `auth-only` — runs only the `modules/authentication/` checks; assumes target is a login surface.

**Response (immediate):**
```json
{ "scan_job_id": "...", "status": "queued" | "rejected_out_of_scope" | "rejected_no_capacity" }
```

#### `GET /bridge/enrich/{target}`
Returns aggregated intel for a single host or URL. Called by deep-eye CLI in flow A.

**Response:**
```json
{
  "target": "target.com",
  "resolved_ips": ["1.2.3.4"],
  "shodan": { "ports": [...], "cves": [...], "tags": [...] },
  "geo": { "country": "US", "asn": "AS15169", "org": "Google LLC" },
  "region_dossier": { ... },
  "geopolitics_alerts": [...],
  "ct_logs": [...],
  "stale_after": "2026-05-05T22:00:00Z"
}
```

Cached server-side for 60s per target.

#### `GET /bridge/findings?scope_token=...&since=...`
Returns findings for a scope manifest. Called by Shadowbroker frontend to render the vulnerability layer; also accepts `since` for incremental fetch.

**Response:**
```json
{
  "findings": [
    {
      "id": "...", "scan_job_id": "...",
      "target": "https://target.com/api/users",
      "lat": 37.7, "lng": -122.4,
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "vuln_class": "sqli" | "xss" | "...",
      "title": "Time-based blind SQLi on /api/users id parameter",
      "evidence": { ... },
      "cwe": "CWE-89",
      "discovered_at": "2026-05-05T21:30:00Z",
      "ai_provider": "claude" | "openai" | "..."
    }
  ]
}
```

#### `POST /bridge/scope/check`
Pre-flight scope validation. Called by frontend before showing right-click menu, by bridge before dispatch, and by deep-eye daemon before scan.

**Request:**
```json
{ "target": { ... }, "scope_token": "engagement-acme-2026-q1" }
```

**Response:**
```json
{ "in_scope": true | false, "reason": "matched cidr 1.2.3.0/24" | "no scope rule matched", "manifest_id": "...", "mode": "engagement" }
```

#### `POST /bridge/findings` (internal, deep-eye → bridge)
deep-eye posts findings as scans progress. HMAC-signed. Server inserts into `findings_store` and pushes SSE events to subscribed sessions.

### deep-eye daemon endpoints (`core/shadowbroker_daemon.py`)

Smaller surface — only Shadowbroker calls these.

- `POST /agent/scan` — accept a scan job, return immediately, work async. Same payload shape as `/bridge/scan`.
- `GET /agent/health` — liveness, current capacity (concurrent jobs running / max).
- `POST /agent/cancel/{scan_job_id}` — abort an in-flight scan.

---

## 6. Data Flows

### Flow A — Pre-scan enrichment (CLI initiates)

```
User             deep-eye CLI                  Shadowbroker bridge        upstream feeds
 │                    │                              │                        │
 │ ──scan target─►   (1) load shadowbroker.yaml      │                        │
 │                   (2) HMAC GET /bridge/enrich/target ──►                   │
 │                    │                             (3) parallel fan-out ──► shodan
 │                    │                              │                   ──► region_dossier
 │                    │                              │                   ──► geopolitics
 │                    │                              │                   ──► ct_logs
 │                    │                             (4) merge + cache 60s     │
 │                    │ ◄────── enrichment JSON ─────                         │
 │                   (5) feed into recon_engine.py + AI payload generator     │
 │                   (6) run scan as normal                                   │
 │ ◄── PDF/HTML report                                                        │
```

If Shadowbroker is unreachable: log warning, fall back to existing `osint_enhanced.py` recon, scan proceeds. **Enrichment is opportunistic, never blocking.**

### Flow B — Infrastructure scan (CLI, non-URL input)

```
User             deep-eye CLI                  Shadowbroker bridge          deep-eye scanner
 │                    │                              │                            │
 │ ─CIDR + scope─►   (1) HMAC POST /bridge/scope/check ──►                       │
 │                    │ ◄── in_scope: true ──                                    │
 │                   (2) sb_target_resolver: expand CIDR → IPs                   │
 │                       HMAC GET /bridge/enrich/{ip} for each (batched 16x)     │
 │                       ───► (3) returns Shodan port data                       │
 │                   (4) filter: keep only IPs with HTTP/HTTPS open              │
 │                   (5) probe / on each → derive base URL                       │
 │                   (6) feed list into existing scanner_engine.py loop ─────► (scan)
 │                   (7) per finding: HMAC POST /bridge/findings                 │
```

Without Shodan available, the resolver refuses to expand CIDRs larger than `/30` and asks the user to narrow input. This prevents accidental wide scans.

### Flow C — Right-click scan (Shadowbroker initiates)

```
Browser              Shadowbroker bridge         deep-eye daemon          map
   │                       │                            │                    │
   │ right-click pin → menu (only shown if in-scope)    │                    │
   │ ─POST /bridge/scope/check─►                        │                    │
   │ ◄── in_scope: true ──                              │                    │
   │ ─POST /bridge/scan ─►                              │                    │
   │  {pin_payload, scope_token, scan_profile}          │                    │
   │                      (1) bridge: pin_target_resolver                    │
   │                      (2) bridge: server-side scope re-check (✓)         │
   │                      (3) bridge: write scan_jobs row "queued"           │
   │                      (4) HMAC POST /agent/scan ──►                      │
   │                                                  (5) daemon scope_enforcer
   │                                                       re-checks (defense in depth)
   │                                                       starts scan async
   │ ◄── 200 {scan_job_id, status:queued} ──            │                    │
   │ subscribed to SSE channel for this scope_token     │                    │
   │                       │ ◄── HMAC POST /bridge/findings (per finding) ── │
   │                      (6) findings_store.insert                          │
   │                      (7) SSE push to subscribed sessions                │
   │ ◄── SSE event "finding" ──                                              │
   │ (8) VulnLayer renders pin at finding's lat/lng                          │
   │     color-coded by severity                                             │
```

### Scan job state machine

```
queued ──► running ──► completed
   │           │           │
   │           ├──► partial (some findings, scanner errored mid-run)
   │           └──► cancelled (user clicked Cancel)
   │           └──► cancelled_scope_expired (manifest expired during scan)
   └──► rejected_out_of_scope
   └──► rejected_no_capacity
```

---

## 7. Scope Manifest

Single file per engagement / bounty / lab session, signed, lives in deep-eye's `config/scope/`. The bridge mirrors a copy on the Shadowbroker side so server checks don't depend on the agent.

### Schema

```yaml
# config/scope/engagement-acme-2026-q1.yml
version: 1
manifest_id: "engagement-acme-2026-q1"
mode: engagement                    # engagement | bounty | self | lab
created_at: "2026-02-01T00:00:00Z"
expires_at: "2026-04-15T00:00:00Z"  # MANDATORY in all modes — no exceptions

authorization:
  contract_ref: "Acme Pentest SOW 2026-Q1, signed 2026-01-15"
  contact: "security@acme.com"
  signing_key_fingerprint: "sha256:..."   # detached signature alongside file

targets:
  include:
    domains:    ["acme.com", "*.acme.com", "api.acme-cdn.io"]
    ip_cidrs:   ["198.51.100.0/24"]
    asns:       ["AS64512"]
  exclude:                          # checked FIRST — explicit out-of-scope wins
    domains:    ["admin.acme.com", "*.payroll.acme.com"]
    ip_cidrs:   ["198.51.100.5/32"]

bounty:                             # mode: bounty — synced from HackerOne/Bugcrowd
  program: "acme-public-bounty"
  last_synced: "2026-05-04T...Z"

lab:                                # mode: lab — bypasses target match, still expires
  region_lock: "10.0.0.0/8"         # CIDR — only targets resolving inside this network are accepted
```

### Validation rules (`scope_manifest.py`, identical on both sides)

1. Manifest expired (`expires_at < now`) → reject every target. No exceptions.
2. Target matches `exclude` → reject. Exclusions always win.
3. Mode is `lab` and target is inside `region_lock` → accept.
4. Target matches `include` → accept.
5. No match → reject with reason `"no scope rule matched"`.

### Multi-manifest

Multiple manifests can be loaded simultaneously. Each scan request names a `scope_token` (= `manifest_id`); the validator only checks against that specific manifest. Two engagements running side-by-side cannot accidentally bleed scope.

### Mandatory expiry

Every manifest, every mode, must have `expires_at`. There is no "never" sentinel. This is the single most important guardrail — forever-authorized scope is the most common way pentest tools cause harm in the wild. Renewal is one git commit; bypass is impossible.

---

## 8. HMAC Channel

Mirror Shadowbroker's existing `services/openclaw_channel.py` pattern — deep-eye becomes a sibling agent under the same scheme.

- **Algorithm**: HMAC-SHA256.
- **Signed material**: `METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + SHA256(BODY)`.
- **Headers**: `X-Bridge-Key-Id`, `X-Bridge-Timestamp`, `X-Bridge-Signature`.
- **Replay protection**: timestamp must be within 60s of server clock; nonce cache (in-memory LRU, 5min TTL) blocks duplicate `(key_id, timestamp, signature)` triples.
- **Key storage**: env vars only, never on disk. Bridge holds both directions' keys. deep-eye holds only its own signing key plus the bridge's public key id.
- **Per-agent key isolation**: OpenClaw and deep-eye get different `key_id`s. Compromise of one doesn't authorize the other.

Out-of-band key exchange for remote topology: documented as a manual operator procedure (no auto-rotation in this design — future work).

---

## 9. Error Handling

Each failure mode has a deliberate response, not a generic try/except.

| Failure | Where | Response |
|---|---|---|
| Network blip (timeout, 502) | Any HTTP call | Exponential backoff retry, max 3 attempts, then surface. CLI flow A's enrichment retries are capped at 1 — never block a scan on slow recon. |
| HMAC verification failure | Receiver side | No retry. Log key_id + reason, return `401`. Possible attack — surface to ops monitoring. |
| Scope rejection | Either scope check | **Not an error.** Return `403` with reason. Frontend renders "Out of scope: {reason}" inline, no toast. |
| Scan crashes mid-run | deep-eye daemon | Mark job `partial`, POST whatever findings already collected, log stack trace. |
| Daemon at capacity | deep-eye daemon | Return `429` with current/max counts. Bridge queues request with 5min TTL, returns `queued`; frontend shows queue position. |
| Shadowbroker unreachable from CLI flow A | deep-eye CLI | Log warning, fall back to existing `osint_enhanced.py` recon, scan proceeds. **Enrichment never blocks a scan.** |
| deep-eye daemon unreachable from flow C | Bridge | Frontend shows "deep-eye agent offline" with last-seen timestamp from `/agent/health` poll. No silent failure. |
| Manifest expired during running scan | Server-side validator on next finding POST | Job marked `cancelled_scope_expired`, in-flight scan signaled to stop. Findings already stored remain (they were authorized when collected). |

### Non-negotiable rule

There is no fallback path that bypasses scope check. A network failure to the bridge during flow C does not produce a "scan it anyway" branch. Either scope is verified, or the scan does not run.

---

## 10. Testing Strategy

### Unit (per file, table-driven)

- `scope_manifest.py` — every rule combination (expired, excluded, lab-mode, multi-manifest), both sides.
- `pin_target_resolver.py` — every Shadowbroker pin type maps to expected target shape.
- `hmac_auth.py` — sign/verify roundtrip, replay rejection, expired timestamp rejection, key-id mismatch.
- `sb_target_resolver.py` — CIDR expansion budget, ASN→IP via Shodan mock, HTTP probe filtering.

### Integration (one repo at a time, mocked sibling)

- deep-eye side: `httpx-mock` impersonates the bridge; exercise flows A and B end-to-end.
- Shadowbroker side: FastAPI `TestClient` + mocked `deep_eye_client`; exercise flow C end-to-end.
- Both: scope rejection paths return correct reason strings, no false positives, no false negatives.

### End-to-end (docker-compose, both real services)

- Spin up Shadowbroker fork + deep-eye daemon in compose.
- Scripted scenarios:
  1. Right-click in-scope Shodan pin → scan completes → finding renders.
  2. Right-click out-of-scope pin → "Scan" menu item not present.
  3. Tamper frontend to send out-of-scope target → bridge `403`.
  4. Tamper bridge to skip server scope check (chaos test) → daemon `403`.
  5. Manifest expires mid-scan → job cancelled cleanly, prior findings retained.
  6. deep-eye crashes mid-scan → bridge marks `partial`, frontend shows "Partial: 3 findings before crash."
  7. CLI flow A with bridge offline → falls back to local recon, scan proceeds.

### Security tests

- Replay attack rejection.
- HMAC tampering (signature, body, header).
- Expired scope manifest.
- Manifest schema validation refuses unknown YAML fields (no extension by malformed input).

---

## 11. Future Work (Out of Scope for This Spec)

- Auto-rotation of HMAC keys.
- Multi-tenant scope manifests served from a central authority.
- Findings export to STIX/TAXII (Shadowbroker has `stix_exporter.py` already — wire-up is straightforward but separate).
- Findings re-scoring via Shadowbroker's `correlation_engine.py` (e.g., a vulnerability is more critical when the target is in a region with active geopolitical tension).
- LLM-driven Shadowbroker pin classification — let an LLM map novel pin types to scannable targets instead of the static lookup table.
- Multi-agent fanout: multiple deep-eye workers behind one bridge for parallel scan capacity.

---

## 12. Open Questions

None at design-approval time. Future implementation may surface specifics — those will be resolved in the implementation plan.
