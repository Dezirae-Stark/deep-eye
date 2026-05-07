# Recon Bridge — Operator Runbook (deep-eye side)

The recon bridge lets deep-eye consult a running Shadowbroker instance
*before* a scan to (1) confirm the target is in scope and (2) pull
aggregated OSINT intel (Shodan, CT logs, geopolitics, region dossier)
that recon_engine merges into its results.

For the **why** and the architectural decisions, see
`docs/superpowers/specs/2026-05-05-shadowbroker-integration-design.md`.

This runbook is the **how**.

---

## Prerequisites

1. A reachable Shadowbroker instance with `/bridge/*` enabled. See the
   server-side runbook in the Shadowbroker repo for setup.
2. From the Shadowbroker operator: a `key_id` and an HMAC secret (hex).
3. A scope manifest — copy `config/scope/example-engagement.yml` and
   replace the `manifest_id`, `expires_at`, `authorization`, and
   `targets.include` blocks with your engagement details. Drop the same
   manifest into the Shadowbroker side under `SCOPE_MANIFEST_DIR`.

## Setup (one-time per environment)

```bash
# 1. Export the HMAC secret. The secret never lives in YAML.
export BRIDGE_HMAC_KEY="<hex-secret-from-shadowbroker-operator>"

# 2. Edit config/config.yaml — add the shadowbroker_bridge section
#    (see config/config.example.yaml for the template).
shadowbroker_bridge:
  enabled: true
  base_url: "https://shadowbroker.internal:8000"
  key_id: "deep-eye-prod-1"
  scope_token: "engagement-acme-2026q2"
  scope_manifest_path: "config/scope/engagement-acme-2026q2.yml"
  timeout: 10

# 3. Smoke test (no real scan, just startup):
python deep_eye.py -u https://acme.com --no-banner
# You should see:
#   ✓ Shadowbroker bridge: target authorized, enrichment loaded (0 feed errors)
```

## CLI flags

| Flag | Purpose |
|------|---------|
| `--no-bridge` | Force-disable the bridge for this run, even if `enabled: true`. Useful when the bridge is down and you need to scan a target you've already authorized. |
| `--bridge-scope-token <id>` | Override `shadowbroker_bridge.scope_token` from config. Handy when one config serves multiple engagements. |
| `--bridge-base-url <url>` | Override `shadowbroker_bridge.base_url`. Useful for staging vs. prod bridges. |

## Running scans

Once configured, `python deep_eye.py -u https://acme.com` runs:

1. **Scope check** (signed POST `/bridge/scope/check`). If the target is
   out of scope, deep-eye exits with `Bridge refused start: target ... not in scope`.
2. **Enrichment** (signed GET `/bridge/enrich/<host>`). The result is
   merged under `recon_engine` results as `shadowbroker.{shodan, geo,
   region_dossier, ct_logs, ct_subdomains, geopolitics_alerts, feed_errors}`.
3. The scan proceeds normally. Reports include the bridge enrichment.

## Troubleshooting

### `Bridge refused start: target ... not in scope for ...`
The bridge's scope manifest doesn't include the target. Either:
- The target is genuinely out of scope (correct behavior — don't bypass).
- The wrong `scope_token` is being used. Check `config/config.yaml` and
  `--bridge-scope-token`.
- The manifest `expires_at` has passed. Get a renewed manifest.

### `Bridge refused start: BRIDGE_HMAC_KEY env var is unset`
The bridge is enabled in config but the HMAC secret isn't exported.
`export BRIDGE_HMAC_KEY=...` and retry.

### `Bridge refused start: bridge unreachable during scope check`
Network/timeout failure. Check the `base_url` is correct and the
Shadowbroker process is up. To bypass once — `--no-bridge` (only safe if
you have a local-authority basis to proceed without the bridge).

### `signature mismatch` (auth error)
- Wrong `BRIDGE_HMAC_KEY` for this `key_id` — check with the Shadowbroker operator.
- Clock skew — ensure NTP is sane on both hosts (60s window).
- A proxy or middleware in between is mangling the URL path. The bridge
  signs the *decoded* canonical path; intermediate URL re-encoding does
  not break the signature, but body modification will. Disable any
  request-rewriting proxy.

### `replay detected`
You sent the exact same signed request twice within 5 minutes. The
nonce cache is process-local, so this is almost always:
- A double-click / retry without timestamp regeneration.
- Two deep-eye instances racing on the same target.
Re-run; each request uses a fresh timestamp.

### Partial enrichment (`feed_errors` populated)
Some upstream feeds (Shodan, ip-api, crt.sh, GDELT) timed out or
returned errors. The scan still proceeds with whatever the rest of the
feeds returned. This is expected for free-tier APIs with rate limits.

## Operating notes

- **Key rotation**: when the Shadowbroker operator rotates secrets, swap
  `BRIDGE_HMAC_KEY` and bounce deep-eye. Old keys keep working until
  removed from the bridge's key map.
- **Scope expiry**: manifests have mandatory expiry. Plan ahead — once
  expired, every scope_check returns false and scans cannot start.
- **Logs**: `logs/deep_eye.log` records bridge phase outcomes. Search
  for `bridge` or `shadowbroker_bridge` to find them.
