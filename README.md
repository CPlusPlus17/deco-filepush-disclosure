# Deco XE75 Pro V3 — owner-authenticated debug channel: arbitrary root file write

Research disclosure, **TP-Link Deco XE75 Pro V3**, firmware **1.5.0 Build
20260603 Rel.15804**. Reported to `security@tp-link.com` and released
publicly alongside our 802.1Q IoT VLAN implementation ([deco-iot-vlan](https://github.com/CPlusPlus17/deco-iot-vlan)).

## Summary

The Deco's owner-authenticated debug SSH channel (Dropbear on TCP 20001,
`direct-tcpip` forwarding only, password auth) reaches an internal
`tmpsvr` service on `127.0.0.1:20002`. One of its Lua handlers,
`inner_file_push` (opcode `0xC456`), opens `params.file` in `"w"` mode and
writes `params.content` verbatim **as root, with no path allowlist, no size
limit, and no privilege drop**. A sibling opcode (`0xF0`) provides a
matching root file read. Together: authenticated read + write of the entire
root filesystem, which on a router is the whole device.

```
SSH :20001  (username = SHA1(owner_email), password = TP-Link account password)
  -> direct-tcpip -> 127.0.0.1:20002 (TMPv2)
     -> 0xC456 inner_file_push : io.open(file,"w"); write(content); close()   [root]
     -> 0x00F0 root file read  : byte-exact file read                          [root]
```

## Impact (live-verified, non-destructive)

- `/etc/config` is a live writable ramfs → change a key, the router honors it.
- `/www` is served over HTTPS by uhttpd → pushed files are immediately reachable.
- `/tp_data/user_data` is persistent ubifs flash → survives reboot.
- The LuCI route cache can be swapped with attacker Lua, triggered via
  `GET /cgi-bin/luci` → root Lua execution → `io.popen` → arbitrary root
  binary execution.

All four steps were executed and reverted on the owner's own main unit.

## Why this is new — and why `tmpsvr` is still unfixed 2 years after CCS'24 / Black Hat '24

The UCR SecLab team publicly documented the `:20001 -> 127.0.0.1:20002` (`tmpsvr`) debug channel **two years ago** in **CCS 2024 — "Untangling the Knot: Breaking Access Control in Home Wireless Mesh Networks"** (and Black Hat USA 2024 — "Fallen Tower of Babel"). Their entry point on older Deco models (X55, FW 1.2.2) was **factoring 512-bit RSA hostkeys** and abusing unvalidated `tmpsvr` handlers.

**TP-Link had two full years (2024 → June 2026, FW `1.5.0 Build 20260603`) to audit and lock down `tmpsvr`. Instead, they only applied a superficial band-aid:**
- They increased the `ssh-rsa` hostkey size from 512-bit to **2048-bit** (one shared factory key across all three mesh units, `SHA256:9feb3ac4...932a36`, plus per-unit `ecdsa-sha2-nistp521`), closing only the 512-bit factorization headline from the 2024 talk.
- **They left the underlying `root` handlers in `tmpsvr` completely untouched in 2026 firmware `1.5.0`:**
  1. **Password auth on `:20001` (`svr_auth_uci`)** remains active using `SHA1(owner_email)` + the shared TP-Link ID password.
  2. **Opcode `0xC456` (`inner_file_push`)** still opens any caller-supplied path in `"w"` mode as `root` with zero path validation.
  3. **Opcode `0x00F0`** still reads any file on the filesystem as `root`.
  4. **Even opcode `0xC505` (`tty2tcp/start`)** — the exact unquoted `/bin/sh -c` command-injection handler highlighted in the 2024 paper — is **still sitting in the June 2026 firmware (`1.5.0`) completely unfixed**.

## Affected (as observed)

- Product: TP-Link Deco XE75 Pro V3 (3-unit mesh; one main unit + two slaves)
- Firmware: 1.5.0 Build 20260603 Rel.15804
- Surface: TCP 20001 (debug SSH) reachable from the LAN; the handler is in
  the extracted 1.5.0 userspace (`luci/controller/admin/mobile_app/iot_device`
  module, `inner_file_push`).

## CVSS 3.1

```
AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H  →  9.9 Critical
```

Fallback positions if the vendor prefers a different scope:

| Vector variant | Score |
|---|---|
| `S:U` (Scope Unchanged) | 8.8 |
| `PR:H` + `S:C` | 9.1 |
| `PR:H` + `S:U` | 7.2 |
| `AV:A` (LAN only) + `S:U` | 8.0 |

## Proof of concept

`poc/deco_filepush_poc.py` — self-contained (stdlib + paramiko). Credentials
via `DECO_EMAIL` / `DECO_PASSWORD` env vars only.

```
python3 poc/deco_filepush_poc.py --selftest        # offline framing sanity
DECO_EMAIL=you@example.com DECO_PASSWORD=*** \
  python3 poc/deco_filepush_poc.py --run           # write marker + readback + HTTPS check
DECO_EMAIL=you@example.com DECO_PASSWORD=*** \
  python3 poc/deco_filepush_poc.py --cleanup <nonce>   # overwrite marker with empty content
```

The PoC writes a single inert marker to `/www/log_export` (ramfs; also
cleared on reboot), then requires **byte-exact readback through the device's
own root-read opcode** and **unmodified HTTPS serving** before reporting
success.

## Reproduction summary (live, 2026-10-17)

1. `ssh-keyscan -p 20001 <deco>` → pin host key (2048-bit RSA shared across
   the mesh + per-unit nistp521).
2. SSH with `SHA1(owner_email)` / TP-Link account password, request
   `direct-tcpip` to `127.0.0.1:20002`.
3. TMPv2 association (`01010100` → `01010200` → `01010200`), then opcode 1
   token request.
4. Opcode `0xC456`, `{"params":{"file":"/www/log_export/deco-write-<nonce>.html",
   "content":"..."}}` → `{"error_code":0,...}`.
5. Opcode `0xF0`, `{"params":{"file":"..."}}` → byte-exact readback.
6. `GET https://<deco>/log_export/deco-write-<nonce>.html` → 200, exact bytes.

## Scope / honesty

- Owner's own hardware, owner's own credentials.
- Non-destructive: single marker, byte-exact restore, verified rollback.
- Demonstrated on the main unit; the same handler is present in the
  extracted 1.5.0 userspace for the whole mesh.
- The `tty2tcp` (0xc505) path is confirmed present + unvalidated (static)
  but not live-verified as a separate injection; listed for completeness.

## Why Public Release (Preventing E-Waste & Right to Network Security)

This research started from a simple, defensive goal: isolating untrusted IoT devices onto a tagged 802.1Q VLAN across a 3-unit Deco XE75 Pro V3 mesh running in Access Point mode.

In 2026, basic network segmentation (putting IoT devices on an isolated VLAN) is a fundamental security requirement — yet on stock firmware `1.5.0`, the feature is artificially left unfinished (`/lib/iot_network/iot_eth.sh` is omitted from the rootfs and the VLAN logic in `/etc_ro/init.d/iot_network` is commented out). That left a stark choice: **either throw away three completely capable Wi-Fi 6E mesh routers as e-waste, or reverse-engineer the firmware and patch the missing functionality in ourselves.**

We chose to release both this security advisory and the companion VLAN implementation ([deco-iot-vlan](https://github.com/CPlusPlus17/deco-iot-vlan)) publicly so that:
1. **Every Deco owner can take immediate defensive precautions** (setting a strong, unique TP-Link ID password and restricting TCP port `20001` on their LAN/VLANs rather than remaining unaware of an exposed `root` file-write interface).
2. **Owners can equip their existing Deco hardware with proper 802.1Q IoT VLAN segmentation** instead of turning working hardware into e-waste when basic security features are withheld.

## Files

- `README.md` — this file
- `TEAM-SUMMARY.md` — how the multi-agent team (claude, codex, gemini, and hermes/Qwen) found it
- `poc/deco_filepush_poc.py` — self-contained PoC
- `docs/cvss-analysis.md` — scoring rationale + fallback matrix
- `docs/handler-source.md` — decompiled `inner_file_push` handler + references
- `tp-link-email.md` — the report sent to security@tp-link.com
- `reddit-post.md` — community post drafts

## Credit

Independent owner-driven reverse engineering. Happy to share the full
decompiled module, the offline framing derivation, and the mesh hostkey
inventory on request.
