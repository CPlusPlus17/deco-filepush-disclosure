# CVSS analysis — Deco XE75 Pro V3, debug-channel arbitrary root file write
_Date: 2026-10-17. Status: internal assessment, pre-disclosure draft._

## The flaw (single vulnerability to score)
The owner-authenticated debug SSH channel (Dropbear :20001, username =
SHA1(owner email), password = TP-Link account password) allows
`direct-tcpip` forwarding to `127.0.0.1:20002` (TMPv2 / `tmpsvr`).
Opcode `0xC456` (`luci.controller.admin.mobile_app.iot_device`,
`inner_file_push`, handler `L93_1` in firmware 1.5.0 Rel.15804):

- takes `params.file` (path) and `params.content` (payload)
- calls `io.open(file, "w")`, writes content verbatim, closes
- NO path allowlist, NO size limit, NO directory check
- runs as UID 0

Same service, opcode `0xF0`: root file read (diagnostic reader).
Together: authenticated read+write of the entire root filesystem.

## Impact
- Integrity: H — any file writable: `/etc/config` (live), `/www` (served
  by uhttpd), `/tp_data/user_data` (persistent ubifs), LuCI index cache
  (=> Lua execution => arbitrary root binary exec, verified live)
- Availability: H — overwrite init scripts / configs / reload => service
  disruption or bricking of config state (firmware 1.5.0 non-downgradable)
- Confidentiality: H — via the sibling read opcode 0xF0 in the same
  authenticated service (WiFi PSKs, cloud credentials, decrypted
  user-config)

## Metric justification
| Metric | Value | Rationale |
|---|---|---|
| AV | N | Service reachable over the network (LAN/WAN if port forwarded or guest/isolation off) |
| AC | L | Deterministic, no race, no special state, single request |
| PR | L | Owner debug-account credentials required (authenticated, not OS-privileged) |
| UI | N | No victim interaction; attacker holds the creds (shared/reused TP-Link pw) |
| S | C | Debug TMP service is a distinct component from the rest of the router OS (config partitions, filesystem, services) — write crosses into the product scope |
| C | H | Full root FS read via sibling opcode 0xF0 |
| I | H | Arbitrary root write, persistent flash, code execution |
| A | H | Reload/init/config overwrite can disrupt the whole network |

## Score matrix (verified against FIRST CVSS v3.1 spec equations)
```
9.9  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H   <- recommended (S:C)
8.8  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H   <- if vendor argues S:U
9.1  CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H   <- if vendor argues owner = PR:H
7.2  CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H   <- vendor-favorable corner
8.0  CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H   <- if AV:A (LAN-only)
```
All scores computed with the spec's roundup() to 1 decimal.

**Recommended: 9.9 (Critical)** — the S:C argument is strong: the
vulnerable component (tmpsvr debug service, Lua handlers) is
separate from the affected component (entire router OS, config
partitions, userspace). This matches how similar "local admin service
writes past its sandbox" findings are scored.

**Expected vendor pushback:**
1. S:U → 8.8 (still High, borderline Critical)
2. PR:H (owner account = high privilege) → 9.1 (still Critical)
3. AV:A (LAN service) → 8.0 (High)

## Related finding (same class as CCS'24, NOT a new primitive)
`tty2tcp/start` (opcode 0xc505, `luci.controller.admin.mobile_app.debug`):
`params.ipaddr` + `params.port` concatenated into a string passed to
`/bin/sh -c` via `luci.sys.fork_exec` with no validation/quoting.
This is the same handler family the UCR seclab CCS 2024 work
("Untangling the Knot") used for its reverse-shell on Deco X55 (where
entry was via cracked 512-bit RSA hostkeys). We confirm it is present
and unvalidated in 1.5.0 Rel.15804 (static decompilation).
Positioning: related/confirmatory, not a separate CVE.
If scored standalone: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8.

## Hostkey status on 1.5.0 (verified live, 2026-10-17, all 3 mesh units)
- ssh-rsa 2048-bit, IDENTICAL factory key on all 3 units:
  SHA256:9feb3ac47a4a08ce7fe8a104c8b024cdfb438315ec9f6d6eec2980537c932a36
- ecdsa-sha2-nistp521 per-unit keys (pinned in analysis/mesh-vlan/ssh-pins.json)
- => CCS'24's 512-bit RSA crack path is CLOSED on this firmware.
  The password-auth path (SHA1(email) + TP-Link account pw) is the
  live entry; this is the differentiator vs. prior public work.

## Scope notes (keep honest in the post)
- Demonstrated on 1 main unit (192.168.68.1), XE75 Pro V3, FW 1.5.0
  Build 20260603 Rel.15804. Same handler present in the extracted
  1.5.0 userspace (decompiled, static).
- Owner-authenticated channel; not an unauthenticated exposure.
- Non-destructive verification only (write/read-back, LuCI cache swap
  with byte-exact restore, persistent probe on ubifs).
