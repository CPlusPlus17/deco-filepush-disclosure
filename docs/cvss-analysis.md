# CVSS analysis — Deco XE75 Pro V3, owner-authenticated debug-channel arbitrary root file write
_Date: 2026-10-17. Status: **corrected** assessment (CVSS v3.1 + v4.0). Supersedes the earlier 9.9 draft — see "Why not 9.9"._

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

## Impact (the one part that is unambiguously maximal)
- **Confidentiality: H** — full root FS read via sibling opcode `0xF0`
  (WiFi PSKs, cloud credentials, decrypted user-config).
- **Integrity: H** — arbitrary root write to `/etc/config` (live), `/www`
  (served by uhttpd), `/tp_data/user_data` (persistent ubifs), and the LuCI
  index cache (→ root Lua execution → arbitrary root binary exec, verified).
- **Availability: H** — reload/init/config overwrite can disrupt the whole
  network or corrupt config state (firmware 1.5.0 is non-downgradable).

## CVSS v3.1 — corrected

### Metric justification
| Metric | Value | Rationale |
|---|---|---|
| AV | **N** *(see caveat)* | Primary claim assumes the service is reachable via the TP-Link cloud-relay path with the account; **demonstrated only from the LAN**, so `AV:A` is the honest fallback until remote reachability for *this* TMPv2 path is shown. "If port-forwarded" is non-default and is **not** a valid basis for `AV:N`. |
| AC | L | Deterministic, no race, no special state, single request. |
| PR | **H** | Requires the **owner / TP-Link-ID account** — the device's *administrative* principal. CVSS `PR` measures privilege **over the vulnerable component** (the router/management plane), not the OS UID. There is no lower-privileged tier; the owner account *is* the admin. (The earlier `PR:L` conflated OS-UID with CVSS-PR.) |
| UI | N | No victim interaction; the attacker holds the credentials. |
| S | **U** | The vulnerable handler **already runs as root (UID 0)**. Exploitation crosses **no authority boundary** — a root service writes the root FS, one and the same security authority. A separate *process* (`tmpsvr`) is not a separate *security scope*. (The earlier `S:C` was the main inflation.) |
| C | H | Full root FS read (opcode `0xF0`). |
| I | H | Arbitrary root write, persistent flash, code execution. |
| A | H | Reload/init/config overwrite can disrupt the whole network. |

### Score
```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  = 7.2 (High)     <- recommended
CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  = 6.8 (Medium)   <- if LAN-only (AV:A)
```
Computed with the FIRST v3.1 spec equations, roundup() to 1 decimal.

### Why NOT 9.9 (rejected inflations)
The earlier 9.9 depended on two aggressive calls, both rejected here:
- **`S:C` → `S:U`** (biggest single swing, ~1 pt). The handler is already
  root; nothing escapes a sandbox or crosses an authority boundary. "Distinct
  process" ≠ "distinct scope." A PSIRT/CNA strikes `S:C` here immediately.
- **`PR:L` → `PR:H`** (~1.5 pt). Owner/TP-ID account = administrative control
  over the component.
- `AV:N` is retained only provisionally; if reachability is LAN-only, `AV:A`
  applies and the score is **6.8 (Medium)**.

Net: a defensible **High ~7.2**, not Critical 9.9 — a ~2.7-point correction.

## CVSS v4.0

### Metric justification
| Metric | Value | Rationale |
|---|---|---|
| AV | N *(or A)* | Same reachability caveat as v3.1. |
| AC | L | No security-mitigation evasion required. |
| AT | **N** | No attack *requirements* (no race, no precondition beyond the attacker's control); the credential requirement lives in `PR`, not `AT`. |
| PR | **H** | Owner/admin account (as above). |
| UI | N | No interaction. |
| VC / VI / VA | **H / H / H** | Full compromise of the vulnerable system (the router): root read, root write, availability. |
| SC / SI / SA | **N / N / N** *(primary)* | Conservative: direct impact is confined to the vulnerable system (the router). **Alternative**, if you argue the router mediates all client traffic and therefore subsequent systems are impacted: `SC:H/SI:H/SA:L` — this is the v4.0 analogue of the old scope debate; state it explicitly rather than smuggling it into the base. |

### Vector + score
```
Primary:     CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
Subsequent:  CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:L   (if "router → client traffic" argued)
LAN-only:    CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```
#### Equivalence-class derivation (primary vector; E:X, CR/IR/AR:X)
v4.0 computes a MacroVector from six equivalence classes (EQ1–EQ6), then
interpolates within it. For the primary vector:

| EQ | Metrics | Value here | Level |
|----|---------|------------|-------|
| EQ1 | AV / PR / UI | AV:N, PR:H, UI:N — not all "N" (PR:H), AV≠P | **1** |
| EQ2 | AC / AT | AC:L ∧ AT:N | **0** |
| EQ3 | VC / VI / VA | all H | **0** |
| EQ4 | SC / SI / SA (+ safety) | all N, no safety | **2** |
| EQ5 | E | E:X → treated as Attacked | **0** |
| EQ6 | CR/IR/AR × VC/VI/VA | CR:X=H ∧ VC:H | **0** |

→ **MacroVector = `100200`.** Subsequent-impact variant (`SC:H`/`SI:H`) flips
EQ4 to level 1 → **`100100`**.

#### Scores (band)
- `100200` (primary) → **High**, estimated **~8.3–8.6**.
- `100100` (subsequent-impact argued) → **High–Critical**, estimated **~8.9–9.3**.
- LAN-only (`AV:A`) → same MacroVector `100200`, a notch lower via the
  intra-macrovector interpolation → **~7.5–8.0 (High)**.

**Honesty note:** the equivalence-class derivation above is exact and reproducible.
The *final decimal*, however, comes from the official 270-entry MacroVector table
plus the severity-distance interpolation — data I will not reproduce from memory.
Treat the figures above as a reasoned band and **confirm the exact decimal in the
FIRST CVSS v4.0 calculator** (https://www.first.org/cvss/calculator/4-0) before
quoting a precise number in the advisory. (Note: v4.0 does not differentiate
`AV:N` vs `AV:A` at the MacroVector level — both are EQ1=1 here because `UI:N`
alone satisfies the clause — so that distinction appears only in the interpolated
decimal, not the MacroVector.)

Why v4.0 ≠ the v3.1 7.2: v4.0 removes the `Scope` metric (so the old `S:C`
trick is gone) but weights full vulnerable-system impact more heavily, so the
primary vector tends to land a little **above** 7.2 while still **well below**
the inflated 9.9 — unless you justify the subsequent-system (`SC/SI`) impact.

## Real-world severity (prose — where the base score undersells)
CVSS base is capped by `PR:H`, but the operational risk is higher than 7.2
suggests and belongs in the report narrative: TP-Link-ID passwords are
**phished, reused, and breached at scale**, and the same cloud account is
what provisions the device. So a single stolen/reused owner password converts
to **persistent root on the home router + the whole mesh**, enabling MITM of
all client traffic and flash-level persistence (1.5.0 non-downgradable). Score
it honestly as High; argue the impact in prose and (optionally) via the v4.0
subsequent-system metrics — not by inflating the base vector.

## Related finding (same class as CCS'24, NOT a new primitive) — corrected
`tty2tcp/start` (opcode `0xc505`, `luci.controller.admin.mobile_app.debug`):
`params.ipaddr` + `params.port` concatenated into a string passed to
`/bin/sh -c` via `luci.sys.fork_exec` with no validation/quoting. Same handler
family as the UCR SecLab CCS 2024 work ("Untangling the Knot", Deco X55, entry
via cracked 512-bit RSA hostkeys). Confirmed present and unvalidated in 1.5.0
Rel.15804 (static decompilation). Positioning: related/confirmatory, **not** a
separate CVE.
- If scored standalone (corrected, same `PR:H`/`S:U` reasoning):
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2** (the earlier 8.8
  used the same `PR:L` overclaim).

## Hostkey status on 1.5.0 (verified live, 2026-10-17, all 3 mesh units)
- ssh-rsa 2048-bit, IDENTICAL factory key on all 3 units:
  `SHA256:9feb3ac47a4a08ce7fe8a104c8b024cdfb438315ec9f6d6eec2980537c932a36`
- ecdsa-sha2-nistp521 per-unit keys.
- ⇒ CCS'24's 512-bit RSA crack path is CLOSED on this firmware; the
  password-auth path (SHA1(email) + TP-Link account pw) is the live entry.

## Scope notes (keep honest in any report)
- **Owner-authenticated** channel; NOT an unauthenticated exposure. This is a
  post-auth, owner-privileged escalation to root — reflected by `PR:H`.
- Reachability **demonstrated from the LAN** on 1 main unit (XE75 Pro V3, FW
  1.5.0 Build 20260603 Rel.15804); same handler present in the extracted 1.5.0
  userspace (decompiled, static). Remote/cloud reachability for this TMPv2 path
  is asserted, not yet demonstrated — keep `AV` honest accordingly.
- Non-destructive verification only (write/read-back, LuCI cache swap with
  byte-exact restore, persistent probe on ubifs).
