# Report to TP-Link Security (coordinated disclosure)

To: security@tp-link.com
Cc: <your email — optional>
Date: 2026-10-17
Subject: [Security Vulnerability Disclosure] Deco XE75 Pro V3 (FW 1.5.0 Build 20260603 Rel.15804) — owner-authenticated debug channel: arbitrary root file write (inner_file_push, opcode 0xC456)

Dear TP-Link Security Team,

I am reporting a vulnerability in the Deco XE75 Pro V3 (firmware 1.5.0 Build
20260603 Rel.15804), found during owner-driven reverse engineering on my own
3-unit mesh. A proof-of-concept and write-up are prepared; I am notifying you
concurrently with public (full / 0-day) disclosure (see "Disclosure timeline"
below). This report contains no credentials or secrets.

## Summary
The owner-authenticated debug SSH channel (Dropbear on TCP 20001, direct-tcpip
forwarding only; password auth = SHA1(owner email) as username + the TP-Link
account password) reaches the internal `tmpsvr` service at 127.0.0.1:20002. The
Lua handler `inner_file_push` (opcode `0xC456`, in the
`luci.controller.admin.mobile_app.iot_device` module) opens `params.file` in
`"w"` mode and writes `params.content` verbatim as UID 0 — with no path
allowlist, no size limit, and no privilege drop. A sibling opcode (`0xF0`)
provides a matching root file read. Net effect: an authenticated read + write of
the entire root filesystem, which on a router is the whole device.

## Handler (decompiled from the exact 1.5.0 userspace)
    local f = io.open(params.file, "w")
    if f then
      f:write(params.content)
      f:close()
    end

## Affected
- Product: TP-Link Deco XE75 Pro V3 (3-unit mesh).
- Firmware: 1.5.0 Build 20260603 Rel.15804. Handler present in the extracted
  1.5.0 userspace; demonstrated live on the main unit, reachable from the LAN on
  TCP 20001.
- Likely broader: `tmpsvr` and the `0xC456` / `0xF0` / `0xC505` handlers are
  shared vendor code and may affect additional Deco models/firmware. Unverified
  on my side — please assess across the product line.

## Impact (live-verified, non-destructive, on my own unit)
- `/etc/config` is live writable ramfs (config changes honored by the router).
- `/www` is served over HTTPS by uhttpd (pushed pages immediately reachable).
- `/tp_data/user_data` is persistent ubifs flash (survives reboot).
- The LuCI route cache can be swapped with Lua and triggered via `GET
  /cgi-bin/luci` → root Lua → `io.popen` → arbitrary root binary execution.

## CVSS (honest assessment — High, not Critical)
This is a **post-authentication, owner-privileged** escalation to root (`PR:H`),
and the vulnerable handler **already runs as root** (`S:U`) — so it scores High,
not Critical. The operational risk is nonetheless significant and is argued in
the narrative below.

    CVSS v3.1:  7.2 (High)    CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
                (6.8 Medium if reachability is LAN-only — AV:A)
    CVSS v4.0:  8.6 (High)    CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                (8.5 High if LAN-only — AV:A; 9.3 Critical with Subsequent-System impact SC:H/SI:H/SA:L)

Full rationale, including why we reject the `S:C`/`PR:L` (9.9) scoring, is in the
accompanying `docs/cvss-analysis.md`.

Operational severity (where the base score undersells): TP-Link ID passwords are
phished, reused, and breached at scale, and the same account provisions the
device — so a single stolen/reused owner password converts to persistent root
across the whole mesh and enables MITM of all client traffic (and 1.5.0 is
non-downgradable).

## Context vs. prior public work
UCR SecLab (CCS 2024, "Untangling the Knot"; Black Hat USA 2024) publicly
documented this exact `:20001 → 127.0.0.1:20002` (`tmpsvr`) debug channel and
demonstrated root compromise on older Deco models by factoring 512-bit RSA
hostkeys and abusing unvalidated `tmpsvr` handlers.

In 1.5.0 the hostkeys were bumped to 2048-bit RSA (one shared factory key across
all three of my units, `SHA256:9feb3ac47a4a08ce7fe8a104c8b024cdfb438315ec9f6d6eec2980537c932a36`,
plus per-unit `ecdsa-sha2-nistp521`), which closes the 512-bit factorization
path. However, the underlying root-level handlers appear unchanged:
- Password auth on `:20001` (`svr_auth_uci`) remains enabled, gated by the
  TP-Link ID password.
- `0xC456` (`inner_file_push`) still writes arbitrary paths as root.
- `0x00F0` still reads arbitrary files as root.
- `0xC505` (`tty2tcp/start`) still builds a `/bin/sh -c` string from
  `params.ipaddr` + `params.port` without quoting/validation (the command-
  injection family noted in the 2024 work). Confirmed present in 1.5.0 by static
  decompilation; not independently exploited by me (listed for completeness).

## Suggested remediation
*Write primitive — `0xC456` (`inner_file_push`):*
1. Remove the handler if it has no production purpose. If a transfer path is
   genuinely required: canonicalize the target (`realpath`), enforce an allowlist
   of a single service-owned directory, open with `O_NOFOLLOW` and
   write-to-temp + atomic rename, reject `..` / symlinks / absolute paths
   escaping the jail, and cap content size.
2. Drop privileges — run file-transfer and diagnostic handlers under a dedicated
   unprivileged UID that owns only its target directory, not UID 0.

*Sibling read `0xF0` and command exec `0xC505` (`tty2tcp`):*
3. `0xF0`: same canonicalize + allowlist + privilege drop; restrict to the
   specific diagnostic files that genuinely must be readable.
4. `0xC505`: never build a `/bin/sh -c` string — use an `execve` argv vector with
   no shell, and validate `params.ipaddr` via `inet_pton` and `params.port` as an
   integer in range; or remove it if it is diagnostic-only / unused on this HW.

*Channel and platform:*
5. `:20001` debug channel: disable by default; if it must remain for the cloud
   tunnel, gate it on a per-device secret rather than the shared TP-Link ID
   password, and tighten the `direct-tcpip` destination allowlist.
6. Issue unique per-device SSH host keys — the `ssh-rsa` factory key is currently
   identical across units, which enables impersonation / MITM within a fleet.
7. Privilege-separate `tmpsvr` / LuCI (a small root broker with unprivileged
   workers) so a single handler bug cannot yield full root; audit every remaining
   opcode that writes or executes as root.

*Non-security, related:* ship the omitted `/lib/iot_network/iot_eth.sh` and
enable 802.1Q IoT VLAN tagging in AP mode, so owners are not pushed to patch
basic network segmentation themselves.

## Reproduction / PoC (published)
A self-contained PoC (`poc/deco_filepush_poc.py`) is included in the published
repository. It takes credentials only via environment variables, writes
a single inert marker to `/www/log_export` (ramfs), requires byte-exact readback
via the device's own `0xF0` read, and confirms unmodified HTTPS serving. I can
provide the full decompiled module and the TMPv2 framing derivation on request.

## Disclosure timeline
This is a full (0-day) disclosure: the write-up, PoC, and companion project are
published publicly concurrently with this report. The `tmpsvr` debug channel and
the `tty2tcp` (`0xC505`) command-injection family were publicly documented at
CCS 2024 / Black Hat USA 2024 — two years ago — and remain unmitigated in 1.5.0
beyond the RSA key-size bump. Given that prior public notice and the lack of
remediation, I am not applying a further embargo, and I am disclosing the
related `inner_file_push` (`0xC456`) root-write primitive together with it.

Requests:
- Please acknowledge receipt and advise on a remediation timeline.
- I will share the full decompiled module and TMPv2 framing derivation on request.
- I am glad to retest candidate fixes.
- Please assign a CVE (as the affected vendor / CNA); otherwise advise and I will
  request one via MITRE.

## CVE
I would appreciate TP-Link (as the affected vendor / CNA) assigning a CVE. If you
prefer, I can request one via MITRE instead — please advise.

## Good-faith research statement
All testing was performed on my own three units, authenticated with my own
TP-Link ID credentials, non-destructively (single inert marker, byte-exact
readback, verified rollback; LuCI cache swap with byte-exact restore). No
third-party devices, networks, or accounts were accessed, and no customer data
was involved.

Thank you for your time, and for maintaining a security contact.

Best regards,
<your name / handle>
<your email>   (PGP: <optional fingerprint>)
Write-up + PoC (published): https://github.com/CPlusPlus17/deco-filepush-disclosure
