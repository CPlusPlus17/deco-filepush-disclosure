# Report to TP-Link Security (verbatim)

To: security@tp-link.com
Cc: [owner address]
Date: 2026-10-17
Subject: Deco XE75 Pro V3 (FW 1.5.0 Build 20260603 Rel.15804) — owner-authenticated debug channel: arbitrary root file write (inner_file_push, opcode 0xC456)

Dear TP-Link Security Team,

I am reporting an issue in the Deco XE75 Pro V3 (firmware 1.5.0 Build
20260603 Rel.15804), found during owner-driven reverse engineering on my
own mesh. A PoC and write-up are available at
https://github.com/CPlusPlus17/deco-filepush-disclosure and I am posting to
the community in parallel with this report.

## Summary
The owner-authenticated debug SSH channel (Dropbear on TCP 20001,
direct-tcpip forwarding only, password auth = SHA1 of the owner email +
the TP-Link account password) reaches the internal tmpsvr service at
127.0.0.1:20002. The Lua handler `inner_file_push` (opcode 0xC456, in the
`luci.controller.admin.mobile_app.iot_device` module) opens
`params.file` in "w" mode and writes `params.content` verbatim as UID 0,
with no path allowlist, no size limit, and no privilege drop. A sibling
opcode (0xF0) provides a matching root file read. Net effect: an
authenticated read+write of the entire root filesystem.

## Handler (decompiled from the exact 1.5.0 userspace)
    local f = io.open(params.file, "w")
    if f then
      f:write(params.content)
      f:close()
    end

## Impact (live-verified, non-destructive, owner's own unit)
- /etc/config is live writable ramfs
- /www is served over HTTPS by uhttpd
- /tp_data/user_data is persistent ubifs flash (survives reboot)
- LuCI route cache can be swapped with Lua and triggered via GET
  /cgi-bin/luci -> root Lua -> io.popen -> arbitrary root binary execution

## CVSS 3.1 (our assessment)
AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H  ->  9.9 (Critical)
Fallback if you prefer: S:U -> 8.8; PR:H+S:C -> 9.1; PR:H+S:U -> 7.2.

## Context vs. prior public work (2 years after CCS 2024 / Black Hat 2024)
UCR SecLab (CCS 2024 "Untangling the Knot"; Black Hat USA 2024) publicly
documented this exact `:20001 -> 127.0.0.1:20002` (`tmpsvr`) debug channel
two years ago and demonstrated root compromise on older Deco models by
factoring 512-bit RSA hostkeys and abusing unvalidated `tmpsvr` handlers.

Despite having **two full years (2024 to June 2026, FW 1.5.0 Build 20260603)**
to audit and harden `tmpsvr`, the only fix applied in 1.5.0 was a superficial
key-size bump from 512-bit RSA to 2048-bit RSA (one shared factory key across
all three of my mesh units, `SHA256:9feb3ac47a4a08ce7fe8a104c8b024cdfb438315ec9f6d6eec2980537c932a36`,
plus per-unit `ecdsa-sha2-nistp521`). The underlying root-level handlers
inside `tmpsvr` were left completely untouched:
- **Password authentication on `:20001` (`svr_auth_uci`)** remains enabled by
  default using the shared TP-Link ID password.
- **Opcode `0xC456` (`inner_file_push`)** still writes arbitrary files to any
  path as `root` (`io.open(params.file, "w")`) with zero validation.
- **Opcode `0x00F0`** still reads arbitrary files as `root`.
- **Opcode `0xC505` (`tty2tcp/start`)** — the exact unquoted `/bin/sh -c`
  command-injection handler family highlighted in the 2024 research — is
  **still present and unvalidated in the June 2026 firmware (`1.5.0`)**.

## Suggested fixes
1. Path-allowlist `inner_file_push` (or confine it to a service-private dir).
2. Cap content size; reject `.` / `..` and absolute paths outside the
   intended target dir.
3. Reconsider whether the debug channel should be on by default and whether
   the shared TP-Link account password (identical across the mesh) is the
   right gate vs. a per-device secret.
4. Quote/validate the `tty2tcp` command build and audit all remaining `tmpsvr`
   opcodes running as `root`.
5. Officially ship the omitted `/lib/iot_network/iot_eth.sh` script and enable
   802.1Q IoT VLAN tagging in AP mode so owners do not have to patch basic
   network segmentation in themselves.

## Reproduction
See the self-contained PoC in the repo
(`poc/deco_filepush_poc.py`, `--selftest` / `--run`). It writes one inert marker
to `/www/log_export` (ramfs), requires byte-exact readback via the device's
own `0xF0` read, and confirms unmodified HTTPS serving.

## Why immediate public disclosure
1. **Two years already elapsed since CCS 2024 / Black Hat 2024:** Because the
   `:20001 -> :20002` `tmpsvr` attack surface was publicly disclosed in 2024
   and only received an RSA key-length bump while leaving `0xC456`, `0x00F0`,
   and `0xC505` unfixed in the 2026 firmware, further embargoing leaves
   customers unaware that their TP-Link ID password gates full `root`
   filesystem access on port `20001`.
2. **Preventing e-waste & enabling basic network segmentation:** In 2026,
   isolating IoT devices onto a tagged VLAN is a baseline security
   requirement, yet on 1.5.0 that feature is artificially left unfinished in
   AP mode (`/lib/iot_network/iot_eth.sh` omitted, `iot_network` VLAN lines
   commented out). Releasing both this advisory and our companion VLAN
   implementation (`https://github.com/CPlusPlus17/deco-iot-vlan`) allows
   Deco owners to immediately secure port `20001` and equip their existing
   hardware with proper 802.1Q VLAN segmentation instead of discarding working
   routers as e-waste.

Happy to coordinate or share the full decompiled module, the offline framing
derivation, and the mesh hostkey inventory.

Thank you,
[Redacted — sent privately to security@tp-link.com]
