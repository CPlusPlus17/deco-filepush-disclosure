# Ready-to-Post Reddit Drafts

This file contains four tailored drafts ready for copy-pasting depending on the subreddit:
1. **`r/netsec` / `r/ReverseEngineering` / `r/hardwarehacking`** — Technical advisory & firmware reverse-engineering focus
2. **`r/LocalLLaMA`** — Multi-agent reverse engineering (`agents.comm`) & why open-weight models (**Qwen** via **Hermes**) were essential when commercial APIs (**Opus 4.8 / 5.5**, etc.) became unusable due to overly strict filter rules
3. **`r/homelab` / `r/HomeNetworking`** — How *"I just wanted an IoT VLAN on my 3 Deco XE75 Pros in AP mode"* turned into rooting firmware 1.5.0 and building real 802.1Q VLAN 30 tagging to OPNsense
4. **`r/TpLink`** — Concise owner heads-up (Port `:20001` password hygiene + why IoT/Guest VLANs don't tag in AP mode on 1.5.0)

---

## 1. `r/netsec`, `r/ReverseEngineering`, `r/hardwarehacking`

> **Tip for `r/netsec`:** Submit as a **Link Post** pointing to `https://github.com/CPlusPlus17/deco-filepush-disclosure` and paste the text below as the top-level summary comment. For `r/ReverseEngineering` and `r/hardwarehacking`, submit directly as a **Text Post**.

**Title:**
`[TP-Link Deco XE75 Pro V3] Two years after CCS'24 / Black Hat '24, TP-Link only bumped the RSA key size — Port 20001 -> tmpsvr still gives Arbitrary Root File Write (0xC456) & RCE on 2026 Firmware 1.5.0`

**Body:**
**Repository (Write-up, Decompiled Handlers, Self-Contained PoC, Multi-Agent Log):**
https://github.com/CPlusPlus17/deco-filepush-disclosure

**TL;DR:** Two years ago (CCS 2024 *"Untangling the Knot"* / Black Hat USA 2024), UCR SecLab researchers publicly disclosed that TP-Link Deco routers expose an internal `tmpsvr` service (`127.0.0.1:20002`) via SSH port forwarding on TCP port `20001` with unvalidated `root` handlers.

**TP-Link had two full years (2024 → June 2026, Firmware `1.5.0 Build 20260603 Rel. 15804`) to audit and fix `tmpsvr`. Instead, they only applied a cosmetic band-aid:** they bumped the SSH RSA hostkey from 512-bit to 2048-bit (to stop the 512-bit factorization headline from the 2024 talk) and **left the underlying `root` handlers inside `tmpsvr` completely untouched**:
- **Password auth on `:20001` (`svr_auth_uci`)** is still open (`username = SHA1(owner_email)`, `password = TP-Link ID password`).
- **Opcode `0xC456` (`inner_file_push`)** still opens any caller-supplied path in `"w"` mode and writes arbitrary content verbatim as `root` (`uid=0`) — zero path allowlist, zero traversal check.
- **Opcode `0x00F0`** still reads any file on the device as `root`.
- **Even Opcode `0xC505` (`tty2tcp/start`)** — the exact unquoted `/bin/sh -c` command-injection handler from the 2024 paper — is **still sitting unfixed in the June 2026 firmware (`1.5.0`)**.

### What's Exposed on the Wire
1. **TCP `:20001` (Dropbear SSH):** Modified `svr_auth_uci()` compares the SSH username against `accountmgnt.cloud_account.username` (`SHA1(owner_email)`) and `crypt()`s the password against `cloud_account.shadow`. `svr_chansess.c` rejects `session`/`exec`, but `svr-tcpfwd.c` allows `direct-tcpip` forwarding to `127.0.0.1:20002`.
2. **Loopback `:20002` (`tmpsvr` / TMPv2):**
   - Opcode `0x00F0` = arbitrary file read as `root`.
   - Opcode `0xC456` (`inner_file_push`) = **arbitrary file write as `root`**.

### The Decompiled Handler (`1.5.0 Build 20260603 Rel. 15804`)
```lua
-- luci.controller.admin.mobile_app.iot_device -> inner_file_push (opcode 0xC456)
local f = io.open(params.file, "w")   -- caller-controlled path, running as UID 0
if f then
  f:write(params.content)             -- caller-controlled bytes, verbatim
  f:close()
end
```
Zero path validation, zero directory confinement, and `error_code = 0` returned immediately.

### Verified Impact (Live-Tested on Owner's 3-Unit Mesh)
1. **Live Web Root (`/www/log_export`):** RAM-backed directory served over HTTPS `:443` by `uhttpd`. Pushing a file via `0xC456` makes it immediately live over HTTPS.
2. **Live UCI Config (`/etc/config`):** Mounted as a writable `ramfs`. Any config file can be overwritten in place.
3. **Persistent Flash (`/tp_data/user_data`):** Mounted `rw,sync` UBIFS (`ubi2:ubi_runtime_data`). Writes survive reboots. We also traced `luci/sys/config.lua` + `luci/model/crypto.lua`, extracted the `libtrkutil` AES-256-CBC key/IV, and decrypted all 14 encrypted NVRAM config blobs (`zlib` + `AES-256-CBC` XML) offline.
4. **Arbitrary `root` Command Execution (`io.popen`):** By pushing a modified LuCI dispatch entry to `/tmp/luci-indexcache` via `0xC456` and triggering a single unauthenticated `GET /cgi-bin/luci`, `uhttpd` executes arbitrary Lua/shell commands as `uid=0(root)` (verified with byte-exact cache restoration afterward).

### CVSS Assessment (High — 7.2 in v3.1 / 8.6 in v4.0)
```text
CVSS v3.1: 7.2 (High)  CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  (6.8 Medium if LAN-only AV:A)
CVSS v4.0: 8.6 (High)  CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N  (8.5 High if AV:A; 9.3 Critical with SC:H/SI:H/SA:L)
```
*(Full scoring rationale — including why we score owner credentials as `PR:H` and `tmpsvr` already running as `root` as `S:U` rather than an inflated 9.9 `S:C`/`PR:L`, and why the operational risk of a single reused TP-Link ID password remains severe — is in [`docs/cvss-analysis.md`](https://github.com/CPlusPlus17/deco-filepush-disclosure/blob/main/docs/cvss-analysis.md)).*

### Why Immediate Public Release? (2 Years Unfixed + Preventing E-Waste)
1. **TP-Link already had two years since CCS'24 / Black Hat '24:** Instead of hardening `tmpsvr`, they only bumped the RSA key size from 512-bit to 2048-bit and left `0xC456`, `0x00F0`, and `0xC505` wide open in the 2026 firmware. Waiting quietly any longer only leaves Deco owners in the dark.
2. **Preventing e-waste & right to network security:** We started this project today with one defensive goal: isolating untrusted IoT devices onto a tagged VLAN on our 3-unit Deco XE75 Pro V3 mesh. On stock firmware `1.5.0`, that basic security feature is artificially withheld (`/lib/iot_network/iot_eth.sh` is omitted and the VLAN setup in `iot_network` is commented out). That left us with a choice: **either turn three completely capable Wi-Fi 6E routers into e-waste and throw them away, or reverse-engineer the firmware and patch the missing security feature in ourselves.**

We are releasing both the security advisory and our 802.1Q IoT VLAN implementation ([deco-iot-vlan](https://github.com/CPlusPlus17/deco-iot-vlan)) publicly so every Deco owner can (1) immediately take defensive precautions around port `20001` and their TP-Link ID password, and (2) equip their own Decos with proper VLAN segmentation instead of throwing working hardware away.

Full technical write-up, decompiled Lua handlers, standalone Python PoC (`--selftest` offline mode included), and our multi-agent reverse-engineering breakdown (`TEAM-SUMMARY.md`) are in the repo:
https://github.com/CPlusPlus17/deco-filepush-disclosure

---

## 2. `r/LocalLLaMA`

**Title:**
`How a 4-agent team (Claude, Codex, Gemini + local open-weight Qwen/Hermes) reverse-engineered a 2026 TP-Link Deco router in one afternoon — and why open-weight models were essential when Opus 4.8/5.5 became unusable due to filter rules`

**Body:**
Today I had a simple choice with my 3-unit **TP-Link Deco XE75 Pro V3** mesh (running 2026 firmware `1.5.0`): **either turn three perfectly good Wi-Fi 6E routers into e-waste because TP-Link artificially left out per-SSID IoT VLAN tagging in AP mode, or reverse-engineer the firmware and patch the feature in myself.**

I spun up a 4-agent reverse-engineering session coordinated through a single shared append-only text file (`agents.comm`, 1,346 lines / 75+ entries) to audit the firmware and find a way in.

By the end of the afternoon, the team had decrypted the firmware offline, discovered that **two years after the 2024 Black Hat / CCS Deco disclosure TP-Link had only bumped the RSA key size while leaving `tmpsvr` wide open**, found an unvalidated `root` arbitrary file-write primitive (`0xC456` `inner_file_push`) reachable over port `:20001`, achieved `root` command execution, decrypted the router's AES-256-CBC flash config partitions, got 802.1Q VLAN 30 working across all three mesh units ([deco-iot-vlan](https://github.com/CPlusPlus17/deco-iot-vlan)), and packaged a full vulnerability disclosure repo ([deco-filepush-disclosure](https://github.com/CPlusPlus17/deco-filepush-disclosure)).

**Full Disclosure Repo (including `TEAM-SUMMARY.md` and the standalone PoC):**
https://github.com/CPlusPlus17/deco-filepush-disclosure

### The 4 Agents & Their Lanes (grounded in `agents.comm`)
1. **`claude` (Anthropic Claude, hosted — 11 entries):** Probed Dropbear SSH on `:20001`, confirmed interactive shell channels (`session`) are rejected while `direct-tcpip` port forwarding to `127.0.0.1:20002` (`tmpsvr`) is allowed, and audited the decompiled Lua controllers to flag `0xC456` (`inner_file_push`) as a potential write primitive.
2. **`codex` (OpenAI Codex, hosted — 49 entries):** Decrypted and RSA-PSS-verified the `1.5.0` firmware image offline, unpacked the SquashFS rootfs, recovered the 555-entry native `tmpsvr` opcode table, decompiled the Lua 5.1 bytecode, and built a safety-locked RAM-only trial harness (with 120s/900s auto-revert watchdogs and byte-exact `/tmp/luci-indexcache` restoration) to test VLAN 30 across all three physical mesh units.
3. **`gemini` (Google Gemini, hosted — 5 entries):** Traced the stock OpenWrt init/hotplug scripts (`guest-eth.sh`, `apsd`, `iot_network`, `wificommon.sh`), proved why flipping `iot_wifi.iot.vlan_enable=1` in UCI is a 100% no-op (`iot_eth.sh` was omitted from the firmware) and why Guest VLAN tagging is gated off in `AP` mode (`ports '6t'` only), and decompiled `luci/sys/config.lua` + `luci/model/crypto.lua` (`zlib` + `AES-256-CBC` + `libtrkutil`).
4. **`hermes` (**Qwen**, open-weight running in the Hermes harness — 6 entries + cross-lane orchestration):** Executed the live `0xC456` write proofs across `/www/log_export`, `/etc/config`, and persistent `/tp_data/user_data` UBIFS flash, verified `root` command execution via `io.popen`, extracted the live `libtrkutil` AES-256-CBC key/IV, decrypted all 14 NVRAM config dumps offline, and wrote the standalone PoC and CVSS disclosure package.

### Why Open-Weight Models (Qwen / Hermes) Were Essential
The biggest practical lesson from this session was **what happens when you do legitimate hardware research on your own home router using only commercial APIs**:
- **Commercial API filter walls (especially Opus 4.8 & 5.5):** Even though every single step was run by me on my own home hardware (`192.168.68.1` / `.2` / `.3`) with my own credentials, the hosted models (**Claude**, **Codex**, and **Gemini**) repeatedly hit automated platform refusals the moment a task crossed from static analysis into verifying a write handler, testing live command execution, or editing a PoC script. In particular, **Opus 4.8 and 5.5 became completely unusable mid-session** due to overly strict filter rules blocking even follow-up work on my own device.
- **Open-weight continuity (`hermes` = Qwen):** Because **Qwen** was running in the **Hermes** harness without cloud policy filters, the workflow never hit a dead end. Whenever a hosted model refused a live verification step or got flagged, Qwen read the exact technical state from `agents.comm`, executed the live `0xC456` and `io.popen` probes, dumped and decrypted the flash configs, and packaged the PoC.
- **Best of both worlds:** Hosted frontier models were great for deep static decompilation, long-context script tracing, and strict unit-tested rollback harnesses, while the open-weight model provided uninterrupted agency and orchestration on the owner's hardware. Neither side alone would have finished the chain in one afternoon.

You can read the detailed breakdown in [`TEAM-SUMMARY.md`](https://github.com/CPlusPlus17/deco-filepush-disclosure/blob/main/TEAM-SUMMARY.md).

---

## 3. `r/homelab`, `r/HomeNetworking`

**Title:**
`I had to choose between turning 3 TP-Link Deco XE75 Pros into e-waste or patching in IoT VLANs myself — discovered TP-Link left Port 20001 root file-write unfixed 2 years after Black Hat '24, and built true 802.1Q VLAN 30 tagging to OPNsense`

**Body:**
If you run TP-Link Deco units (like the **XE75 Pro V3**) in **Access Point (AP) mode** in front of a real firewall (OPNsense / pfSense / UniFi), you've probably noticed two annoying limitations:
1. The Deco app has a dedicated **"IoT Network"** toggle, but it doesn't let you assign a VLAN ID to it — all IoT traffic gets dumped untagged onto `br-lan` alongside your main LAN.
2. Even if you try to use the **Guest Network VLAN ID** trick, it silently fails to tag Ethernet frames in AP mode unless you use specific port/backhaul setups.

In 2026, proper IoT network segmentation is a basic security requirement — and artificially withholding it on capable Wi-Fi 6E hardware is unacceptable. Today I faced a choice: **either throw three working Deco XE75 Pro units onto the e-waste pile, or reverse-engineer firmware `1.5.0 Build 20260603 Rel. 15804` and activate/patch the feature myself.**

### 1. Why the Stock Firmware Doesn't Tag IoT VLANs (Decompiled Rootfs Findings)
After decrypting and unpacking the `1.5.0` SquashFS rootfs:
- **The IoT VLAN knob exists in UCI, but is a total no-op:** `/etc/config/iot_wifi` actually has `option vlan_enable '0'`, and `/etc_ro/init.d/iot_network` has code for `iot_vlan_id` and `switch_iot_config` — **but TP-Link commented out lines 41–69 and omitted `/lib/iot_network/iot_eth.sh` from the firmware image!** Meanwhile `/lib/wifi/wificommon.sh` (line 651) hardcodes `uci_set wireless $section network "lan"`.
- **Guest VLAN in AP mode is gated in `/etc/init.d/guest-eth.sh`:** In `Router` mode, `guest-eth.sh` adds switch ports `0t 1t 2t 3t 6t` to the guest VLAN. In `AP` mode on the main unit, it only adds the internal CPU port (`6t`) and skips external switch port tagging.

### 2. How We Got Root Without UART — 2 Years After CCS'24 / Black Hat '24, `tmpsvr` Is Still Wide Open
Two years ago (CCS 2024 / Black Hat USA 2024), researchers showed that every Deco unit listens on **TCP port `20001`** (Dropbear SSH) and tunnels to `127.0.0.1:20002` (`tmpsvr`).
- **TP-Link had two years (2024 → June 2026) to secure `tmpsvr`.** All they did in firmware `1.5.0` was bump the SSH RSA key size from 512-bit to 2048-bit, while leaving password authentication (`SHA1(your_tplink_email)` + your TP-Link ID password) and the underlying `root` handlers completely untouched!
- On `tmpsvr`, opcode `0x00F0` still reads any file as `root`, opcode **`0xC456` (`inner_file_push`) still writes any file to any path as `root`** (`io.open(params.file, "w")`, zero path validation), and even the 2024 `tty2tcp` (`0xC505`) shell injection handler is still unfixed in the code.
- From `0xC456`, swapping `/tmp/luci-indexcache` gives full `root` Lua / shell execution (`io.popen`), and we were able to create a dedicated `br-iot` bridge (`eth1.30` + `ath08` 2.4GHz IoT VAP + `ath18` 5GHz IoT VAP + `switch1` VLAN 30 on `2t 6t`) across all three mesh units talking directly to OPNsense (`192.168.30.1`).

### 3. Why Public Release & Repositories
Because TP-Link already had two years since the 2024 disclosure and only increased the RSA key length while leaving `tmpsvr` unfixed, we are releasing both repositories publicly so that every Deco owner has the chance to (a) take immediate defensive precautions around port `20001` and their TP-Link ID password, and (b) equip their existing Decos with proper 802.1Q VLAN segmentation instead of replacing working hardware:
- **802.1Q IoT VLAN Runtime & Native Web-UI (`deco-iot-vlan`):** https://github.com/CPlusPlus17/deco-iot-vlan
- **Security Advisory & PoC (`deco-filepush-disclosure`):** https://github.com/CPlusPlus17/deco-filepush-disclosure

**Quick takeaway for Deco owners:** Make sure your TP-Link ID password is unique (never reused anywhere else) and restrict TCP port `20001`, because on 1.5.0 that port still exposes full `root` file read/write.

---

## 4. `r/TpLink`

**Title:**
`[Heads-Up / Technical Deep-Dive] Deco XE75 Pro V3 (Firmware 1.5.0): Why IoT VLAN tagging doesn't work in AP mode + Why Port 20001 is still a root risk 2 years after Black Hat 2024`

**Body:**
Hi everyone,

Today we had to choose between retiring our 3-unit **Deco XE75 Pro V3** mesh (firmware `1.5.0 Build 20260603 Rel. 15804`) as e-waste just because it lacked 802.1Q VLAN tagging for the IoT network in Access Point (AP) mode, or unpacking the firmware to see if we could patch it in ourselves. In 2026, basic IoT VLAN segmentation is an essential security feature that shouldn't be artificially withheld on capable hardware.

Here are the two main findings from our audit, released publicly so every Deco owner can both secure their units and enable proper VLAN segmentation:

1. **Why IoT Network VLANs don't work on 1.5.0 (even though the config field exists):**
   - Internally, `/etc/config/iot_wifi` has an `option vlan_enable` setting, and `/etc_ro/init.d/iot_network` references `/lib/iot_network/iot_eth.sh`.
   - However, in firmware `1.5.0`, the VLAN setup lines in `iot_network` are commented out and `/lib/iot_network/iot_eth.sh` is not included in the firmware image; `/lib/wifi/wificommon.sh` always pins the IoT VAPs (`ath08` / `ath18`) to `br-lan`.
   - With custom bridge/switch rules (`br-iot` + `eth1.<VID>` + switch port tagging `2t 6t`), the hardware and QCA drivers handle 802.1Q VLAN tagging for the IoT SSID across all mesh units cleanly — so TP-Link could easily enable this officially in a future firmware build!

2. **Security Note on TCP Port `20001` (Still unfixed 2 years after CCS 2024 / Black Hat 2024):**
   - Two years ago (CCS 2024 / Black Hat 2024), security researchers disclosed that Deco units expose an internal SSH service on TCP port `20001` that tunnels to `127.0.0.1:20002` (`tmpsvr`).
   - Despite having **two years (2024 → June 2026)** to harden `tmpsvr`, firmware `1.5.0` only bumped the SSH RSA key size from 512-bit to 2048-bit. It left password authentication (`SHA1(owner_email)` + your TP-Link account password) and the underlying `root` handlers untouched: opcode `0xC456` (`inner_file_push`) still writes arbitrary files to any path as `root` without an allowlist, `0x00F0` reads any file as `root`, and even `0xC505` (`tty2tcp`) remains unvalidated.
   - We have sent a full report to `security@tp-link.com`. Because two years have already passed since the original 2024 disclosure without `tmpsvr` being locked down, **make sure your TP-Link ID uses a strong, unique password** and never expose port `20001` to the WAN or untrusted VLANs.

Full technical details, VLAN implementation, and firmware analysis:
- IoT VLAN Tagging & Native Web-UI: https://github.com/CPlusPlus17/deco-iot-vlan
- Security Advisory (`0xC456` Root File Write): https://github.com/CPlusPlus17/deco-filepush-disclosure

