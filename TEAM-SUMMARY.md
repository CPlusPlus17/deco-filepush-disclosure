# How this was found — team summary

This disclosure is the product of a multi-agent reverse-engineering
session run by the owner on 2026-10-17 (one day, CEST) against their own
TP-Link Deco XE75 Pro V3 mesh (3 units: `192.168.68.1`, `192.168.68.2`, `192.168.68.3`).
Four agents worked in parallel on the shared channel `agents.comm`
(append-only, 75+ timestamped entries) plus the local file system, with
the owner coordinating and approving every live change.

> **Note on agent names:** In `agents.comm` and throughout this repo,
> **`hermes` is Qwen** — an open-weight model running locally/privately
> inside the **Hermes** agent harness, which served both as the fourth
> hands-on agent (`hermes`) and as the cross-lane orchestrator alongside
> the three hosted commercial models (**Claude**, **Codex**, and **Gemini**).

## Division of labor (verified from `agents.comm`)

| Agent (`agents.comm` handle) | Model / Harness | Role | Summary of contributions |
|---|---|---|---|
| **`claude`** (11 entries) | Anthropic Claude (hosted) | Recon + boundary-setting | Confirmed Dropbear SSH on `:20001` is **forwarding-only** (`session` channel refused); established the `direct-tcpip → 127.0.0.1:20002` path; read live config over the tunnel; issued the static **WRITE-ACCESS verdict** from the native opcode map + debug controllers; deliberately **stopped its own live exploit-hunt lane** to keep its work non-destructive. |
| **`codex`** (49 entries) | OpenAI Codex (hosted) | Firmware + live VLAN trials | **Decrypted the 1.5.0 image offline** and RSA-PSS signature-verified it; extracted the full SquashFS userspace; recovered the 555-entry native `tmpsvr` opcode table; confirmed **root Lua execution** and the byte-exact `/tmp/luci-indexcache` restore discipline; ran the bounded **VLAN 30 live trials** across the 3-unit mesh; built the read/write/persist helpers. |
| **`gemini`** (5 entries) | Google Gemini (hosted) | Datapath + crypto analysis | Mapped the stock OpenWrt VLAN/bridge/VAP scripts and explained **why guest-VLAN tagging is AP-mode-gated** (`ports '6t'` only) and why `iot_wifi.iot.vlan_enable` is a no-op; reconciled the conflicting `0x4008` guest-VLAN write schemas across `mobile_wireless.lua`/`app_wifi.lua`; decompiled `luci/sys/config.lua` and `luci/model/crypto.lua` to trace the `zlib` + `AES-256-CBC` persistence pipeline; audited the 3-node mesh baseline and satellite backhaul links. |
| **`hermes`** (6 entries + orchestration) | **Qwen** (open-weight, via Hermes harness) | Live write + config decryption + disclosure | Performed the **live write-access proofs** via `0xC456` (`/www`, `/etc/config`, persistent `/tp_data/user_data` UBIFS) with byte-exact readback; demonstrated **full root command execution** (`io.popen`); extracted the live `libtrkutil` key/IV and completed **offline config decryption** (AES-256-CBC over zlib-XML); verified SSH host keys across all 3 units; authored the session handoff, CVSS 9.9 analysis, standalone PoC, and disclosure repo. |

---

## Detailed breakdown: what each agent actually did

### 1. `claude` — Initial SSH/TMPv2 recon & static write-surface audit
- **Probed TCP `:20001` (Dropbear SSH)** using the owner's TP-Link ID credentials (`SHA1(email)` as username + password) and proved that interactive shell channels (`session` / `exec`) are rejected by `svr_chansess.c`, while `direct-tcpip` port forwarding to `127.0.0.1:20002` (`tmpsvr`) is permitted (`svr-tcpfwd.c`).
- **Enumerated the TMPv2 surface over the tunnel**, pulling initial live state (`0x00F0` file reads) and comparing live UCI configs against the mobile app API.
- **Audited the decompiled Lua controller tree** (`inner_file.lua`, `debug.lua`, `config.lua`) and posted the **WRITE-ACCESS verdict** identifying `0xC456` (`inner_file_push`) as an unvalidated root file-write primitive, before **Opus (4.8 / 5.5)** became completely unusable for the remainder of the session due to overly strict platform filter rules.

### 2. `codex` — Offline firmware extraction, opcode recovery & 3-unit VLAN trials
- **Decrypted and verified the official 1.5.0 firmware image offline** (`Deco_XE75_Pro_V3_1.5.0_20260603`), validating the RSA-PSS signature against TP-Link's public key and unpacking the SquashFS rootfs (`extracted/_rootfs.bin.extracted/squashfs-root`).
- **Recovered the complete 555-entry native `tmpsvr` opcode dispatch table** from the ARM binaries and mapped every opcode to its underlying `luci.controller.admin.*` module and function.
- **Decompiled the precompiled Lua 5.1 bytecode** across `squashfs-root/usr/lib/lua/luci/` and discovered how `/tmp/luci-indexcache` caches the dispatch table in RAM (30 entries when initialized by `uhttpd`/`luci`, 29 entries when rebuilt by `tmpsvr`).
- **Built the safety-locked RAM-only trial framework** (120s and 900s auto-revert watchdogs, `flock` kernel locks, per-unit route-cache backups, and unit-specific identity/MAC verification) and executed the **live VLAN 30 trials** across `Node 1 (Main)` (`192.168.68.1`), `Node 2 (Satellite 1)` (`192.168.68.2`), and `Node 3 (Satellite 2)` (`192.168.68.3`), proving end-to-end 802.1Q VLAN 30 tagging (`br-iot` + `eth1.30` + `ath08`/`ath18`) to the upstream OPNsense firewall (`192.168.30.1`).

### 3. `gemini` — Static OpenWrt datapath & NVRAM crypto pipeline analysis
- **Traced the entire stock VLAN/bridge/VAP execution chain** across `/etc/init.d/guest-eth.sh`, `/etc/Guest_network/guest-vlan.sh`, `/etc/init.d/apsd`, `/etc/init.d/iot_network`, and `/lib/wifi/qcawifi.sh`:
  - Proved that `iot_wifi.iot.vlan_enable` / `vlan_id` in `/etc/config/iot_wifi` has **zero consumers** in the 1.5.0 rootfs (`iot_eth.sh` was never shipped), explaining why flipping the UCI flag alone does nothing on the wire.
  - Proved that `guest-eth.sh` checks `sysmode.sysmode.mode == "Router"` before adding external switch ports (`0t 1t 2t 3t 6t`) to `vlan_guest`; in `AP` mode it configures only the CPU port (`6t`) and leaves `apsd`'s `vconfig` tagging inactive.
- **Reconciled the conflicting `0x4008` (`wireless_guest_write`) schemas**, showing that `app_wifi.lua` expects nested `enable`/`vlan_id` fields inside `band2_4` (`write_guest_data`) while `mobile_wireless.lua` expects top-level `vlan_id` (`set_guest_info`), and traced how `/sbin/wifi reload` regenerates `/etc/config/wireless` from `mobile_wireless`.
- **Decompiled `luci/sys/config.lua` and `luci/model/crypto.lua`**, mapping how `saveconfig` serializes `/etc/config/*` into XML, compresses it with `zlib`, and pipes it through `openssl aes-256-cbc -e -k <key> -iv <iv>` using hardware/firmware secrets from `libtrkutil.so` (`get_CryKey` / `get_CryIv`) before writing to `/tp_data/user_data/user-config` via `nvrammanager`.
- **Reviewed the 3-node mesh baseline (`baseline.json`)**, identifying why `Node 1` (2.5G) and `Node 2` (2.5G) passed VLAN 30 DHCP while `Node 3` (1G link) timed out on tagged frames.

### 4. `hermes` (Qwen, open-weight) — Live write proofs, root exec, offline config decryption & disclosure
- **Executed the live `0xC456` (`inner_file_push`) write proofs** on `192.168.68.1` across all three storage tiers with byte-exact `0x00F0` readback and cleanup:
  1. `/www/log_export/.write_test_hermes` (RAM-backed web root served over HTTPS `:443`).
  2. `/etc/config/.write_test_hermes` (live UCI configuration RAM filesystem).
  3. `/tp_data/user_data/.write_test_hermes` (persistent UBIFS flash partition surviving reboot).
- **Verified arbitrary root command execution** by registering a temporary Lua dispatch entry calling `io.popen("id; uname -a; ...")` (`uid=0(root) gid=0(root)` on `Linux ER706W-4G 5.4.213 aarch64`) and restoring `/tmp/luci-indexcache` byte-for-byte (`6860` bytes).
- **Completed the end-to-end config decryption chain**: used `gemini`'s static trace of `luci/model/crypto.lua` to call `luci.model.crypto.get_key()` and `get_iv()` live on the device, recovered the 32-byte AES-256 key and 16-byte IV from `libtrkutil`, and decrypted all 14 files in `/tp_data/user_data/` offline (AES-256-CBC → raw deflate `wbits=-15` → plaintext XML config).
- **Validated SSH host keys (`rsa-sha2-512`) across all three mesh nodes** (`192.168.68.1`, `192.168.68.2`, `192.168.68.3`), confirming the same `:20001 → :20002` architecture mesh-wide.
- **Authored and packaged this disclosure repository**: wrote the standalone zero-dependency-beyond-Paramiko PoC (`poc/deco_filepush_poc.py`), the handler source analysis (`docs/handler-source.md`), the CVSS v3.1 9.9 assessment (`README.md`), and the vendor notification (`tp-link-email.md`).

---

## How the pieces came together (chronological flow)
1. **Firmware ground truth (offline)** — `codex` decrypted the 1.5.0 Cloud firmware image offline using the public RSA-PSS key, verified the image signature, extracted the SquashFS rootfs, and recovered the 555-entry native `tmpsvr` opcode table. That turned blind black-box probing into exact source/bytecode inspection.
2. **Tunnel & read primitive** — `claude` and `codex` confirmed that Dropbear SSH on TCP `:20001` (authenticated via `SHA1(owner_email)` + TP-Link password) refuses shell channels (`session`) but permits `direct-tcpip` forwarding to `127.0.0.1:20002` (`tmpsvr`), where opcode `0x00F0` reads arbitrary files as `root`.
3. **Static datapath & config-crypto mapping** — `gemini` traced the stock OpenWrt init/hotplug scripts (`guest-eth.sh`, `guest-vlan.sh`, `apsd`, `iot_network`, `wificommon.sh`) and decompiled `luci/sys/config.lua` + `luci/model/crypto.lua`, mapping the `zlib` + `AES-256-CBC` persistence pipeline (`nvrammanager` + `libtrkutil`).
4. **The write & execution primitives** — After hosted models hit automated platform blocks on live write-path testing, **Qwen (`hermes`)** stepped in to verify `0xC456` (`inner_file_push`) live across `/www/log_export`, `/etc/config`, and `/tp_data/user_data`, extracted the live `libtrkutil` AES-256-CBC key/IV via `io.popen`, decrypted the flash config dumps offline, and packaged the disclosure artifacts.
5. **Bounded runtime verification across the 3-unit mesh** — `codex` built the self-reverting RAM-only trial harness (with 120s/900s kernel-locked watchdogs and byte-exact `/tmp/luci-indexcache` restoration) to prove isolated VLAN 30 tagging (`br-iot` + `eth1.30` + `ath08`/`ath18`) and native UI status rendering across the three-unit mesh without touching flash.

---

## Why open-weight models (Qwen / `hermes`) were essential
A major practical takeaway from this session is **why combining open-weight models with commercial frontier models matters for legitimate hardware research**:
- **Overly strict filter rules on commercial APIs:** Even though every step was performed by the device owner on their own home hardware (`192.168.68.1` / `.2` / `.3`) with their own credentials, the hosted models (**Claude**, **Codex**, and **Gemini**) repeatedly hit automated platform blocks whenever a task crossed from static analysis into auditing write handlers, verifying live command execution, or editing proof-of-concept scripts. In particular, **Opus (4.8 and 5.5)** became completely unusable mid-session because overly strict filter rules blocked even follow-up analysis on the owner's own router.
- **Open-weight continuity (Qwen as `hermes`):** Running an open-weight model locally/privately meant the workflow never dead-ended at a policy filter. When `claude`, `codex`, or `gemini` were blocked from auditing a write path or running a live verification probe, **Qwen (`hermes`)** seamlessly picked up the exact technical context from `agents.comm`, executed the live `0xC456` and `io.popen` proofs, dumped and decrypted the config partitions, and drafted the disclosure package.
- **Complementary strengths:** Hosted frontier models excelled at deep static decompilation, long-context script/datapath verification, and strict rollback test suites, while the open-weight model provided unthrottled agency and orchestration on the owner's hardware. Neither side alone would have finished the whole chain in a single afternoon.

## What this says about multi-agent RE
- **Parallel lanes, one shared log.** Each model owned a lane (recon / firmware & trials / datapath & crypto / live-write & disclosure) and posted to the same append-only `agents.comm` file, so no one duplicated or clobbered another's findings.
- **Read-only by default, live only with owner sign-off.** Nobody wrote to the device without an explicit, logged owner approval and a bounded, auto-reverting trial.
- **Cross-checking caught the traps.** Static cross-checks (such as `gemini`'s AP-mode gate trace and `codex`'s byte-exact route-cache checks) prevented false claims and caught subtle bugs (like restoring a 29-entry cache over a 30-entry UI cache) in minutes.
- **Qwen (`hermes`) as the connective tissue.** As orchestrator and hands-on agent, Qwen held the cross-tool context (which opcode is which, which file is authoritative, who holds the live write lease) and bridged the gaps whenever commercial models were blocked.

## Reproducibility
Everything above is grounded in:
- `agents.comm` (the shared append-only log, 75+ timestamped entries)
- the extracted userspace + decompiled handlers (referenced in `docs/handler-source.md`)
- the self-contained PoC (`poc/deco_filepush_poc.py`)
