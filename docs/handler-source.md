# The vulnerable handler (decompiled)

Source: extracted firmware 1.5.0 Build 20260603 Rel.15804 userspace,
module `luci.controller.admin.mobile_app.iot_device`, decompiled from the
release Lua bytecode (original instruction stream preserved; integer tags
normalized for display). Function is the callback for `inner_file_push`
(opcode `0xC456` in the native `tmpsvr` opcode table).

```lua
-- inner_file_push(params)  -- runs as UID 0 inside tmpsvr
local resp = { success = "1" }
if params == nil then return resp end

local f = params.file
if f ~= nil then
  local content = params.content
  if content ~= nil then
    local fh = io.open(f, "w")        -- arbitrary path, mode "w"
    if fh then
      fh:write(content)               -- verbatim, no size cap
      fh:close()
    end
  else
    -- batch form: params.file_list = { {file=..., content=...}, ... }
    for _, item in ipairs(params.file_list) do
      local fh = io.open(item.file, "w")
      if fh then fh:write(item.content) fh:close() end
    end
  end
end
return resp
```

Observations (static + live):
- `resp.success` is set to `"1"` unconditionally — the handler reports
  success even when `io.open` fails. The real proof is byte-exact readback
  (opcode 0xF0) plus HTTPS serving from `/www`.
- No path normalization, no allowlist, no `chroot`, no `setuid` drop.
- The same table registers `inner_file_pull` (opcode sibling) and the
  root file read used as our readback primitive (opcode `0xF0`).

## Related: tty2tcp (opcode 0xc505)

`luci.controller.admin.mobile_app.debug` `tty2tcp/start` reads
`params.ipaddr` / `params.port`, checks only truthiness, then builds a
command string passed to `luci.sys.fork_exec`, which execs `/bin/sh -c`
on the concatenated string. No quoting, no type check. Same class as the
CCS 2024 reverse-shell vector; present and unvalidated on 1.5.0 (static).

## Native opcode table

555 entries recovered from the release `tmpsvr` binary (offline).
Relevant rows:

| opcode | controller | operation |
|---|---|---|
| 0x00F0 | diagnostic reader | root file read |
| 0xC456 | iot_device.inner_file_push | root file write (this report) |
| 0xC505 | mobile_app.debug.tty2tcp/start | shell-string build (related) |

## Hostkey status (live, 2026-10-17, all 3 mesh units)

- ssh-rsa 2048-bit, **identical factory key** on all three units:
  `SHA256:9feb3ac47a4a08ce7fe8a104c8b024cdfb438315ec9f6d6eec2980537c932a36`
- ecdsa-sha2-nistp521 per-unit keys.
- => the CCS'24 512-bit RSA crack path is closed on this firmware; the
  password-auth path is the live entry.
