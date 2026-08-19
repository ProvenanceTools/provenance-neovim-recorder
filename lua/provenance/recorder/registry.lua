--- registry.lua — the root -> session map (Plan:
--- 2026-07-20-nested-manifest-discovery). Replaces the single module-level
--- `state`/`controller` pair recorder/init.lua used to own with a table
--- keyed by assignment root, so more than one assignment can record at the
--- same instant, each with its own live recording_controller session.
---
--- Deliberately dumb: this module does not know about discovery, buffers,
--- or autocmds -- it only tracks "which roots currently have a live
--- session" and starts/stops sessions via an injected start_recording seam
--- (production: recording_controller.start; tests: a spy, mirroring
--- init_controller_spec.lua's existing style).
---
--- It also owns the VERIFIED-ROOT CACHE (`reg.load_and_verify`). Activation
--- resolution runs on BufEnter/BufReadPost/BufNewFile, i.e. on every buffer
--- switch, and each resolution used to re-run a pure-Lua ed25519 verification
--- costing ~12 ms on the main loop -- a visible UI hitch inside any activated
--- workspace. The registry is the natural home for that cache: it is already
--- the per-editor-instance "what do we know about this root" map.
local activation = require("provenance.recorder.activation")

local M = {}

--- @param opts table { start_recording: function(start_opts) -> controller }
--- @return table registry
function M.new(opts)
  opts = opts or {}
  local start_recording = opts.start_recording

  -- root -> { manifest, controller, provenance_dir }
  local sessions = {}

  -- Verified-root cache: root -> { digest, pubkey_override, result }.
  --
  -- Keyed on the root directory PLUS the manifest's content digest PLUS the
  -- caller's public-key OVERRIDE, so a cached verdict cannot outlive any of the
  -- three inputs that produced it.
  --
  -- The override rather than the resolved key, because since Manifest 2.0 there
  -- is no single resolved key to name up front: activation.evaluate picks the
  -- anchor from the manifest's own `format_version` (2.0 -> root key, 1.x ->
  -- grandfathered legacy course key). Keying on the digest covers that
  -- completely -- the bytes determine the version, the version determines the
  -- anchor -- so a manifest that switches format version between reads has a
  -- different digest and therefore cannot hit a verdict computed under the other
  -- anchor. A `nil` override is a distinct key from any explicit one.
  --
  -- The manifest identity is a sha256 of its bytes, deliberately NOT
  -- mtime+size. This cache short-circuits a security gate, so its key has to be
  -- as hard to forge as the gate itself: mtime and size are both
  -- attacker-controlled (`touch -t`, pad to length), which would let a
  -- "verified" verdict survive the manifest being swapped for a forgery -- the
  -- cache would become the attack. A content digest cannot be spoofed that way,
  -- and it is effectively free: the bytes are read either way, and hashing a few
  -- hundred of them is microseconds against a ~12 ms verification.
  --
  -- Unbounded by root, which is fine: entries are tiny and bounded by the
  -- number of distinct manifest-bearing directories one editor session visits.
  local verified = {}

  local reg = {}

  --- Cached front door to activation.load_and_verify -- same signature, same
  --- return shapes, same semantics, minus the repeated ed25519 cost. Drop-in
  --- for discovery.resolve_from_dir's `load_and_verify` seam.
  ---
  --- Verification still happens on first sight of a root and again after ANY
  --- change to the manifest file's bytes; only a byte-identical re-read is
  --- served from the cache.
  --- @param workspace_dir string
  --- @param pubkey_hex string|nil
  --- @return table  see activation.load_and_verify
  function reg.load_and_verify(workspace_dir, pubkey_hex)
    local read = activation.read_manifest(workspace_dir)
    if read.status ~= "found" then
      -- No bytes means no identity to key on -- and nothing expensive ran.
      return read
    end

    local digest_ok, digest = pcall(vim.fn.sha256, read.text)
    local hit = verified[workspace_dir]
    if digest_ok and hit and hit.digest == digest and hit.pubkey_override == pubkey_hex then
      return hit.result
    end

    local eval_ok, result = pcall(activation.evaluate, read.text, pubkey_hex)
    if not eval_ok then
      return { status = "inactive", reason = "manifest_read_error" }
    end

    -- Only cache when the digest is trustworthy; otherwise re-verify each time.
    if digest_ok then
      verified[workspace_dir] = { digest = digest, pubkey_override = pubkey_hex, result = result }
    end
    return result
  end

  --- Drop every cached verification verdict, forcing the next resolve of each
  --- root to re-verify. Nothing in the plugin needs this today; it exists so no
  --- caller has to reach into the cache table to get a clean slate.
  function reg.clear_verification_cache()
    verified = {}
  end

  --- Aggregate, no-arg (deliberately named to match RecorderState.is_active()
  --- so status.attach(reg) works unmodified): true iff at least one session
  --- is currently registered.
  function reg.is_active()
    return next(sessions) ~= nil
  end

  --- @param root string
  --- @return boolean
  function reg.has_session(root)
    return sessions[root] ~= nil
  end

  --- @param root string
  --- @return table|nil { manifest, controller, provenance_dir }
  function reg.get(root)
    return sessions[root]
  end

  --- @return table[]  { root, manifest, controller }, sorted by root ascending
  function reg.list()
    local out = {}
    for root, entry in pairs(sessions) do
      out[#out + 1] = { root = root, manifest = entry.manifest, controller = entry.controller }
    end
    table.sort(out, function(a, b)
      return a.root < b.root
    end)
    return out
  end

  --- Idempotent: if `root` already has a live session, returns it unchanged
  --- (does not call start_recording again). Otherwise starts one.
  --- @param root string
  --- @param manifest table
  --- @param extra_opts table|nil  merged into the start_recording opts,
  ---   winning on any key collision with the derived workspace/provenance_dir/manifest
  --- @return table|nil controller, boolean started, string|nil err
  function reg.ensure_session(root, manifest, extra_opts)
    local existing = sessions[root]
    if existing then
      return existing.controller, false
    end

    local provenance_dir = root .. "/.provenance"
    local start_opts = vim.tbl_extend("force", {
      workspace = root,
      provenance_dir = provenance_dir,
      manifest = manifest,
    }, extra_opts or {})

    local ok, controller = pcall(start_recording, start_opts)
    if not ok then
      return nil, false, controller
    end

    sessions[root] = { manifest = manifest, controller = controller, provenance_dir = provenance_dir }
    return controller, true
  end

  --- Stop every registered session (pcall-guarded per entry, so one
  --- failing stop() never blocks the others) and clear the registry.
  --- Order-independent by construction (Lua's pairs() order is
  --- unspecified) -- this is deliberate: see paste_intercept.lua's
  --- ref-counted-singleton fix for why teardown order must never matter.
  --- @param reason string|nil
  function reg.stop_all(reason)
    for root, entry in pairs(sessions) do
      pcall(entry.controller.stop, reason)
      sessions[root] = nil
    end
  end

  return reg
end

return M
