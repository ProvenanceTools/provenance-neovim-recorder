# Core Crypto & Bundle Implementation Plan (Plan 2 of the provnvim series)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Extend `lua/provenance/core/` with the crypto + bundle layer — vendored pure-Lua ed25519 (sign/verify) and XChaCha20-Poly1305, HKDF-SHA256, manifest parse+verify (the activation gate), bundle manifest shape+signing, per-session ed25519 keypair + encrypted private key, and signed checkpoints — each proven against `log-core` via the deterministic golden vectors the export tool emits.

**Architecture:** Still pure-Lua, **zero native dependencies** (the keystone, design.md §3). SHA-256 is `vim.fn.sha256`; ed25519 and XChaCha20-Poly1305 are **vendored, pinned pure-Lua implementations** under `lua/provenance/vendor/`; HKDF-SHA256 is a small deterministic construction over `vim.fn.sha256`. Every primitive is proven by a **committed golden vector** the monorepo already emits with fixed seeds/salt/nonce — so parity is a red/green test, never a judgment call.

**Tech Stack:** Lua (LuaJIT), `vim.fn.sha256`, vendored pure-Lua ed25519 + XChaCha20-Poly1305 (see Task 0), plenary. Builds on Plan 1's `sha256`, `json`, `envelope`.

## Global Constraints

(Inherits Plan 1's Global Constraints.) Additional:

- **Pure-Lua, zero native deps is a keystone, not an implementation detail** (design.md §3, CLAUDE.md). No FFI-to-libsodium, no sidecar binary, no compiled helper. If the pure-Lua path proves genuinely unworkable for a primitive (e.g. no pure-Lua ed25519 reproduces the vector on LuaJIT), **STOP and ask** — do not swap in a native dependency to make it easier.
- **Do not write crypto from scratch.** Vendor a known, readable existing pure-Lua implementation and pin it (design.md §12 open q1). The two small exceptions permitted here are **HKDF-SHA256 and HMAC-SHA256**, which are standard deterministic KDF/MAC constructions (RFC 5869 / RFC 2104) built over the approved `vim.fn.sha256` builtin — both are pinned byte-for-byte by the `hkdf_key_hex` vector, so correctness is proven, not assumed.
- **Vendoring is a licensing gate (CLAUDE.md).** In the *same commit* that vendors a component, create/update `THIRD-PARTY-NOTICES.txt` at the repo root with the upstream project, vendored path, version/commit, and full license + copyright text. Prefer MIT/BSD/Apache-2.0/CC0/Unlicense; copyleft needs review first. **No `THIRD-PARTY-NOTICES.txt` entry → do not vendor.**
- **ed25519 is RFC 8032 pure-variant, deterministic.** Same key + message → identical 64-byte (128-hex) signature. This is the cross-language guarantee the `ed25519.json` vector relies on (`priv=0x07×32`, `msg='{"a":1}'` → the pinned `sig_hex`).
- **Signed-payload cheat sheet (all → `json.canonicalize` → UTF-8 → ed25519):**
  - **Manifest verify:** `canonicalize({assignment_id, semester, issued_at, files_under_review})` — the `sig` field is **excluded**.
  - **Bundle manifest sign:** `canonicalize(entire manifest object)`; **persist the exact canonical string** to `manifest.json` (do not re-serialize).
  - **Checkpoint sign:** `canonicalize({hash, seq})` (JCS sorts to `hash` then `seq`).
- **Session privkey encryption (PRD §4.6):** XChaCha20-Poly1305; key = HKDF-SHA256(IKM = hex-decoded manifest `sig`, salt = 16 bytes, info = ASCII `"provenance-session-key-v1"`, len 32); nonce = 24 bytes; 16-byte Poly1305 tag appended to ciphertext; `algorithm = "xchacha20-poly1305-hkdf-sha256-v1"`. The analyzer (`@noble/ciphers`) must decrypt what this produces — the `session-key.json` vector (fixed salt `0x11×16`, nonce `0x22×24`) pins `hkdf_key_hex` and `ciphertext_hex` exactly.
- **Golden vectors are the source of truth** — all committed in Plan 1 Task 9 (`tests/conformance/fixtures/`). Never invent a crypto vector; regenerate via `make vectors`.

### File structure (created across this plan)

```
lua/provenance/vendor/
  ed25519.lua        -- vendored pure-Lua ed25519 (Task 1)
  xchacha20poly1305.lua -- vendored pure-Lua AEAD (Task 4)
lua/provenance/core/
  ed25519.lua        -- thin wrapper/normalizer over the vendored impl (Task 1)
  hkdf.lua           -- HMAC-SHA256 + HKDF-SHA256 over vim.fn.sha256 (Task 4)
  manifest.lua       -- parse + verify (activation gate) (Task 2)
  bundle.lua         -- BundleManifest model, shape validation, sign (Task 3)
  session_keys.lua   -- keypair + encrypt/decrypt session privkey (Task 4)
  checkpoint.lua     -- sign/verify seq→hash checkpoints (Task 5)
THIRD-PARTY-NOTICES.txt  -- created/updated in Tasks 1 and 4
```

---

### Task 0 (spike, no commit): choose the ed25519 and AEAD implementations to vendor

**This is the keystone-resolution step (design.md §12 open q1). Do it before Task 1.**

- [ ] **XChaCha20-Poly1305 + Poly1305 + ChaCha20:** the primary candidate is **`philanc/plc` (Pure Lua Crypto), MIT** — pure Lua, no C/FFI, explicitly provides ChaCha20, XChaCha20 (24-byte nonce), Poly1305, and RFC 7539/8439 authenticated encryption. Confirm at spike time that its AEAD framing (16-byte tag appended, empty AAD) reproduces `session-key.json`'s `ciphertext_hex`. Fallback: `BernhardZat/pure-lua-5.1-crypto` (MIT) has ChaCha20/XChaCha20 but lacks Poly1305 — not sufficient alone.
- [ ] **ed25519 (the genuine risk):** the widely-known Lua crypto libs with ed25519 (`luazen`, `luatweetnacl`, `luamonocypher`, `lua-openssl`) are **native C extensions** and are therefore **disqualified by the zero-native-deps keystone**. `plc` and `BernhardZat` provide only X25519/ec25519 key exchange, **not** ed25519 signatures. The realistic pure-Lua candidates are Roblox/Luau-origin ports, e.g. **`daily3014/cryptography` (Luau, MIT, has `EdDSA.Sign`/`Verify`)** or a vetted standalone `ed25519.lua`. These target Luau and may use `buffer`/`bit32`; a LuaJIT port (replace `buffer` with byte strings, `bit32` with the LuaJIT `bit` library) is expected work.
- [ ] **Decision rule:** in Task 1 you will vendor the chosen ed25519 and assert it reproduces `ed25519.json`'s `sig_hex` **on LuaJIT under headless Neovim**. **If no readable pure-Lua ed25519 reproduces the vector on LuaJIT, STOP and ask** — that is the keystone becoming unworkable, a decision owned above this plan (CLAUDE.md). Record the final choice + license in `THIRD-PARTY-NOTICES.txt` in the vendoring commit.

*(No commit — this task produces the two named choices and confirms the AEAD vector reproduces in a throwaway scratch script.)*

---

### Task 1: Vendor ed25519 + wrapper (sign/verify) — pinned to `ed25519.json`

**Files:**
- Create: `lua/provenance/vendor/ed25519.lua` (vendored, LuaJIT-adapted)
- Create: `lua/provenance/core/ed25519.lua` (thin wrapper: hex helpers + `sign`/`verify`/`public_key_of`/`generate_keypair`)
- Create/Modify: `THIRD-PARTY-NOTICES.txt` (upstream, path, commit, full license + copyright)
- Test: `tests/core/ed25519_spec.lua`
- Modify: `tests/conformance/conformance_spec.lua` — add the `ed25519.json` assertion.

**Interfaces (`core/ed25519`):**
- `generate_keypair(): priv32, pub_hex` — 32-byte private key string, 64-hex public key.
- `sign(message: string, priv32: string): string` — 64-byte signature (raw string).
- `verify(sig: string, message: string, pub: string): boolean` — never throws; false on malformed input.
- `public_key_of(priv32: string): string` — 32-byte raw pubkey.
- `to_hex(bytes)` / `from_hex(hex)` helpers (lowercase).

**Test intent:**
- Round-trip: generate → sign → verify true; tampered message → false; wrong pubkey → false; malformed input → false (no throw).
- **Cross-language vector (`ed25519.json`):** `to_hex(sign(fixture.msg_utf8, from_hex(fixture.priv_hex))) == fixture.sig_hex`, and `to_hex(public_key_of(from_hex(fixture.priv_hex))) == fixture.pub_hex`, and `verify(from_hex(fixture.sig_hex), fixture.msg_utf8, from_hex(fixture.pub_hex)) == true`. This proves the vendored ed25519 ≡ `@noble/ed25519`.

**Gate:** `make test` green including the `ed25519.json` conformance assertion. **If the signature does not match `sig_hex`, STOP — do not weaken the assertion; the pure-Lua ed25519 is wrong or non-deterministic.**

**Steps:** standard TDD (write round-trip + cross-language vector test → fails → vendor + adapt impl + write wrapper + THIRD-PARTY-NOTICES entry → passes → commit). Commit `feat(core): vendor pure-Lua ed25519 + wrapper matching noble via ed25519.json` **with** the `THIRD-PARTY-NOTICES.txt` change in the same commit (explicit pathspec).

---

### Task 2: Manifest parse + verify (the activation gate primitive)

**Files:**
- Create: `lua/provenance/core/manifest.lua`
- Test: `tests/core/manifest_spec.lua`
- Modify: `tests/conformance/conformance_spec.lua` — add the `manifest.json` assertion.

**Interfaces:**
- Consumes: `json`, `ed25519`.
- Produces:
  - `manifest.parse(text: string): ok(Manifest) | err({reason})` — validates JSON + field shapes; `assignment_id`/`semester`/`issued_at` non-empty strings; `files_under_review` array of strings; `sig` matches `^[0-9a-f]{128}$`. (Mirrors log-core `parseManifest`.) `Manifest = {assignment_id, semester, issued_at, files_under_review, sig}`.
  - `manifest.verify(m: Manifest, course_pubkey_hex: string): boolean` — builds `json.canonicalize({assignment_id, semester, issued_at, files_under_review})` (the `sig` field **excluded**), UTF-8, ed25519-verify against the 64-hex pubkey. Returns false on any malformed input (never throws).

**Test intent:**
- **Cross-language (`manifest.json` fixture):** `manifest.verify(parse(fixture.manifest).value, fixture.course_pubkey_hex) == true`; and false if any of `assignment_id`/`semester`/`issued_at`/`files_under_review`/`sig` is mutated. Note the `files_under_review` array must canonicalize as a `json.array` — the parser tags it.
- `parse` rejects: non-object, missing fields, non-128-hex sig, non-string array element.

**Gate/Steps:** TDD → commit `feat(core): manifest parse + ed25519 verify (activation gate)`.

---

### Task 3: Bundle manifest — model, shape validation, signing

**Files:**
- Create: `lua/provenance/core/bundle.lua`
- Test: `tests/core/bundle_spec.lua`
- Modify: `tests/conformance/conformance_spec.lua` — add the `bundle-manifest.json` and `golden-bundle.json` assertions.

**Interfaces:**
- Consumes: `json`, `ed25519`.
- Produces:
  - A builder that assembles the on-the-wire `BundleManifest` (all snake_case keys): `format_version` (`"1.0"|"1.1"`), `assignment_id`, `semester`, `extension_hash`, `sessions` = array of `{session_id, prev_session_id, slog_sha256, meta_sha256}` (nulls as `json.NULL`), `submission_files` = array of `{path, status, sha256}` (`sha256 = json.NULL` when `missing`), omitted entirely for `1.0`.
  - `bundle.to_canonical(manifest_value): string` — `json.canonicalize(manifest_value)`; this is exactly what gets signed and written to `manifest.json`.
  - `bundle.validate_shape(value): ok(manifest) | err({kind, field?})` — mirrors `validateBundleManifestShape`: accepts 1.0 without `submission_files`; 1.1 requires it; `present`→64-hex sha, `missing`→null sha; `HEX_64` for `extension_hash`/`slog_sha256`/`meta_sha256`.
  - `bundle.sign(manifest_value, signing_priv32): {canonical_json, signature_hex}` — `canonical_json = json.canonicalize(manifest_value)`; `signature_hex = ed25519.to_hex(ed25519.sign(canonical_json, signing_priv32))`. Caller writes `canonical_json`→`manifest.json`, `signature_hex`→`manifest.sig`.
  - `bundle.verify_sig(canonical_json, sig_hex, pubkey_hex): boolean`.

**Test intent:**
- **`bundle-manifest.json` fixture (the byte-for-byte JCS pin):** building the manifest from the fixture's `manifest` object and `bundle.to_canonical` must equal `fixture.canonical_json` **exactly** (this pins the Lua JCS output of the full nested bundle shape, including `null` and nested-array key ordering). Then `bundle.verify_sig(fixture.canonical_json, fixture.signature_hex, fixture.session_pubkey_hex) == true`, and signing the same manifest with the fixture session privkey reproduces `signature_hex`.
- **`golden-bundle.json` fixture:** `bundle.validate_shape(fixture.manifest)` is `ok` (a real sealed 1.0 manifest validates).
- `validate_shape` rejects: wrong version, missing `extension_hash`, non-64-hex sha, 1.1 missing `submission_files`, `missing` status with non-null sha.

**Gate/Steps:** TDD → commit `feat(core): bundle manifest model, shape validation, ed25519 signing`.

---

### Task 4: Vendor XChaCha20-Poly1305 + HKDF + session keypair/encrypted privkey

**Files:**
- Create: `lua/provenance/vendor/xchacha20poly1305.lua` (vendored, LuaJIT-adapted)
- Create: `lua/provenance/core/hkdf.lua` (HMAC-SHA256 + HKDF-SHA256 over `vim.fn.sha256`)
- Create: `lua/provenance/core/session_keys.lua`
- Modify: `THIRD-PARTY-NOTICES.txt` (add the AEAD library)
- Test: `tests/core/hkdf_spec.lua`, `tests/core/session_keys_spec.lua`
- Modify: `tests/conformance/conformance_spec.lua` — add the `session-key.json` assertions.

**Interfaces:**
- `hkdf.hmac_sha256(key: string, msg: string): string` (raw 32-byte) and `hkdf.derive(ikm, salt, info, len): string`.
- `xchacha20poly1305.encrypt(key32, nonce24, plaintext, aad?): string` (ciphertext‖16-byte tag) and `.decrypt(key32, nonce24, ct_with_tag, aad?): string|nil` (nil on tag failure).
- `session_keys.generate(): {public_key_hex, private_key(32B raw)}` (ed25519 keypair).
- `session_keys.encrypt_privkey(priv32, manifest_sig_hex, salt?, nonce?): EncryptedPrivkey` — salt/nonce injectable for deterministic tests; defaults random (16/24 bytes). `EncryptedPrivkey = {algorithm="xchacha20-poly1305-hkdf-sha256-v1", nonce(hex), ciphertext(hex), salt(hex), info="provenance-session-key-v1"}`.
- `session_keys.decrypt_privkey(enc: EncryptedPrivkey, manifest_sig_hex): string|nil` — nil on auth-tag failure (wrong manifest sig).

**Test intent:**
- **HKDF vector:** `hkdf.derive(from_hex(fixture.manifest_sig), from_hex(fixture.salt_hex), "provenance-session-key-v1", 32)` → `to_hex(...) == fixture.hkdf_key_hex`. (Pins HMAC + HKDF independently of the cipher.)
- **AEAD/session vector (the hard gate):** `encrypt_privkey(from_hex(fixture.privkey_hex), fixture.manifest_sig, from_hex(fixture.salt_hex), from_hex(fixture.nonce_hex)).ciphertext == fixture.ciphertext_hex`. This proves the vendored XChaCha20-Poly1305 framing ≡ `@noble/ciphers`. **If it differs, STOP and reconcile nonce/tag/IKM handling — do not weaken the test.**
- Round-trip: `decrypt_privkey(encrypt_privkey(priv, sig), sig) == priv`; wrong `manifest_sig` on decrypt → nil.

**Risk note:** this is the single highest-risk task in Plan 2. The vendored AEAD's tag placement (16-byte tag appended), 24-byte nonce, and the RFC 8439 Poly1305 construction (empty AAD) must match `@noble/ciphers`. The `session-key.json` vector surfaces any mismatch immediately. Budget iteration here.

**Gate/Steps:** TDD → commit `feat(core): vendor XChaCha20-Poly1305 + HKDF + session keypair/encrypted privkey` with the `THIRD-PARTY-NOTICES.txt` update in the same commit.

---

### Task 5: Signed checkpoints

**Files:**
- Create: `lua/provenance/core/checkpoint.lua`
- Test: `tests/core/checkpoint_spec.lua`
- Modify: `tests/conformance/conformance_spec.lua` — add the `checkpoint.json` assertion.

**Interfaces:**
- Consumes: `json`, `ed25519`.
- Produces:
  - `checkpoint.sign(seq: number, entry_hash: string, priv32: string): {seq, hash, sig}` — signs `json.canonicalize({hash = entry_hash, seq = seq})` UTF-8; `sig` is 128-hex.
  - `checkpoint.verify(cp: {seq, hash, sig}, pubkey_hex: string): boolean` — false (never throws) on invalid.

**Test intent:**
- **`checkpoint.json` fixture:** `checkpoint.verify({seq=128, hash=fixture.hash, sig=fixture.sig}, fixture.session_pubkey_hex) == true`; tampered hash/seq → false.
- Sign → verify true; wrong pubkey → false.

**Gate/Steps:** TDD → commit `feat(core): signed seq→hash checkpoints`.

---

### Task 6: Consolidate the full crypto/bundle conformance gate

**Files:**
- Modify: `tests/conformance/conformance_spec.lua` — ensure every fixture is asserted: `vectors.json` (Plan 1), `ed25519.json`, `manifest.json`, `bundle-manifest.json`, `golden-bundle.json`, `session-key.json`, `checkpoint.json`.

- [ ] Run `make test` — the entire `core/` suite green (Plan 1 + Plan 2). This is the gate before any wiring work (Plan 3+) begins.
- [ ] Confirm `THIRD-PARTY-NOTICES.txt` has one entry per vendored file (ed25519, XChaCha20-Poly1305) with license + copyright.
- [ ] Commit `test(core): full crypto/bundle conformance gate against golden vectors`.

---

## Self-Review

**Spec coverage (design.md §3 crypto keystone + §9.1 completion):** ed25519 vendor+wrapper (T1), manifest gate (T2), bundle sign+shape (T3), XChaCha20-Poly1305 + HKDF + session keypair/encrypted privkey (T4), checkpoints (T5), consolidated conformance (T6). Together with Plan 1, `core/` is feature-complete for the format contract the plugin (Plans 3+) drives.

**Keystone honesty (lead-with-it, per CLAUDE.md):** the pure-Lua **ed25519 signature** primitive has **no drop-in, widely-audited pure-Lua library** — the known ones are native C extensions (disqualified) or Luau ports needing a LuaJIT adaptation. Task 0 names the candidates; Task 1 pins the result to `ed25519.json` on real LuaJIT with an explicit **STOP-and-ask** if none reproduces the vector. XChaCha20-Poly1305 has a clean pure-Lua source (`plc`, MIT). HKDF/HMAC are built in-repo over the approved `vim.fn.sha256` — the only from-scratch code, and both are byte-pinned by `hkdf_key_hex`. **These trade-offs should be surfaced at plan review before execution.**

**Vector honesty:** every crypto primitive is pinned by a **deterministic** golden vector the export tool already emits (fixed seeds/salt/nonce), including the byte-for-byte `bundle-manifest.json` `canonical_json` that pins the Lua JCS output of the full nested bundle shape. No crypto vector is invented.

**Type consistency:** `ed25519.to_hex/from_hex/sign/verify` (T1) reused by manifest (T2), bundle (T3), checkpoint (T5); `json.canonicalize`/`json.array`/`json.NULL` (Plan 1) reused throughout; `EncryptedPrivkey` shape (T4) matches the `SlogMeta.encrypted_session_privkey` fields the meta writer (Plan 4) persists.

**Licensing gate:** `THIRD-PARTY-NOTICES.txt` is created/updated in the *same commit* as each vendored file (T1, T4); no entry → no vendor.
