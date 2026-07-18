# Three-Signal Paste Detection (Plan 6 of the provnvim series)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Detect pastes (especially large LLM pastes) by combining three signals and reconcile them to exactly one event per paste — emitting `paste` (with content) or `doc.change` with `source="paste_likely"`, plus a `paste.anomaly` watchdog when the signals disagree. This is design.md §5's **second high-risk** item: Neovim has no single paste-command surface.

**Architecture:** Three signals — (1) the **bulk-insertion classifier** over the `on_lines` delta shape (single delta ≥30 chars, or aggregate ≥30 with a newline), (2) the **paste intercept** via `vim.paste()` override / bracketed-paste, (3) the **clipboard registers** `getreg('+')`/`getreg('*')`. A correlator fuses (1)+(2)+(3) into one `PasteDecision`; an independent reconciler compares per-interval intercepted-vs-classified counts and emits `paste.anomaly` on divergence. Pure-logic-first; the `vim.paste()` seam is isolated.

**Tech Stack:** Lua, `vim.paste` override, `on_lines` deltas, `vim.fn.getreg`, `vim.uv` timer, plenary. Builds on Plan 4's doc-wiring + emit.

## Global Constraints

(Inherits Plans 1–5.) Additional:

- **Do not simplify to one signal (CLAUDE.md, design.md §5).** All three signals must be reconciled to exactly one event per paste.
- **Classifier thresholds (char-length, not bytes):** `PASTE_MIN_INSERT_CHARS = 30`. `paste_likely` iff a single delta's `#text >= 30`, OR aggregate inserted chars `>= 30` **and** some delta contains `\n`. Aggregate ≥30 without any newline (multi-cursor typing) → `typed`.
- **Payload (UTF-8 bytes):** `length` = UTF-8 byte length; `sha256` of the text; inline `content` when `length <= 4096`, else `content_head`/`content_tail` = first/last 512 **chars**.
- **Emit routing:** a single-delta paste at an empty range → `kind="paste"` (with payload + `range`); a multi-delta / non-empty-range replacement classified paste_likely → `kind="doc.change"` with `source="paste_likely"`.
- **Reconciler:** every interval (default 5000ms) compute per-interval deltas of intercepted vs large-insert counts; `abs(delta_i - delta_l) > tolerance` (default 1, strictly greater) → emit `paste.anomaly {intercepted_count, large_insert_count}` (per-interval deltas, not cumulative); reset baselines each tick.
- Every timer/override has a `dispose()` that restores `vim.paste` and stops the timer.

### File structure

```
lua/provenance/recorder/
  events/paste_classifier.lua    -- classify_change(deltas) → "typed"|"paste_likely" (signal 1)
  events/paste_payload.lua       -- build_paste_payload(text) (inline/truncate)
  events/paste_correlator.lua    -- fuse signals 1+2+3 → PasteDecision + anomaly counters
  events/paste_reconciler.lua    -- interval anomaly watchdog (signal 3 reconciliation)
  wiring/paste_intercept.lua     -- vim.paste() override + clipboard read (signal 2 seam)
  wiring/paste_assembly.lua      -- wire correlator + intercept + doc-change into doc-wiring
tests/recorder/**/*_spec.lua
```

---

### Task 1: Bulk-insertion classifier (signal 1)

**Files:** Create `events/paste_classifier.lua`; Test.

**Interfaces:** `classify_change(deltas) → "typed"|"paste_likely"`. Empty → `typed`. Compute `total_inserted_chars`, `max_single_delta_chars`, `any_delta_has_newline` (over `#delta.text` / `delta.text:find("\n")`). Rule 1: `max_single >= 30` → paste_likely. Rule 2: `total >= 30 and any_newline` → paste_likely. Else typed. (Char length, not bytes.)

**Test intent:** single 30-char → paste_likely, 29 → typed; single 0 → typed; empty array → typed; single ≥30 at non-empty range → paste_likely; multi-delta one ≥30 → paste_likely; aggregate ≥30 with newline → paste_likely; aggregate ≥30 **without** newline → typed; aggregate <30 with newline → typed. **Gate:** spec green. **Commit:** `feat(recorder): paste bulk-insertion classifier`.

---

### Task 2: Paste payload builder

**Files:** Create `events/paste_payload.lua`; Test.

**Interfaces:** `build_paste_payload(text) → {length, sha256, content?/content_head?/content_tail?}` — `length` = UTF-8 bytes; `sha256` of text; `≤4096` → `content=text`; `>4096` → head/tail 512 chars, omit content; empty → `{length=0, content=""}`.

**Test intent:** short inline; >4096 truncated; multibyte-emoji length in bytes (`😀`→4); 4096 boundary inclusive. **Gate:** spec green. **Commit:** `feat(recorder): paste payload builder`.

---

### Task 3: Paste correlator (fuse signals 1+2+3)

**Files:** Create `events/paste_correlator.lua`; Test.

**Interfaces:** `correlator.new({window_ms?, get_now, similarity?}) → c` with:
- `c.on_paste_intercept(text, at)` — records a pending paste (signal 2) + captured clipboard text (signal 3), increments intercepted count.
- `c.on_doc_change(deltas, range, at) → PasteDecision` — classifies (signal 1); if a pending intercept is within the window and the inserted text matches the clipboard (containment / EOL-normalized similarity ≥ threshold), confirm and consume it → `{kind="paste", payload, range}`; else if paste_likely → `{kind="doc.change", source="paste_likely", deltas}`; else `{kind="doc.change", source="typed", deltas}`. Increments large-insert count when paste_likely.
- `c.counts() → {intercepted, large_insert}` for the reconciler.

**Test intent:** intercept + matching change within window → one `paste`; change past window or non-matching clipboard → `doc.change source=paste_likely`; pending consumed once; plain typing → `source=typed`. **Gate:** spec green. **Commit:** `feat(recorder): paste correlator (three-signal fusion)`.

---

### Task 4: Paste reconciler (anomaly watchdog)

**Files:** Create `events/paste_reconciler.lua`; Test.

**Interfaces:** `reconciler.start({interval_ms?=5000, tolerance?=1, emit, get_intercepted_count, get_large_insert_count}) → handle` — baseline at start; each tick compute per-interval deltas, update baselines unconditionally, `abs > tolerance` → emit `paste.anomaly {intercepted_count=delta_i, large_insert_count=delta_l}`; `.unref()`d timer; `dispose()` stops.

**Test intent:** equal deltas → no emit; `|2-3|=1` (not >1) → no emit; `|1-4|=3` → emit `{1,4}`; tolerance 0 with `+2 vs +3` → emit `{2,3}`; after emit, next tick measured from new baseline. **Gate:** spec green. **Commit:** `feat(recorder): paste anomaly reconciler`.

---

### Task 5: Paste intercept seam (`vim.paste` override + clipboard)

**Files:** Create `wiring/paste_intercept.lua`; Test (headless, invoke `vim.paste`).

**Interfaces:** `paste_intercept.attach({on_intercept, get_now}) → handle` — wraps the global `vim.paste` (and honors bracketed-paste): on a paste, read `getreg('+')`/`getreg('*')`, call `on_intercept(pasted_text, get_now())`, then **delegate to the original `vim.paste`** so the paste still happens. `handle.dispose()` restores the original `vim.paste`.

**Test intent (headless):** calling `vim.paste({...}, -1)` triggers `on_intercept` with the text and captures clipboard; the paste still applies to the buffer; `dispose` restores the original. **Gate:** spec green. **Commit:** `feat(recorder): vim.paste intercept + clipboard capture`.

---

### Task 6: Assembly + payload-shape conformance

**Files:** Create `wiring/paste_assembly.lua`; Tests incl. an event-shape conformance spec.

**Interfaces:** `paste_assembly.attach({emit, doc_wiring_hooks}) → handle` — instantiates the correlator, wires `paste_intercept` → `correlator.on_paste_intercept`, routes doc-wiring's `on_lines` through `correlator.on_doc_change` (replacing Plan 4's hardcoded `source="typed"`), emits the resulting `paste`/`doc.change`, and starts the reconciler with `correlator.counts`. `handle.dispose()` tears down all three.

**Conformance intent:** assert the emitted `paste`, `doc.change` (`source` enum), and `paste.anomaly` payloads match `log-core`'s `events.ts` field names/optionality exactly (a shape test, mirroring provjet's payload-conformance task).

**Test intent (headless):** a real `vim.paste` of ≥30 chars produces exactly one `paste` event with content; typing produces `doc.change source=typed`; disagreeing counts drive a `paste.anomaly`. **Gate:** spec green + full `make test`. **Commit:** `feat(recorder): assemble three-signal paste detection`.

---

## Self-Review

**Spec coverage (design.md §5, §9.5, PRD §4.3):** classifier (T1), payload (T2), correlator fusing all three signals into one decision (T3), anomaly reconciler (T4), the `vim.paste` intercept seam + clipboard (T5), assembly + payload conformance (T6). The three signals are explicitly reconciled to one event — not simplified.

**Port fidelity:** classifier thresholds/boundaries (`≥30`, newline rule, char-not-byte) match `paste-classifier.ts`; payload inline/truncate (4096/512, byte-length) matches `paste-payload.ts`; reconciler per-interval-delta + strict-`>` tolerance matches `paste-reconciler.ts`; emit routing (empty-range single delta → `paste`; else `doc.change source=paste_likely`) matches doc-events/PRD §4.3.

**Type consistency:** `classify_change` (T1) + `build_paste_payload` (T2) consumed by the correlator (T3); `correlator.counts` (T3) feeds the reconciler (T4); `paste_intercept.on_intercept` (T5) feeds `correlator.on_paste_intercept`; assembly (T6) replaces Plan 4's `source="typed"` stub — a named seam, not a silent change.
