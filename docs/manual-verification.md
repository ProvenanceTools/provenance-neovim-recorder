# Manual Verification Checklist

This file documents manual, real-TUI verification steps that the headless test suite cannot cover. Each item is checked off only after a human confirms it in a real `nvim` session. New plans append their own real-TUI items here over time.

## Plan 3 — Activation + status indicator

- [ ] **Non-assignment directory (no `.provenance-manifest`):** Open a directory that does not contain a `.provenance-manifest` file in `nvim`. Confirm that the status segment does NOT show "Provenance: recording" (it is absent from the statusline). Also verify that no `.provenance/` directory is created in that folder.

- [ ] **Valid signed manifest:** Create or navigate to a directory containing a valid, signed `.provenance-manifest` (one that verifies against the embedded course public key), then open that directory in `nvim`. Confirm that the status segment shows `● Provenance: recording`.

- [ ] **Tampered manifest signature:** In a directory with a valid `.provenance-manifest`, manually edit the manifest file and flip one hex character in the `sig` field (e.g., change the first hex digit of the signature), then save and relaunch `nvim` in that directory. Confirm that the status segment is absent (no "Provenance: recording" message), because signature verification fails on activation.

### How to view the status segment

To observe the status segment during testing, add the following to your Neovim statusline configuration (e.g., in `init.lua`):

```lua
vim.opt.statusline = '%{v:lua.require\'provenance.recorder.status\'.segment()}'
```

Or append it to an existing statusline if you prefer; the segment returns an empty string when recording is inactive, so it renders invisibly when not activated.
