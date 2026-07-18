## Recording your work with the Provenance Recorder (Neovim)

For some assignments this term you'll record your work with the **Provenance Recorder**, a Neovim plugin that keeps a tamper-evident log of _how_ your code comes together as you work. When you're done, one command bundles your assignment files together with that log into a single sealed `.zip` — that one file is your submission, so your work can be reviewed as a process and not just a final file.

The plugin only runs inside assignment folders the course has authorized. In every other folder it does nothing — no recording, no network requests, and no change to how Neovim behaves. Setup takes a couple of minutes, and you only do it once.

> **What gets recorded?** Inside the assignment folder only: your edits, pastes, saves, cursor/selection movement, terminal commands, git activity, and editor focus. Everything stays on your computer until _you_ upload the sealed `.zip`. The complete list is in the [README](https://github.com/ProvenanceTools/provenance-neovim-recorder#what-it-records).

> **For course staff:** hand this page to students as-is, or copy it into your assignment instructions. Customize two things for your course: the **release tag** in step 1 (use the tag whose `extension_hash` you added to the analyzer allowlist), and how you **distribute the assignment folder** — it must contain the `.provenance-manifest` signed with your course's master key, or recording won't start.

### Before you start

You'll need:

- **Neovim 0.10 or newer.** Check with `nvim --version` (or `:version` inside Neovim). Update from <https://neovim.io> if you're behind.
- **A Neovim plugin manager** (lazy.nvim, packer.nvim, vim-plug, or mini.deps). If you already use Neovim you almost certainly have one.
- **The assignment folder** distributed for the assignment. It contains a hidden `.provenance-manifest` file — that's what authorizes recording. If it's missing, recording can't start; re-download the starter files.

### 1. Install the plugin

Add the plugin **pinned to the tag your course specifies** (examples below use `v0.1.1`). Pinning the tag is required: it ships the course's public key, and its source hash is what the analyzer recognizes as an approved build.

**lazy.nvim** — add to your plugin spec:

```lua
{ "ProvenanceTools/provenance-neovim-recorder", version = "v0.1.1", lazy = false }
```

**packer.nvim:**

```lua
use({ "ProvenanceTools/provenance-neovim-recorder", tag = "v0.1.1" })
```

**vim-plug** (in `init.vim`):

```vim
Plug 'ProvenanceTools/provenance-neovim-recorder', { 'tag': 'v0.1.1' }
```

Then install (`:Lazy sync`, `:PackerSync`, or `:PlugInstall` respectively) and restart Neovim. Other managers work too — see the [README install section](https://github.com/ProvenanceTools/provenance-neovim-recorder#install). You don't need an account; the plugin makes no network requests during a session.

> **Don't lazy-load it.** The recorder has to load every time Neovim starts so it can notice when you open an assignment folder. The `lazy = false` above is what guarantees that for lazy.nvim (some configs lazy-load everything by default). For packer/vim-plug, just don't add on-demand loading options (`opt`, `cmd`, `ft`, `event`, `{ 'on': ... }`, `{ 'for': ... }`). If the plugin only loads on demand, **your work won't be recorded** even though it looks installed.

### 2. Open the assignment folder

The recorder activates based on Neovim's **working directory**, so start Neovim _inside_ the assignment folder — not a parent, not a subfolder:

```sh
cd path/to/the-assignment-folder
nvim .
```

(If you're already in Neovim, `:cd path/to/the-assignment-folder` works too.) The folder must contain the `.provenance-manifest` file. When Neovim sees it, the recorder activates automatically.

### 3. Confirm it's recording

Run this in Neovim:

```vim
:lua =require('provenance.recorder.status').segment()
```

- If it prints **`● Provenance: recording`**, you're set.
- If it prints an empty string (`""`), recording is **not** active yet — see [Troubleshooting](#troubleshooting).

You can also tell at a glance because a hidden **`.provenance/`** folder appears inside the assignment folder once a session starts — that's where the log lives. Don't delete, edit, or commit it; the submission step bundles it for you.

> **Want a permanent indicator?** Unlike VS Code, Neovim won't add anything to your statusline on its own (so it never overwrites your config). If you'd like a persistent `● Provenance: recording` segment, add the plugin's `segment()` function to your statusline — see [Status indicator](https://github.com/ProvenanceTools/provenance-neovim-recorder#status-indicator) in the README. This is optional; the check above works without it.

### 4. Work normally

Just do the assignment. The log is appended continuously, so you can:

- Quit Neovim and come back later — reopening the folder starts a new session that links to the previous one. Nothing is lost.
- Use the built-in terminal, run and debug code, use your usual plugins — all fine.

There's nothing to start or stop. As long as the check in step 3 says `● Provenance: recording`, you're covered.

### 5. Prepare your submission bundle

When you've finished the assignment, run:

```vim
:ProvenanceSeal
```

A sealed **`.zip`** file is written for your submission, and Neovim prints the path to it. This bundle contains both your assignment files and the process log.

### 6. Submit

Upload **only that `.zip`** to Gradescope — nothing else. The bundle already includes your assignment files, so you don't submit your code separately.

### Troubleshooting

**Step 3 prints `""` (not recording).**
The recorder only activates for an authorized assignment folder. Check that:

- You started Neovim with the assignment folder as the working directory (step 2) — not a parent or subfolder. Confirm with `:pwd`.
- The `.provenance-manifest` file is still present in that folder.
- You installed the tag the course expects. If the manifest's signature doesn't match your installed build, recording won't start — reinstall the version posted for this assignment (step 1) and restart Neovim.

**`:ProvenanceSeal` says "not an activated assignment workspace".**
The live seal command only works while recording is active. Confirm step 3 first; if it prints `""`, fix activation (above) before sealing.

**I quit Neovim in the middle of the assignment — did I lose my log?**
No. The log is written continuously, not held until submission. Reopen the folder and keep working; the new session links to the previous one.

**Sealing failed.**
You'll see an error message. The usual cause is a partially-written log file, which the plugin repairs automatically on the next launch. Reopen the folder and run `:ProvenanceSeal` again.

**Can I see exactly what was recorded?**
Yes. The files in the hidden `.provenance/` folder (`session-*.slog`) are plain newline-delimited JSON. Open them in Neovim and read every event as it was logged. Recording is fully transparent — there are no hidden signals, and the plugin is open source.

### Privacy at a glance

- The log lives **only on your computer** until you upload the sealed `.zip` yourself.
- The plugin makes **no network requests** and sends nothing anywhere automatically.
- It records **nothing outside the assignment folder** — other projects, your Neovim config, and other apps are invisible to it.
- It does **not** record your name, email address, or IP address.

For the complete, itemized list of what is and isn't captured, see the [README](https://github.com/ProvenanceTools/provenance-neovim-recorder#what-it-records).
