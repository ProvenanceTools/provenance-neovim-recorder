# Brand assets

This plugin ships under the **Provenance Recorder** name and uses the
[Provenance](https://github.com/ProvenanceTools/provenance) mark unchanged — two interlocking
rounded-square chain links, woven with a true over/under. The only addition is a
`for Neovim` line under the wordmark, in the same wordmark-plus-tagline arrangement the
[JetBrains recorder](https://github.com/ProvenanceTools/provenance-jetbrains-recorder) uses.

The mark is not re-drawn or re-colored here. If the Provenance master changes, re-derive
these files from it rather than editing them in place.

## Color tokens

| Token      | Light surface | Dark surface |
| ---------- | ------------- | ------------ |
| Ink / line | `#18181b`     | `#fafafa`    |
| Accent     | `#EA580C`     | `#F97316`    |
| Subtitle   | `#52525b`     | `#a1a1aa`    |

Same tokens as Provenance; the accent brightens on dark surfaces for contrast.

## Source masters

| File                                 | Use                            |
| ------------------------------------ | ------------------------------ |
| `provenance-neovim-lockup.svg`       | mark + wordmark, light surface |
| `provenance-neovim-lockup-dark.svg`  | mark + wordmark, dark surface  |

The wordmark is the Tailwind default system-sans stack at weight 600, matching the
Provenance wordmark; the tagline is the same stack at weight 500.

## Exports

The README embeds the **PNGs**, not the SVGs. System fonts render per-machine, so the
wordmark is rasterized for portable, predictable sizing; the SVGs stay the editable
masters. PNGs have transparent backgrounds so they blend into GitHub's light or dark theme,
selected with a `<picture>` + `prefers-color-scheme` element.

| File                       | Where it's wired |
| -------------------------- | ---------------- |
| `exports/lockup-light.png` | README header    |
| `exports/lockup-dark.png`  | README header    |

## Regenerating exports

Rendered with [`rsvg-convert`](https://gitlab.gnome.org/GNOME/librsvg) (`brew install librsvg`).
From this directory:

```sh
rsvg-convert -w 1240 provenance-neovim-lockup.svg      -o exports/lockup-light.png
rsvg-convert -w 1240 provenance-neovim-lockup-dark.svg -o exports/lockup-dark.png
```

## Note on `extension_hash`

These assets live outside `lua/`, and the recorder's `extension_hash` is a tree-hash of
`lua/` only — so adding or changing brand files does not change a release's `extension_hash`
or require a new analyzer allowlist entry.
