# Blueprint icons

Icon path data vendored from [`@blueprintjs/icons`](https://github.com/palantir/blueprint)
version **5.10.0**, published by Palantir Technologies under the **Apache License
2.0** — the full text is in `LICENSE` beside this file.

## What is here

One `.path` file per icon, each holding the `d` attribute of Blueprint's 16×16
SVG, copied verbatim from `src/generated/16px/paths/<name>.ts` in the published
package. One subpath per line. Nothing has been redrawn, simplified or
rescaled.

The file name is Blueprint's own name for the icon, so any of these can be
checked against the published set.

| file | used for |
| --- | --- |
| `play.path` | start a scan |
| `stop.path` | stop the running scan |
| `refresh.path` | run the same scan again |
| `cog.path` | scan configuration |
| `folder-open.path` | open a saved scan |
| `floppy-disk.path` | save results |
| `search.path` | the display filter |
| `arrow-left.path` | previous host |
| `arrow-right.path` | next host |
| `step-backward.path` | first host |
| `step-forward.path` | last host |
| `eye-open.path` | show hosts that are down |
| `comparison.path` | compare with a saved scan |
| `help.path` | filter syntax |

## How they are drawn

`crates/netscan-gui/src/icons/` reads these at runtime: `path.rs` parses and
flattens the path, `raster.rs` fills it with the nonzero winding rule into an
alpha mask, and `mod.rs` uploads that mask once per size and tints it. No SVG
rendering library is involved, and the icons are rasterised at the size they are
actually drawn at so they stay sharp on a high-density display.

## Adding another icon

1. Copy the `d` string out of `@blueprintjs/icons` for the 16px variant into
   `<blueprint-name>.path`.
2. Add a variant to `Icon`, with its name and an `include_str!` arm.

The tests in `icons/mod.rs` will then check that it parses, that it stays inside
the 16-unit box, that it covers a sensible fraction of it, and that it is not a
duplicate of an icon already in the set.
