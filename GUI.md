# The desktop application

`netscan-gui` is a native application over the same engine as the command line tool. A scan run here and a scan run in a terminal produce identical results, and both read and write the same JSON files.

## Views

**Results.** A sortable host list over a detail pane. Eleven columns per host: address, hostname, status, inferred role, open and tested port counts, latency, MAC, vendor, operating system and services. Rows are selectable and carry a context menu for copying an address, a row or the whole visible list, narrowing the filter, or rescanning one host or one port. The detail pane has tabs for ports, host facts, detection evidence and TLS certificates.

**Statistics.** Services by frequency, the busiest hosts, port states as a proportion, and a latency distribution. Every bar is a link: clicking one opens the results filtered to what the bar counted.

**Topology.** Hosts grouped by the subnet they were found in, joined to the services they offer. Drag a node to move it, drag the background to pan, scroll to zoom, and hover to follow one thread through the graph while the rest dims.

**Compare.** Two saved scans side by side, with what appeared, disappeared and changed.

**Log.** What the scan did, as it did it.

## The display filter

A short expression language in the style of Wireshark's display filter.

```
port:22                 ports numbered 22
port:>1024              ports above a number
port:8000-9000          a range
service:http            service name contains
product:nginx           identified product
state:open              port state
status:up               host status
host:192.168.1          address or hostname contains
net:192.168.1.0/24      addresses inside a block
os:linux                inferred operating system
vendor:apple            hardware vendor
tls:true                ports where TLS was observed
!port:22                negate any term
nginx                   free text, matched against all of the above
```

Terms are separated by spaces and all must match. Everything the language expresses is also reachable from the ordinary controls, so nobody has to learn it.

## Why egui

The requirement was a native application with no runtime dependency, one binary, and a table that stays responsive with tens of thousands of rows arriving while the user scrolls it.

| Option | Why not |
| --- | --- |
| Slint | good, but its own markup language for a table heavy application adds a layer without adding much |
| Qt | large runtime dependency, C++ build chain, licensing to think about |
| GTK | ties the application to the GNOME stack and complicates macOS and Windows builds |
| Tauri or Electron | a browser engine, which is a large dependency and a large attack surface for a security tool |

egui is immediate mode, pure Rust, renders through wgpu or glow, and produces one binary per platform with no runtime. Immediate mode suits results that change every frame during a scan: there is no widget tree to keep in step with the data, because the frame is drawn from the data each time.

The cost is that egui gives you very little for free. Tables, the node graph, the icon rendering and the theme are all built here. That was an acceptable trade for a dense instrument where the stock widgets would have been replaced anyway.

## Icons

Vendored from Palantir's Blueprint, Apache 2.0, as raw SVG path data under `assets/blueprint-icons`. Each is parsed and rasterised at runtime into an alpha mask, then tinted and cached per size and colour.

Why not a font: an icon font puts glyphs at codepoints that vary by platform and silently renders a missing box when a fallback font takes over. Why not a bundled SVG library: it is a large dependency to draw sixteen shapes. The path parser and scanline rasteriser are about 400 lines with their own tests, including the awkward parts of the SVG path grammar such as packed arc flags and run together numbers.

Provenance, the mapping from netscan's names to Blueprint's, and how to add another are recorded in `assets/blueprint-icons/README.md`.

## Fonts

Amazon Ember, bundled so the application looks the same everywhere rather than inheriting whatever the system decides. It is redistributable with an application. If your distribution terms differ, replace the files in `assets` and rebuild.

## Theme

Three surfaces and no more: a title bar, one ground for the whole window, and a recess for anything you can type in or press. Regions are separated by hairlines and their contents rather than by fills, shadows or generous padding.

Colour carries meaning and nothing else. Green is open or up, orange is filtered, red is a probe that could not complete, blue is the selection. Every one is accompanied by text saying the same thing, so colour is never the only signal.

Each surface names the ink that is legible on it, and the pairings are checked by contrast tests rather than by eye. The host list is drawn on a light band with dark ink; the port list on the dark ground with light ink; a selected row is blue with white ink. Nothing can be drawn in a colour that does not carry on the surface under it without a test failing.

Both a light and a dark palette follow the system preference.

## Window

The application draws its own title bar so the window looks the same on every platform, with the current task in the middle: `netscan`, then what it is doing. On macOS the system title bar is hidden and the traffic lights are placed by the application.

## What it will not do

The topology view shows what a port scanner can observe: which subnet a host was found in, whether that subnet is attached to this machine, and what each host appears to be. It does not draw switch fabric, routing or physical links, because a port scanner does not see them and a diagram claiming otherwise would be fiction.

Role and operating system are labelled as inferences wherever they appear, with their evidence and a confidence level.
