# Architecture

## Three crates

```
netscan-core   the engine: everything about planning, running and reporting a scan
netscan-cli    the command line tool, a thin front end over the engine
netscan-gui    the desktop application, a thin front end over the engine
```

Neither front end contains scanning logic. That is not tidiness for its own sake: it is what makes a scan run in the interface produce byte identical results to the same scan run in a terminal, and it means a fix to timing or detection reaches both at once.

Roughly 33000 lines across the workspace, of which a third are tests.

## netscan-core

```
config/       ScanConfig, the builder, netscan.toml, and the safety limits
scanner/      target expansion, the worker pool, per host and per port results
discovery/    ICMP echo, TCP ping, ARP, reverse DNS
protocols/    TCP connect, SYN, UDP, TLS, raw sockets
detection/    service and version probes, OS fingerprinting, MAC vendor lookup
output/       text, JSON, JSON Lines, CSV, XML
profiles/     built in profiles and port presets
compare.rs    diffing two scans
inventory.rs  what has been seen on a network over time
engine.rs     ties it together and drives the scan
```

### How a scan runs

1. **Configuration.** `ScanConfig` is built from defaults, then the configuration file, then a profile, then command line options, in that order. It validates itself before anything touches the network, so a scan that would exceed a limit is refused before it starts rather than halfway through.

2. **Target expansion.** Addresses, hostnames, CIDR blocks and ranges expand into a target list, with exclusions removed. IPv4 network and broadcast addresses are dropped by default. The result is counted against `max_targets` before any of it is used.

3. **Discovery.** Unless disabled, each target is checked with ICMP echo, TCP ping and, on directly attached IPv4 networks, ARP. Hosts that do not answer are reported as down and their ports are not scanned.

4. **Port scanning.** A bounded worker pool runs probes against the live hosts. Concurrency is capped by configuration and again by `max_concurrency`, so an unbounded number of sockets is not reachable from any input. Adaptive timing moves the pool size and timeouts within those bounds as latency and loss are observed.

5. **Detection.** Open ports optionally get a banner read, then probes chosen by service and capped by intrusiveness. Every result carries a confidence and the source it came from.

6. **Reporting.** Results stream out as `ScanEvent` values while the scan runs, which is what the progress line and the live result tables consume. The same data is assembled into a `ScanReport` at the end for the output writers.

### Two ways to run one

```rust
let report = Engine::new(config)?.run().await?;      // batch
let handle = Engine::new(config)?.start().await?;    // streaming events
```

The CLI uses the second for its progress line and the first for everything else. The GUI uses the second throughout.

### Concurrency

Tokio, with a bounded channel between the workers and the consumer. When the consumer falls behind, the channel fills, and the workers block on send rather than accumulating results in memory. A scan of a large network has a bounded memory profile no matter how fast results arrive or how slow the reader is.

### Errors

One `Error` enum with a `Result` alias. Errors describe what failed and what to change, and errors that come from a limit name the limit. Nothing in the engine panics on input: a malformed target, a hostile banner and an unreachable interface are all ordinary errors.

## netscan-cli

Argument parsing with clap, then a mapping onto `ScanConfig`, then one of a handful of modes: scan, compare, watch, inventory, or one of the list commands. Output goes through the writers in `netscan-core::output`, so the CLI decides what to print and the engine decides what the data is.

Tables are drawn to fit the terminal, with box drawing characters where the terminal supports them and ASCII where it does not.

## netscan-gui

egui and eframe, drawn immediately every frame with no retained widget tree.

```
app.rs        the window, menus, and what each action does
session.rs    owns the engine handle and the live results
views/        results, statistics, topology, compare, log
theme.rs      the palette, and the ink that is legible on each surface
widgets.rs    shared small pieces
icons/        SVG path parsing and rasterising for the Blueprint icons
filter.rs     the display filter language
```

The reasoning behind the framework choice, the icon pipeline and the font bundling is in [GUI.md](GUI.md).

Everything the interface computes is pure where it can be: sorting, filtering, the graph layout, the menu contents and the aggregate statistics are all functions over data, tested without a window. What is left is drawing, and that is covered by tests that render each view headlessly at several sizes.

## Testing

| Kind | Where | What it covers |
| --- | --- | --- |
| Unit | beside the code | parsing, expansion, detection, formatting, filtering |
| Render | `netscan-gui/src/views/render_tests.rs` | every view drawn with data, with none, and in a pane too small |

750 tests, run with `cargo test --workspace`.

What is not covered: raw socket paths, which need a privileged socket and a real interface, and are verified by hand on macOS and Linux instead.

## Safety posture

- `#![forbid(unsafe_code)]` in every crate
- every input parsed rather than interpolated, with no shell invocation anywhere
- bounded concurrency, bounded read sizes, bounded channels, bounded target counts
- limits checked before a scan starts, not while it runs
- no credentials read, stored or transmitted
- temporary files created with `tempfile`, never at a predictable path

See [SECURITY.md](SECURITY.md).
