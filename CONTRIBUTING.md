# Contributing

## Getting set up

Rust 1.83 or later, through [rustup](https://rustup.rs).

```sh
git clone https://github.com/sssst9s/netscan.git
cd netscan
cargo build
cargo test --workspace
```

Linux needs the X11 and Wayland development packages for the desktop application; see [INSTALL.md](INSTALL.md). The command line tool builds with nothing beyond a C linker.

## Before opening a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
cargo test --workspace
```

All three have to be clean. CI runs the same commands on Linux, macOS and Windows, plus the minimum supported Rust version and a dependency audit.

## What the code looks like

The workspace has a few standing rules, all enforced rather than remembered:

- `#![forbid(unsafe_code)]` in every crate
- no comments. If a piece of code needs explaining, the fix is a better name or a smaller function, not a paragraph above it
- names carry the meaning: a function is called what it does and a type is called what it is
- no `unwrap` or `expect` outside tests, where clippy allows them
- errors say what failed and what to change

New behaviour needs a test. Behaviour that is pure logic gets a unit test beside it. Anything that draws gets a render test in `crates/netscan-gui/src/views/render_tests.rs`, which runs a frame headlessly at several sizes including one too small to lay out in, because hand drawn geometry fails by panicking on a degenerate rectangle.

## Where things live

See [ARCHITECTURE.md](ARCHITECTURE.md). The short version: scanning logic goes in `netscan-core` and nowhere else. If you find yourself adding scanning logic to the CLI or the GUI, it belongs in the engine, where both can use it and both are tested against it.

## Claims

Two rules about what the project says of itself, which apply to code and documentation equally:

- no feature that does not work. A flag that is accepted and ignored is worse than a flag that does not exist. If something falls back, it says so at the time.
- no performance claim without a benchmark to back it. "Fast" in prose is fine; a number is not, unless it can be reproduced.

Detection results are inferences and are labelled as such wherever they are shown, with their evidence and a confidence level.

## Commit messages

A short imperative summary, then a body explaining why if it is not obvious.

```
Add net: filter term for subnet containment

host:192.168.1 matched 192.168.10.1, which is wrong for a subnet.
Parsing the value as a network makes containment exact.
```

## Reporting a bug

Open an issue with what you ran, what happened, what you expected, and the output of `netscan --version`. `--debug` prints the resolved configuration, which is usually the fastest way to a diagnosis.

For a security problem, do not open an issue. See [SECURITY.md](SECURITY.md).

## Proposing a feature

Open an issue first for anything substantial. It is easier to agree on a shape before the code exists than after.

## Licence

Contributions are made under the MIT licence, the same as the project.
