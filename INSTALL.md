# Installing netscan

Every route below installs the same two binaries: `netscan` for the command line and `netscan-gui` for the desktop application.

## Supported platforms

| Platform | Command line | Desktop application |
| --- | --- | --- |
| macOS 12 or later, Apple silicon and Intel | yes | yes |
| Linux, x86_64 and aarch64, glibc 2.31 or later | yes | yes |
| Windows 10 or later, x86_64 | yes | yes |

## Homebrew

```sh
brew tap sssst9s/netscan https://github.com/sssst9s/netscan.git
brew install netscan
```

Upgrading later:

```sh
brew update && brew upgrade netscan
```

The formula builds from source, so it needs a Rust toolchain, which Homebrew installs as a build dependency if you do not already have one.

The formula points at a release tag, so this route works once the first release has been published. Before then, use `--HEAD` to build the current main branch:

```sh
brew install --HEAD netscan
```

## Install script

```sh
curl -fsSL https://raw.githubusercontent.com/sssst9s/netscan/main/install.sh | sh
```

It detects your platform, downloads the matching archive from the latest release, verifies its checksum and installs `netscan` into `/usr/local/bin`.

Options, set as environment variables:

| Variable | Effect |
| --- | --- |
| `NETSCAN_INSTALL_DIR` | install somewhere other than `/usr/local/bin` |
| `NETSCAN_VERSION` | install a specific tag rather than the latest |

Piping a script from the internet into a shell is worth a look first. Read it at [install.sh](install.sh), or download and run it separately.

## Prebuilt archives

Every release publishes an archive per platform on the [releases page](https://github.com/sssst9s/netscan/releases), each with a `.sha256` file beside it.

```sh
tar xzf netscan-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 755 netscan /usr/local/bin/netscan
```

On macOS the archives are not notarised, so Gatekeeper will refuse the first run. Clear the quarantine attribute:

```sh
xattr -d com.apple.quarantine netscan
```

## Cargo

```sh
cargo install --git https://github.com/sssst9s/netscan netscan-cli
cargo install --git https://github.com/sssst9s/netscan netscan-gui
```

## From source

Requires Rust 1.83 or later, installed through [rustup](https://rustup.rs).

```sh
git clone https://github.com/sssst9s/netscan.git
cd netscan
cargo build --release
```

Binaries land in `target/release`.

### Linux build dependencies

The desktop application needs the usual X11 and Wayland development packages. On Debian and Ubuntu:

```sh
sudo apt install build-essential pkg-config libx11-dev libxcursor-dev \
    libxrandr-dev libxi-dev libgl1-mesa-dev libwayland-dev libxkbcommon-dev
```

The command line tool has no system dependencies beyond a C linker.

## Raw sockets and SYN scanning

Half open SYN scanning and ARP discovery need raw sockets, which are behind an optional build feature because they need elevated privileges and are not available everywhere.

```sh
cargo build --release --features raw
```

Grant the capability rather than running the whole scanner as root:

```sh
# Linux
sudo setcap cap_net_raw,cap_net_admin=eip target/release/netscan

# macOS
sudo chown root target/release/netscan && sudo chmod u+s target/release/netscan
```

Without the feature or the privilege, `--syn` falls back to a full TCP connect scan and says so. Nothing silently degrades.

The raw socket paths have been exercised against a live network on macOS and Linux. They are not covered by the automated tests, because a test that needs a privileged socket and a real interface is not a test that can run in CI. That limitation is stated here rather than papered over.

## Verifying the install

```sh
netscan --version
netscan --list-interfaces
netscan 127.0.0.1
```

## Bundled third party assets

| Asset | Where | Licence |
| --- | --- | --- |
| Amazon Ember | `assets/*.ttf` | Amazon's font licence, redistributable with the application. Replace the files and rebuild if your distribution terms differ. |
| Blueprint icons | `assets/blueprint-icons` | Apache 2.0, from Palantir's Blueprint. The licence and provenance are recorded in `assets/blueprint-icons/README.md`. |

## Uninstalling

```sh
brew uninstall netscan                 # Homebrew
rm /usr/local/bin/netscan              # install script or manual
cargo uninstall netscan-cli            # cargo
```

Configuration lives in `~/.config/netscan/netscan.toml` on Linux, `~/Library/Application Support/netscan` on macOS and `%APPDATA%\netscan` on Windows. Remove it if you want nothing left behind.
