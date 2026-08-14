# Changelog

Notable changes to netscan. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-14

First release.

### Scanning

- Host discovery over ICMP echo, TCP ping and ARP on directly attached IPv4 networks
- TCP connect scanning, needing no privileges
- Half open SYN scanning through the optional `raw` build feature, falling back to connect with a warning where it is unavailable
- UDP scanning
- IPv4 and IPv6, with targets given as addresses, hostnames, CIDR blocks, ranges or files, and exclusion lists
- Adaptive timing that follows observed latency and loss, within five timing templates
- Safety limits on targets, probes, concurrency, response size and buffering, checked before a scan starts

### Detection

- Service and version detection from banners and a probe database, capped by an intrusiveness level
- Operating system and device type inference from TTL, TCP behaviour, banners and MAC vendor, always reported with its evidence and a confidence level
- TLS inspection: negotiated version, cipher and certificate details

### Output

- Text tables that fit the terminal, with box drawing or ASCII borders and optional colour
- JSON, JSON Lines, CSV and XML, all carrying the same scan
- Format inferred from the output file extension

### Comparison and monitoring

- `--compare` reports what changed between two saved scans
- `--watch` rescans on an interval and reports changes as they happen
- `--inventory` maintains a record of what has been seen on a network over time

### Command line

- Seven built in scan profiles and named port presets
- Configuration through `netscan.toml`, with user defined profiles
- `--list-profiles`, `--list-probes` and `--list-interfaces`

### Desktop application

- Native application on the same engine, reading and writing the same files
- Sortable host list with eleven columns, selectable rows and context menus
- Detail pane with ports, host facts, detection evidence and TLS certificates
- Display filter language in the style of Wireshark
- Statistics view where every bar links into the filtered results
- Topology view grouping hosts by subnet and joining them to their services, with drag, pan and zoom
- Scan comparison and a live log
- Light and dark themes following the system preference
