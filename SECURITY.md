# Security

## Authorised use

Port scanning a system you do not own or have written permission to test may be unlawful where you are, and may breach the terms of service of the network you are connected to. In several jurisdictions unauthorised scanning is a criminal offence regardless of whether any harm results.

netscan is for:

- networks you own or are responsible for
- systems you have written authorisation to test
- security research on infrastructure you control
- education, on a network set up for it

netscan is not for scanning systems belonging to other people without their permission. If you are unsure whether you have permission, you do not have permission.

The authors are not responsible for how you use it.

## Built in restraint

The defaults assume a mistake is more likely than an emergency.

| Guard | Default | Purpose |
| --- | --- | --- |
| `max_targets` | 65536 | a mistyped CIDR cannot become a scan of the internet |
| `max_total_probes` | 20000000 | one scan cannot run indefinitely by accident |
| `max_concurrency` | 20000 | in flight probes are bounded whatever is requested |
| `max_response_bytes` | 65536 | a hostile service cannot stream unbounded data into memory |
| `event_buffer` | 4096 | results are bounded, and workers slow when a reader falls behind |
| confirmation | on | a scan large enough to be a mistake needs `--yes` |

Limits are checked before a scan starts. Raising them is deliberate and documented in [CONFIGURATION.md](CONFIGURATION.md).

Timing defaults to `normal` rather than the fastest setting, and adaptive timing backs off when a network shows loss. Scanning faster than a network can absorb is a denial of service on that network, however unintentional.

## How netscan is built

- `#![forbid(unsafe_code)]` in every crate, so memory safety rests on the compiler rather than review
- no shell invocation anywhere, so command injection has nowhere to happen
- every input parsed rather than interpolated, including targets, ports, filters, probe files and configuration
- responses treated as hostile: bounded reads, no format strings from remote data, escaping in every output writer so a banner cannot break out of a CSV row or an XML element
- bounded concurrency, bounded channels and bounded allocations, so resource use does not scale with what a remote host chooses to send
- no credentials read, stored or transmitted; netscan does not authenticate to anything
- temporary files through `tempfile`, never at a predictable path
- dependencies kept few, and audited in CI with `cargo audit` and `cargo deny`

Raw sockets are behind an optional `raw` build feature, off by default, because they need elevated privileges. Grant a capability rather than running the scanner as root; see [INSTALL.md](INSTALL.md).

## Privacy

netscan sends no telemetry. It makes no network connection except to the targets you name and to the DNS resolver, and `--no-dns` stops the latter.

Saved scans record addresses, hostnames, MAC addresses, service banners and certificate details of the hosts scanned. That is information about a network. Treat the files accordingly.

## Reporting a vulnerability

Report privately through [GitHub Security Advisories](https://github.com/sssst9s/netscan/security/advisories/new). Please do not open a public issue for a security problem.

Include what you found, how to reproduce it, which version you were on and what you think the impact is.

You should get an acknowledgement within a few days. Fixes go out as a patch release with the advisory published once people have had a chance to update. Credit is given unless you would rather it were not.

### Scope

In scope: memory safety failures, denial of service reachable from a remote response, unsound parsing of any input netscan reads, anything that causes a scan to exceed its configured limits, anything that leaks data it should not.

Out of scope: the fact that netscan can be used to scan networks. That is what it is.

## Supported versions

The latest release receives security fixes.
