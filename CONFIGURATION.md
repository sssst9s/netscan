# Configuration

netscan runs with no configuration at all. A `netscan.toml` file changes the defaults, defines your own scan profiles and raises or lowers the safety limits.

## Where the file lives

The first file found wins:

1. the path in `NETSCAN_CONFIG`, or the one given to `--config`
2. `netscan.toml` in the working directory
3. `$XDG_CONFIG_HOME/netscan/netscan.toml`
4. `~/.config/netscan/netscan.toml`
5. `~/Library/Application Support/netscan/netscan.toml` on macOS
6. `%APPDATA%\netscan\netscan.toml` on Windows

`--no-config` ignores all of them. Command line options always win over the file.

## Shape of the file

```toml
default_profile = "quick"

[defaults]
description = "settings applied before any profile"
timing = "normal"
service_detection = true
reverse_dns = true

[limits]
max_targets = 65536

[profiles.lab]
description = "the test network, everything on"
ports = "top:1000"
service_detection = true
os_detection = true
tls_inspection = true
timing = "aggressive"
```

Unknown keys are an error rather than a silent no-op, so a typo tells you about itself.

## Defaults

The `[defaults]` table takes any of the profile keys below. They are applied before a profile and before command line options.

## Profiles

A profile is a named bundle of settings, used with `--profile <name>`. Define one under `[profiles.<name>]`.

| Key | Type | Meaning |
| --- | --- | --- |
| `description` | string | shown by `--list-profiles` |
| `ports` | port selector | which ports to scan |
| `udp_ports` | port selector | UDP ports, when scanning both transports |
| `timing` | string | `sneaky`, `polite`, `normal`, `aggressive` or `insane` |
| `tcp` | bool | scan TCP ports |
| `tcp_mode` | string | `connect` or `syn` |
| `udp` | bool | scan UDP ports |
| `discovery` | bool | run host discovery |
| `discovery_only` | bool | find live hosts and stop |
| `service_detection` | bool | identify service and version |
| `os_detection` | bool | infer operating system and device type |
| `tls_inspection` | bool | collect TLS and certificate detail |
| `max_intrusiveness` | 0 to 9 | cap how intrusive probes may be |
| `concurrency` | integer | probes in flight at once |
| `connect_timeout_ms` | integer | connection timeout |
| `retries` | integer | extra attempts for probes that time out |
| `max_rate` | integer | cap on probes per second |
| `scan_delay_ms` | integer | delay between probes to one host |
| `reverse_dns` | bool | look up hostnames |
| `adaptive` | bool | adjust timing from observed latency and loss |

Port selectors take one of three forms:

```toml
ports = "top:1000"                # the 1000 highest ranked ports
ports = "preset:web"              # a named preset
ports = "22,80,443,8000-9000"     # an explicit specification
```

### Built in profiles

| Name | What it does |
| --- | --- |
| `quick` | top 100 TCP ports, fast timing, no service detection |
| `full` | top 1000 TCP ports with service, version and OS detection |
| `thorough` | all TCP ports, top 100 UDP ports, all detection enabled |
| `web` | HTTP and HTTPS ports with service, version and TLS inspection |
| `database` | common database ports with service and version detection |
| `discovery` | find which hosts are up, without scanning ports |
| `stealth` | SYN scan where available, no discovery, no probes, slow serial timing |

Defining a profile with a built in name replaces it.

## Limits

These are the guard rails. They exist so that a mistyped target cannot turn into a scan of the internet, and so that a scan cannot exhaust memory or file descriptors on the machine running it.

| Key | Default | Meaning |
| --- | --- | --- |
| `max_targets` | 65536 | most addresses a scan may expand to |
| `max_ports_per_host` | 131070 | most ports per host, across both transports |
| `max_total_probes` | 20000000 | most individual port probes in one scan |
| `max_concurrency` | 20000 | ceiling on in flight probes, whatever is requested |
| `max_response_bytes` | 65536 | most bytes read from one banner or probe response |
| `event_buffer` | 4096 | results buffered before the engine slows its workers |

Exceeding a limit stops the scan before it starts, with a message naming the limit and what to change. Raise them knowing why you are raising them.

## Environment variables

| Variable | Effect |
| --- | --- |
| `NETSCAN_CONFIG` | path to a configuration file |
| `NO_COLOR` | disable colour, as does `--no-colour` |
| `XDG_CONFIG_HOME` | changes where the file is looked for on Linux |

## Checking what is in effect

```sh
netscan --list-profiles          # profiles, built in and yours
netscan --list-interfaces        # what netscan can send from
netscan --debug 127.0.0.1        # the resolved configuration for one scan
```
