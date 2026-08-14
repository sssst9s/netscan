# Using netscan

`netscan --help` lists every option. This covers what each group is for and how they combine.

## Targets

```sh
netscan 192.168.1.1                      # one address
netscan example.com                      # a hostname
netscan 192.168.1.0/24                   # a CIDR block
netscan 10.0.0.1-50                      # a range in the last octet
netscan 192.168.1.1 10.0.0.0/24 host.tld # several at once
netscan -f targets.txt                   # one per line from a file
netscan -f - < targets.txt               # from standard input
netscan --local                          # the networks this machine is on
```

Exclusions take the same forms:

```sh
netscan 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254
netscan 10.0.0.0/16 --exclude-file do-not-scan.txt
```

IPv4 network and broadcast addresses are skipped when expanding a block. `--include-network-addresses` keeps them.

### Address family

`-4` scans IPv4 and is the default. `-6` scans IPv6. `--both` scans each family a target resolves to.

## Ports

```sh
netscan target                       # top 100, the default
netscan target -p 22                 # one port
netscan target -p 1-1024             # a range
netscan target -p 22,80,443,8000-900 # a list
netscan target -p T:80,443,U:53,161  # per transport
netscan target --top-ports 1000      # the N highest ranked
netscan target --preset web          # a named preset
netscan target -p-                   # every port
```

Presets: `common`, `web`, `database`, `remote-access`, and more. `--web`, `--database` and `--remote-access` are shorthand for the matching preset.

## Techniques

| Flag | Technique | Privileges |
| --- | --- | --- |
| `--connect` | full TCP connect, the default | none |
| `--syn` | half open SYN | raw sockets, and the `raw` build feature |
| `--udp` | UDP probes | none |
| `--ping` | discovery only, no port scan | none |

`--syn` on a build or a system that cannot do it falls back to a connect scan and prints a warning. It does not silently do something other than what you asked.

## Detection

```sh
netscan target -sV                     # service and version
netscan target --os-detection          # operating system and device type
netscan target --tls                   # TLS version, cipher, certificate
netscan target --max-intrusiveness 3   # cap how far probes go
netscan target --no-banner             # do not read banners at all
```

Note that `-sV` is the short form and `--sV` is the alias. `-sV` on its own parses as `-s -V`, which prints the version and exits.

Detection results carry a confidence level and the source they came from. An operating system is always presented as an inference with its evidence, never as a measurement.

## Discovery

By default netscan checks whether a host is up before scanning its ports, using ICMP echo, TCP ping and, on directly attached IPv4 networks, ARP.

```sh
netscan target --no-discovery      # treat every target as up
netscan target --no-icmp           # skip ICMP echo
netscan target --no-tcp-ping       # skip TCP ping
netscan target --ping-ports 80,443 # which ports TCP ping uses
```

Networks that drop ICMP and refuse connections to the ping ports will report hosts as down. `--no-discovery` is the answer, at the cost of scanning every address.

## Timing

```sh
netscan target -T aggressive     # a template
netscan target -c 500            # concurrency
netscan target --timeout 800     # connect timeout in milliseconds
netscan target -r 2              # retries for probes that time out
netscan target --max-rate 1000   # cap probes per second
netscan target --scan-delay 100  # delay between probes to one host
netscan target --host-timeout 30000
netscan target --no-adaptive     # fixed timing
```

Templates run from `sneaky` through `polite`, `normal`, `aggressive` and `insane`. Adaptive timing moves concurrency and timeouts within the bounds a template sets, based on observed latency and loss. Explicit flags override it.

Faster is not always quicker. A network that starts dropping probes under load produces retries and timeouts, and an aggressive scan of it can take longer than a polite one.

## Output

```sh
netscan target --json                    # to standard output
netscan target -o scan.json              # to a file, format from the extension
netscan target --csv -o results.txt      # format given explicitly
netscan target --show-down               # include hosts that did not answer
netscan target --show-all-ports          # list closed and filtered ports
netscan target -q                        # results only
netscan target -vv                       # more detail
netscan target --table ascii             # ASCII table borders
netscan target --no-colour
```

[OUTPUT.md](OUTPUT.md) documents the shape of each format.

## Comparing and watching

```sh
netscan --compare before.json after.json
netscan --watch 5m 192.168.1.0/24
netscan --watch 30s target --watch-rounds 10
netscan target --inventory inventory.json
```

`--compare` reports hosts that appeared or disappeared, ports that opened or closed and services whose version changed. `--watch` rescans on an interval and reports each round's changes as they happen. `--inventory` maintains a record across runs of what has been seen on a network and when.

## Profiles

```sh
netscan --list-profiles
netscan --profile full 192.168.1.0/24
```

Profiles bundle ports, timing and detection settings under a name. Define your own in `netscan.toml`; see [CONFIGURATION.md](CONFIGURATION.md).

## Safety

A scan that would expand past `max_targets` is refused before it starts. `--max-targets` raises the ceiling for one run and `--yes` confirms a scan large enough that netscan would otherwise decline it.

```sh
netscan 10.0.0.0/8 --max-targets 2000000 --yes
```

Think about what that command does before running it.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | the scan completed |
| 1 | the scan failed |
| 2 | the arguments were rejected |
| 130 | interrupted, with partial results written |

## Worked examples

Audit one server thoroughly and keep the record:

```sh
netscan server.internal -p- -sV --os-detection --tls -o audit.json
```

Find what is on the network you are attached to:

```sh
netscan --local --os-detection --show-down
```

Watch a network and get told when something changes:

```sh
netscan --watch 10m 192.168.1.0/24 --inventory office.json
```

Check whether anything changed after a maintenance window:

```sh
netscan 10.0.0.0/24 -o after.json
netscan --compare before.json after.json
```
