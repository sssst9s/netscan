# Output formats

Every format carries the same scan. Text is for reading, the rest are for machines.

```sh
netscan target                  # text, the default
netscan target --json
netscan target --jsonl
netscan target --csv
netscan target --xml
netscan target -o scan.json     # format inferred from the extension
netscan target --csv -o out.txt # format given explicitly
```

## Text

Tables with box drawing borders, colour when the output is a terminal, and a summary at the end.

```
127.0.0.1 (localhost)
  ╭──────────┬───────┬─────────┬──────────────┬─────────╮
  │ PORT     │ STATE │ SERVICE │ VERSION      │ DETAILS │
  ├──────────┼───────┼─────────┼──────────────┼─────────┤
  │ 22/tcp   │ open  │ ssh     │ OpenSSH 10.3 │         │
  │ 5000/tcp │ open  │ upnp    │              │         │
  ╰──────────┴───────┴─────────┴──────────────┴─────────╯
  Not shown: 1 closed
```

Closed and filtered ports are summarised rather than listed, because a scan of 1000 ports that found 3 open should not print 997 lines. `--show-all-ports` lists them.

`--table` picks the border style: `auto`, `rounded`, `square`, `ascii` or `plain`. `auto` uses box drawing when the terminal supports it and ASCII when it does not. Colour follows `NO_COLOR`, `--no-colour` and whether output is a terminal, and can be forced with `--colour`.

## JSON

One document per scan, with a `schema_version` at the top so a consumer can tell which shape it is reading.

```json
{
  "schema_version": 1,
  "tool": { "name": "netscan", "version": "0.1.0" },
  "scan_id": "20260814T042839Z-1cec73",
  "started_at": "2026-08-14T04:28:39.744055Z",
  "finished_at": "2026-08-14T04:28:39.807441Z",
  "outcome": "completed",
  "parameters": {
    "targets": ["127.0.0.1"],
    "ports": "22",
    "transports": ["tcp"],
    "tcp_mode": "connect",
    "timing": "normal",
    "concurrency": 512,
    "service_detection": false,
    "os_detection": false
  },
  "hosts": [
    {
      "address": "127.0.0.1",
      "hostnames": [{ "name": "localhost", "source": "reverse-dns" }],
      "status": "up",
      "status_reason": "host discovery disabled",
      "ports": [
        {
          "port": 22,
          "transport": "tcp",
          "state": "open",
          "reason": "connection-established",
          "rtt_ms": 0.743292,
          "service": {
            "name": "ssh",
            "product": "OpenSSH",
            "version": "10.3",
            "source": { "kind": "banner" },
            "confidence": "medium"
          },
          "banner": "SSH-2.0-OpenSSH_10.3\\n",
          "attempts": 1
        }
      ],
      "not_scanned": 0,
      "started_at": "2026-08-14T04:28:39.745545Z",
      "finished_at": "2026-08-14T04:28:39.807426Z"
    }
  ],
  "stats": {
    "hosts_total": 1,
    "hosts_up": 1,
    "hosts_down": 0,
    "probes_sent": 1,
    "ports_tested": 1,
    "ports_open": 1,
    "ports_closed": 0,
    "ports_filtered": 0,
    "retries": 0,
    "errors": 0,
    "duration_ms": 65,
    "mean_rtt_ms": 0.644833
  }
}
```

`outcome` is `completed`, `cancelled` or `failed`. A cancelled scan still writes everything it found, so partial results are never lost.

This is the format the desktop application reads and writes, and the one `--compare` expects.

### Field notes

| Field | Notes |
| --- | --- |
| `state` | `open`, `closed`, `filtered`, `open\|filtered` or `unknown` |
| `reason` | why netscan decided that, such as `connection-established` or `no-response` |
| `confidence` | `high`, `medium` or `low`, on every detection result |
| `source` | how a service was identified: `banner`, `probe`, `port-number`, `tls` |
| `os` | present only when `--os-detection` ran, and carries its evidence |
| `not_scanned` | ports the scan did not reach, so absence is never mistaken for closed |

## JSON Lines

One JSON object per line, so a long scan can be streamed and processed as it runs. The first line is the scan header, then one line per host, then a trailer with the statistics.

```sh
netscan 192.168.1.0/24 --jsonl | jq -c 'select(.type == "host" and .status == "up")'
```

## CSV

One row per port, with the host repeated on each row, which is what a spreadsheet wants.

```
address,hostname,host_status,host_rtt_ms,mac,vendor,os_family,os_confidence,port,transport,state,reason,port_rtt_ms,service,product,version,tls,tls_subject,tls_expires,detection_source,confidence,banner,scan_id,started_at
127.0.0.1,localhost,up,,,,,,5000,tcp,open,connection-established,1.15,upnp,,,false,,,port-number,low,,20260814T042757Z-387f11,2026-08-14T04:27:57.429763+00:00
```

Fields containing a comma, a quote or a newline are quoted and escaped. Banners are escaped so a hostile banner cannot break the row structure.

## XML

For pipelines that already consume XML.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<netscan version="0.1.0" schema="1" scan_id="20260814T042847Z-882785" outcome="completed">
  <parameters>
    <target>127.0.0.1</target>
    <ports>22</ports>
    <transport>tcp</transport>
  </parameters>
  <hosts>
    <host address="127.0.0.1" status="up">
      <hostname source="reversedns">localhost</hostname>
      <ports>
        <port number="22" transport="tcp" state="open" reason="connection-established" rtt_ms="0.21">
          <service name="ssh" source="banner" confidence="medium" tls="false" product="OpenSSH" version="10.3"/>
          <banner>SSH-2.0-OpenSSH_10.3\n</banner>
        </port>
      </ports>
    </host>
  </hosts>
</netscan>
```

It is netscan's own schema, not Nmap's. Text content and attribute values are escaped.

## Stability

`schema_version` is 1. Fields will be added within version 1; existing fields will not change meaning or disappear. A change that would break a reader comes with a new version number.
