# ioc-hunt

Extract Indicators of Compromise (IOCs) from raw log/text. Stdlib-only Python CLI — no dependencies.

## Features

- Extracts IPv4, IPv6, domains, URLs, emails, MD5/SHA1/SHA256 hashes, CVE IDs
- Detects defanged IOCs (`1.2.3[.]4`, `hxxp://`, `example[.]com`) and reports the refanged form
- De-duplicates and counts occurrences
- Whitelists private/loopback IPs and common benign domains (editable list in source)
- `--include-private` to also report internal IPs when pivoting on local logs
- Output as ASCII table, JSON, or CSV

## Install

```bash
git clone https://github.com/Llunatics/ioc-hunt.git
cd ioc-hunt
chmod +x ioc_hunt.py
```

Requires Python 3.8+. No pip packages.

## Usage

```bash
# from a file
./ioc_hunt.py /var/log/auth.log

# from a pipe
cat firewall.log | ./ioc_hunt.py

# JSON / CSV output
./ioc_hunt.py --json auth.log > iocs.json
./ioc_hunt.py --csv auth.log > iocs.csv

# filter by type (aliases: ip = ipv4+ipv6, hash = md5+sha1+sha256)
./ioc_hunt.py --types ip,domain auth.log

# only IOCs seen at least 3 times
./ioc_hunt.py --min-count 3 auth.log

# include private/loopback/link-local IPs (skipped by default)
./ioc_hunt.py --include-private auth.log
```

## Example

```
$ ./ioc_hunt.py tests/sample.log
+--------+----------------------------------+-------+
| type   | value                            | count |
+--------+----------------------------------+-------+
| ipv4   | 45.155.204.9                     |     3 |
| cve    | CVE-2026-104935                  |     2 |
| domain | login-secure.tk                  |     2 |
| ipv4   | 185.220.101.4                    |     2 |
| md5    | 5d41402abc4b2a76b9719d911017c592 |     2 |
...
+--------+----------------------------------+-------+
12 unique IOC(s)
```

## IOC types

| Type | Matches | Notes |
|------|---------|-------|
| `ipv4` | `45.155.204.9` | validated octets; private/loopback skipped unless `--include-private` |
| `ipv6` | `2606:4700:4700::1111`, `::1` | `::` compression (incl. leading `::`) and IPv4-mapped forms supported; private/link-local skipped unless `--include-private` |
| `domain` | `evil.example.net` | benign domains (`google.com`, `microsoft.com`, …) skipped |
| `url` | `http://x/y` | host folded in — not double-counted as domain |
| `email` | `soc@evil.example.net` | same host-folding as URL |
| `md5` / `sha1` / `sha256` | hex strings 32/40/64 | case-insensitive |
| `cve` | `CVE-2026-104935` | normalized to uppercase, case-insensitive dedup |

Defanged input (`185.220[.]101[.]4`, `hxxp://…`, `soc[@]…`) is refanged before matching and merged with its plain form.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | success |
| `1` | input/usage error (file not found, bad `--types`, …) |
| `130` | interrupted with Ctrl-C |

## Whitelist

Edit `BENIGN_DOMAINS` in `ioc_hunt.py` to add/remove trusted domains. Private IP ranges are handled via `ipaddress` (no list to maintain).

## License

MIT
