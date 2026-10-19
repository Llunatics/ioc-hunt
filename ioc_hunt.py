#!/usr/bin/env python3
"""ioc-hunt: extract Indicators of Compromise from raw text/log.

Reads a text file or stdin, extracts IPv4, IPv6, domains, URLs, hashes
(MD5/SHA1/SHA256), emails and CVE IDs, de-duplicates them, counts
occurrences and prints a tidy table (or JSON/CSV).

Stdlib only. Exit codes: 0 = success, 1 = input/usage error.
Ctrl-C exits gracefully (130).
"""

import argparse
import bisect
import csv
import io
import ipaddress
import json
import re
import sys

VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# Defang handling
# ---------------------------------------------------------------------------
# Defanged forms analysts use to avoid accidental clicks:
#   1.2.3[.]4   10[.]0[.]0[.]1   hxxp://x   hxxps://x
#   example[.]com   user[@]example[.]com
DEFANG_DOT = re.compile(r"\[\.\]")
DEFANG_AT = re.compile(r"\[@\]")


def refang(text: str) -> str:
    """Restore a defanged string to its normal form."""
    text = DEFANG_DOT.sub(".", text)
    text = DEFANG_AT.sub("@", text)
    text = re.sub(r"(?i)\bhxxp(s?)://", r"http\1://", text)
    return text


def _valid_label(label: str) -> bool:
    return (1 <= len(label) <= 63 and label[0].isalnum()
            and label[-1].isalnum()
            and all(c.isalnum() or c == "-" for c in label))


def _valid_tld(tld: str) -> bool:
    return len(tld) >= 2 and all("a" <= c <= "z" or "A" <= c <= "Z"
                                 for c in tld)


class _MatchSpan:
    """Minimal re.Match stand-in: only span() and group(0) are used."""
    __slots__ = ("_start", "_end", "_text")

    def __init__(self, start: int, end: int, text: str):
        self._start = start
        self._end = end
        self._text = text

    def span(self):
        return (self._start, self._end)

    def start(self):
        return self._start

    def end(self):
        return self._end

    def group(self, n=0):
        assert n == 0
        return self._text


class _DomainFinder:
    """Linear-time domain matcher.

    The naive single-regex domain pattern
    (?:label\\.)+[A-Za-z]{2,} backtracks catastrophically on repetitive
    input like "a.a.a.a…" (0.6s for 4k chars → minutes for real logs).
    Instead: match maximal dot-separated runs with a simple linear regex,
    then validate labels in Python (O(n) total, zero backtracking).
    """

    _run = re.compile(
        r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
        r"(?:\.(?!\.)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
    )

    def finditer(self, text):
        for m in self._run.finditer(text):
            run = m.group(0)
            if "." not in run:
                continue
            labels = run.split(".")
            if not _valid_tld(labels[-1]):
                continue
            if not all(_valid_label(l) for l in labels):
                continue
            yield _MatchSpan(m.start(), m.end(), run)


# ---------------------------------------------------------------------------
# IOC patterns (applied to refanged text)
# ---------------------------------------------------------------------------
PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "url": re.compile(
        r"\bhttps?://[^\s<>'\"()\[\]{}]+", re.IGNORECASE
    ),
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    # IPv6: at least two colons required by the pattern itself (covers ::1,
    # ::ffff:1.2.3.4, 2001:db8::1). Lookarounds instead of \b so addresses
    # starting with ':' are still found; ipaddress does the real validation.
    "ipv6": re.compile(
        r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*(?![\w:])"
    ),
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    # domain: matched by _DomainFinder (linear time), not a single regex —
    # the classic (?:label\.)+[A-Za-z]{2,} pattern backtracks
    # catastrophically on repetitive input ("a.a.a.a…").
    "domain": _DomainFinder(),
}

# Shorthand aliases accepted by --types
TYPE_ALIASES = {
    "ip": {"ipv4", "ipv6"},
    "hash": {"md5", "sha1", "sha256"},
}

# Extraction order: specific types first so a URL is not also reported
# as domain/ipv4/email. Domains that are the host part of a URL or email
# are dropped afterwards.
TYPE_ORDER = ["cve", "url", "email", "ipv4", "ipv6", "md5", "sha1", "sha256", "domain"]

# Common benign domains — edit freely. Entries match the domain itself
# and any subdomain of it.
BENIGN_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "facebook.com",
    "github.com",
    "amazon.com",
    "cloudflare.com",
    "akamai.com",
    "w3.org",
    "ietf.org",
    "iana.org",
    "example.com",
    "windowsupdate.com",
    "digicert.com",
}

TRAILING_PUNCT = ".,;:!?\"')]}>"


def strip_trailing(value: str) -> str:
    return value.rstrip(TRAILING_PUNCT)


def is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback


def valid_ipv4(value: str) -> bool:
    try:
        parts = value.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def is_benign_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == b or d.endswith("." + b) for b in BENIGN_DOMAINS)


def extract_host(url: str) -> str:
    m = re.match(r"https?://([^/\s?#]+)", url, re.IGNORECASE)
    if not m:
        return ""
    host = m.group(1).rsplit("@", 1)[-1]  # strip userinfo
    if host.startswith("["):              # IPv6 literal: [::1]:8080
        host = host.split("]", 1)[0] + "]"
    else:
        host = host.split(":", 1)[0]      # strip port
    return host.lower().rstrip(".")


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------
def extract(text: str, wanted: set,
            include_private: bool = False) -> dict:
    """Return {(type, value): count} for the wanted IOC types.

    Matching always runs on the refanged copy of the text.
    """
    counts: dict[tuple[str, str], int] = {}
    src = refang(text)

    # Kumpulkan semua kandidat lalu sapu terurut berdasarkan posisi.
    # Klaim berjalan dalam urutan start menaik; di antara span yang
    # berawalan sama, yang terpanjang + url/email didahulukan supaya host
    # URL/email tidak pernah dilaporkan sebagai domain polos.
    # (start, -end, priority, itype, match)
    cands: list[tuple[int, int, int, str, re.Match]] = []
    for itype, prio in (("url", 0), ("email", 1)):
        for m in PATTERNS[itype].finditer(src):
            cands.append((m.start(), -m.end(), prio, itype, m))
    for itype in TYPE_ORDER:
        if itype not in wanted or itype in ("url", "email"):
            continue  # url/email sudah ditambahkan di loop pertama
        for m in PATTERNS[itype].finditer(src):
            cands.append((m.start(), -m.end(), 2, itype, m))
    cands.sort(key=lambda c: (c[0], c[1], c[2]))

    # Span yang sudah diklaim, selalu terurut menaik berdasarkan start
    # (append sesuai urutan sapu) -> cek overlap O(log n) via bisect.
    claimed: list[tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        i = bisect.bisect_left(claimed, (start, end))
        if i > 0:
            s, e = claimed[i - 1]
            # claimed[i-1] mulai di/di bawah `start`: s < end otomatis.
            if (s, e) != (start, end) and start < e:
                return True
        j = i
        while j < len(claimed) and claimed[j][0] < end:
            if claimed[j] != (start, end):
                return True
            j += 1
        return False

    seen_hosts: set[str] = set()  # hosts already reported via url/email

    for start, neg_end, _prio, itype, m in cands:
        end = -neg_end
        if overlaps(start, end):
            continue
        value = strip_trailing(m.group(0))

        if itype == "cve":
            value = value.upper()

        # Validate per type. Invalid values are dropped WITHOUT claiming
        # the span (same as before); url/email spans are always claimed so
        # their hosts are never double-reported as bare domains.
        count_it = itype in wanted
        if itype == "ipv4":
            if not valid_ipv4(value):
                continue
            if not include_private and is_private_ip(value):
                continue
        elif itype == "ipv6":
            if value.count(":") < 2:
                continue
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not include_private and (
                addr.is_private or addr.is_loopback or addr.is_link_local
            ):
                continue
            value = addr.compressed
        elif itype == "url":
            host = extract_host(value)
            if host and not is_benign_domain(host):
                seen_hosts.add(host)
            else:
                count_it = False  # benign/empty host: claimed, not counted
        elif itype == "email":
            host = value.split("@", 1)[1].lower() if "@" in value else ""
            if host and not is_benign_domain(host):
                seen_hosts.add(host)
            else:
                count_it = False
        elif itype == "domain":
            dom = value.lower().rstrip(".")
            if is_benign_domain(dom) or dom in seen_hosts:
                continue
            value = dom

        claimed.append((start, end))  # urutan sapu = selalu terurut
        if count_it:
            key = (itype, value)
            counts[key] = counts.get(key, 0) + 1

    return counts


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def render_table(rows: list[tuple[str, str, int]]) -> str:
    if not rows:
        return "No IOCs found."
    w_type = max(len("type"), max(len(t) for t, _, _ in rows))
    w_val = max(len("value"), max(len(v) for _, v, _ in rows))
    w_cnt = max(len("count"), max(len(str(c)) for _, _, c in rows))
    line = f"+-{'-' * w_type}-+-{'-' * w_val}-+-{'-' * w_cnt}-+"
    out = [line]
    out.append(f"| {'type'.ljust(w_type)} | {'value'.ljust(w_val)} | {'count'.rjust(w_cnt)} |")
    out.append(line)
    for t, v, c in rows:
        out.append(f"| {t.ljust(w_type)} | {v.ljust(w_val)} | {str(c).rjust(w_cnt)} |")
    out.append(line)
    out.append(f"{len(rows)} unique IOC(s)")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ioc-hunt",
        description=(
            "Extract Indicators of Compromise (IPs, domains, URLs, hashes, "
            "emails, CVE IDs) from a log/text file or stdin. Defanged IOCs "
            "like 1.2.3[.]4 or hxxp:// are detected and refanged."
        ),
    )
    parser.add_argument(
        "file", nargs="?",
        help="input file (omit to read from stdin)",
    )
    parser.add_argument(
        "--types", default="",
        help="comma-separated IOC types to extract "
             "(cve,url,email,ipv4,ipv6,md5,sha1,sha256,domain; "
             "aliases: ip=ipv4+ipv6, hash=md5+sha1+sha256). Default: all",
    )
    parser.add_argument(
        "--min-count", type=int, default=1, metavar="N",
        help="only show IOCs seen at least N times (default: 1)",
    )
    parser.add_argument(
        "--include-private", action="store_true",
        help="also report private/loopback/link-local IPs "
             "(skipped by default)",
    )
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument(
        "--json", action="store_true",
        help="output as JSON array",
    )
    fmt.add_argument(
        "--csv", action="store_true",
        help="output as CSV",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {VERSION}",
    )
    args = parser.parse_args(argv)

    if args.min_count < 1:
        print("error: --min-count must be >= 1", file=sys.stderr)
        return 1

    if args.types:
        wanted = {t.strip().lower() for t in args.types.split(",") if t.strip()}
        expanded: set[str] = set()
        for t in wanted:
            expanded |= TYPE_ALIASES.get(t, {t})
        wanted = expanded
        unknown = wanted - set(TYPE_ORDER)
        if unknown:
            print(f"error: unknown type(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            print(f"valid types: {', '.join(TYPE_ORDER)} (aliases: ip, hash)", file=sys.stderr)
            return 1
    else:
        wanted = set(TYPE_ORDER)

    # --- read input ---
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except FileNotFoundError:
            print(f"error: file not found: {args.file}", file=sys.stderr)
            return 1
        except IsADirectoryError:
            print(f"error: not a file: {args.file}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
            return 1
    else:
        if sys.stdin.isatty():
            print("error: no input file and stdin is a terminal (nothing to read)",
                  file=sys.stderr)
            parser.print_usage(sys.stderr)
            return 1
        text = sys.stdin.read()

    # --- extract (on refanged copy; spans are consistent within it) ---
    counts = extract(text, wanted, include_private=args.include_private)

    rows = sorted(
        ((t, v, c) for (t, v), c in counts.items() if c >= args.min_count),
        key=lambda r: (-r[2], r[0], r[1]),
    )

    if args.json:
        print(json.dumps(
            [{"type": t, "value": v, "count": c} for t, v, c in rows],
            indent=2,
        ))
    elif args.csv:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["type", "value", "count"])
        writer.writerows(rows)
        print(buf.getvalue(), end="")
    else:
        print(render_table(rows))

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
