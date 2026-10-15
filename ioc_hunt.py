#!/usr/bin/env python3
"""ioc-hunt: extract Indicators of Compromise from raw text/log.

Reads a text file or stdin, extracts IPv4, IPv6, domains, URLs, hashes
(MD5/SHA1/SHA256), emails and CVE IDs, de-duplicates them, counts
occurrences and prints a tidy table (or JSON/CSV).

Stdlib only. Exit codes: 0 = success, 1 = input/usage error.
Ctrl-C exits gracefully (130).
"""

import argparse
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
    # domain must come after url/email so hosts are not double counted
    "domain": re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,}\b"
    ),
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
    m = re.match(r"https?://([^/:?\s]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else ""


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------
def extract(text: str, wanted: set, refanged_text: str | None = None,
            include_private: bool = False) -> dict:
    """Return {(type, value): count} for the wanted IOC types.

    Matching always runs on the refanged copy of the text; spans are
    consistent within that copy, so the original is not needed here.
    """
    counts: dict[tuple[str, str], int] = {}
    consumed: set[tuple[int, int]] = set()  # spans claimed by earlier types

    src = refanged_text if refanged_text is not None else text

    seen_hosts: set[str] = set()  # hosts already reported via url/email

    # Always claim URL/email spans first so their hosts are never reported
    # as bare domains, even when url/email are not in the wanted types.
    for itype in ("url", "email"):
        for m in PATTERNS[itype].finditer(src):
            start, end = m.span()
            # skip spans claimed by another match (same-span reclaim is fine)
            if any(s < end and start < e and (s, e) != (start, end)
                   for s, e in consumed):
                continue
            value = strip_trailing(m.group(0))
            if itype == "url":
                host = extract_host(value)
                if host and not is_benign_domain(host):
                    seen_hosts.add(host)
            else:
                host = value.split("@", 1)[1].lower() if "@" in value else ""
                if host and not is_benign_domain(host):
                    seen_hosts.add(host)
            consumed.add((start, end))

    for itype in TYPE_ORDER:
        if itype not in wanted:
            continue
        for m in PATTERNS[itype].finditer(src):
            start, end = m.span()
            # skip spans claimed by another match (same-span reclaim is fine)
            if any(s < end and start < e and (s, e) != (start, end)
                   for s, e in consumed):
                continue
            value = strip_trailing(m.group(0))

            if itype == "cve":
                value = value.upper()

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
                if not host or is_benign_domain(host):
                    continue
                seen_hosts.add(host)
            elif itype == "email":
                host = value.split("@", 1)[1].lower()
                if is_benign_domain(host):
                    continue
                seen_hosts.add(host)
            elif itype == "domain":
                dom = value.lower().rstrip(".")
                if is_benign_domain(dom) or dom in seen_hosts:
                    continue
                value = dom

            consumed.add((start, end))
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
    counts = extract(text, wanted, refang(text),
                     include_private=args.include_private)

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
