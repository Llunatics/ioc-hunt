"""Tests for ioc_hunt: extraction, defanging, filtering, CLI, performance."""
import io
import json
import os
import sys
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ioc_hunt
from ioc_hunt import (extract, extract_host, is_benign_domain, main, refang,
                      render_table)

ALL = set(ioc_hunt.TYPE_ORDER)


def get(text, types=ALL, **kw):
    return extract(text, set(types), **kw)


class TestRefang(unittest.TestCase):
    def test_dot_brackets(self):
        self.assertEqual(refang("1.2.3[.]4"), "1.2.3.4")

    def test_hxxp(self):
        self.assertEqual(refang("hxxp://evil.com"), "http://evil.com")
        self.assertEqual(refang("hxxps://evil.com"), "https://evil.com")
        self.assertEqual(refang("HXXP://EVIL.COM"), "http://EVIL.COM")

    def test_at_brackets(self):
        self.assertEqual(refang("a[@]b.com"), "a@b.com")


class TestExtractTypes(unittest.TestCase):
    def test_ipv4(self):
        r = get("from 45.155.204.9 ok", {"ipv4"})
        self.assertEqual(r, {("ipv4", "45.155.204.9"): 1})

    def test_ipv4_invalid_octet_skipped(self):
        self.assertEqual(get("999.999.999.999", {"ipv4"}), {})

    def test_ipv4_private_skipped_by_default(self):
        self.assertEqual(get("10.0.0.5 192.168.1.1 172.16.0.1", {"ipv4"}), {})

    def test_ipv4_private_with_flag(self):
        r = get("10.0.0.5", {"ipv4"}, include_private=True)
        self.assertEqual(r, {("ipv4", "10.0.0.5"): 1})

    def test_ipv6_forms(self):
        r = get("a 2606:4700:4700::1111 b ::ffff:45.155.204.9", {"ipv6"})
        vals = {v for (_, v) in r}
        self.assertIn("2606:4700:4700::1111", vals)
        # IPv4-mapped addresses are canonicalized by ipaddress (.compressed).
        self.assertIn("::ffff:2d9b:cc09", vals)

    def test_ipv6_documentation_range_treated_as_private(self):
        # 2001:db8::/32 (TEST-NET) is_private per ipaddress -> skipped
        # unless --include-private, same as other non-routable ranges.
        self.assertEqual(get("2001:db8::1", {"ipv6"}), {})
        r = get("2001:db8::1", {"ipv6"}, include_private=True)
        self.assertEqual(r, {("ipv6", "2001:db8::1"): 1})

    def test_ipv6_loopback_skipped(self):
        self.assertEqual(get("::1", {"ipv6"}), {})
        r = get("::1", {"ipv6"}, include_private=True)
        self.assertEqual(r, {("ipv6", "::1"): 1})

    def test_domain(self):
        r = get("evil.example.net", {"domain"})
        self.assertEqual(r, {("domain", "evil.example.net"): 1})

    def test_domain_lowercased(self):
        r = get("EVIL.EXAMPLE.NET", {"domain"})
        self.assertEqual(r, {("domain", "evil.example.net"): 1})

    def test_benign_domain_skipped(self):
        self.assertEqual(get("www.google.com", {"domain"}), {})
        self.assertEqual(get("sub.github.com", {"domain"}), {})
        # ...tapi domain jahat yang mirip tetap kena
        r = get("google.com.evil.com", {"domain"})
        self.assertEqual(r, {("domain", "google.com.evil.com"): 1})

    def test_url(self):
        r = get("see http://evil.com/a?x=1.", {"url"})
        self.assertEqual(r, {("url", "http://evil.com/a?x=1"): 1})

    def test_url_benign_host_skipped(self):
        self.assertEqual(get("https://www.google.com/search", {"url"}), {})

    def test_url_host_not_double_counted_as_domain(self):
        r = get("http://evil.com/x", {"url", "domain"})
        self.assertNotIn(("domain", "evil.com"), r)
        self.assertIn(("url", "http://evil.com/x"), r)

    def test_url_with_userinfo_host_folded(self):
        r = get("http://user:pass@evil.com:8080/x evil.com",
                {"url", "domain"})
        self.assertIn(("url", "http://user:pass@evil.com:8080/x"), r)
        self.assertNotIn(("domain", "evil.com"), r)

    def test_email(self):
        r = get("contact soc@evil.net ok", {"email"})
        self.assertEqual(r, {("email", "soc@evil.net"): 1})

    def test_hashes(self):
        md5, sha1, sha256 = "a" * 32, "b" * 40, "c" * 64
        r = get(f"{md5} {sha1} {sha256}", {"md5", "sha1", "sha256"})
        self.assertEqual(r[("md5", md5)], 1)
        self.assertEqual(r[("sha1", sha1)], 1)
        self.assertEqual(r[("sha256", sha256)], 1)

    def test_hash_inside_longer_hex_not_split(self):
        # 40-char sha1 tidak boleh dicacah sebagai md5 parsial
        r = get("b" * 40, {"md5", "sha1"})
        self.assertNotIn(("md5", "b" * 32), r)
        self.assertEqual(r[("sha1", "b" * 40)], 1)

    def test_cve_normalized_uppercase(self):
        r = get("cve-2021-44228 and CVE-2021-44228", {"cve"})
        self.assertEqual(r, {("cve", "CVE-2021-44228"): 2})

    def test_defanged_end_to_end(self):
        r = get("185.220[.]101[.]4 hxxp://malware-drop[.]ru/payload.exe",
                {"ipv4", "url"})
        self.assertIn(("ipv4", "185.220.101.4"), r)
        self.assertIn(("url", "http://malware-drop.ru/payload.exe"), r)

    def test_dedup_counts(self):
        r = get("1.2.3.4 1.2.3.4 1.2.3.4", {"ipv4"})
        self.assertEqual(r[("ipv4", "1.2.3.4")], 3)

    def test_wanted_subset(self):
        r = get("1.2.3.4 evil.com", {"domain"})
        self.assertEqual(set(t for t, _ in r), {"domain"})


class TestExtractHost(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(extract_host("http://example.com/a"), "example.com")

    def test_port_stripped(self):
        self.assertEqual(extract_host("http://example.com:8080/a"),
                         "example.com")

    def test_userinfo_stripped(self):
        self.assertEqual(extract_host("http://user:pass@example.com/a"),
                         "example.com")

    def test_ipv6(self):
        self.assertEqual(extract_host("http://[::1]:8080/a"), "[::1]")


class TestBenign(unittest.TestCase):
    def test_exact_and_subdomain(self):
        self.assertTrue(is_benign_domain("google.com"))
        self.assertTrue(is_benign_domain("WWW.GOOGLE.COM"))
        self.assertTrue(is_benign_domain("a.b.microsoft.com"))
        self.assertFalse(is_benign_domain("google.com.evil.com"))
        self.assertFalse(is_benign_domain("evil.com"))


class TestRenderTable(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(render_table([]), "No IOCs found.")

    def test_shape(self):
        out = render_table([("ipv4", "1.2.3.4", 2)])
        self.assertIn("1.2.3.4", out)
        self.assertIn("1 unique IOC(s)", out)


class TestMain(unittest.TestCase):
    def _run(self, argv, stdin_text=None):
        import ioc_hunt as m
        old_stdin = sys.stdin
        if stdin_text is not None:
            sys.stdin = io.StringIO(stdin_text)
        try:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = m.main(argv)
        finally:
            sys.stdin = old_stdin
        return rc, out.getvalue(), err.getvalue()

    def test_file_json(self):
        rc, out, _ = self._run(["--json", "tests/sample.log"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        by = {(d["type"], d["value"]): d["count"] for d in data}
        self.assertEqual(by[("ipv4", "45.155.204.9")], 3)
        self.assertEqual(len(data), 12)

    def test_types_alias(self):
        rc, out, _ = self._run(["--types", "ip", "--json",
                                "tests/sample.log"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertTrue(all(d["type"] in ("ipv4", "ipv6") for d in data))

    def test_unknown_type(self):
        rc, _, err = self._run(["--types", "bogus", "tests/sample.log"])
        self.assertEqual(rc, 1)
        self.assertIn("unknown type", err)

    def test_min_count(self):
        rc, out, _ = self._run(["--min-count", "3", "--json",
                                "tests/sample.log"])
        data = json.loads(out)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["value"], "45.155.204.9")

    def test_csv(self):
        rc, out, _ = self._run(["--csv", "tests/sample.log"])
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("type,value,count"))

    def test_stdin(self):
        rc, out, _ = self._run(["--json"], stdin_text="evil.com 1.2.3.4")
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(len(data), 2)

    def test_missing_file(self):
        rc, _, err = self._run(["/tidak/ada.log"])
        self.assertEqual(rc, 1)
        self.assertIn("not found", err)

    def test_min_count_invalid(self):
        rc, _, err = self._run(["--min-count", "0", "tests/sample.log"])
        self.assertEqual(rc, 1)

    def test_sample_golden(self):
        # Golden test: sample.log must keep producing the documented output.
        rc, out, _ = self._run(["tests/sample.log"])
        self.assertEqual(rc, 0)
        self.assertIn("12 unique IOC(s)", out)
        for needle in ("45.155.204.9", "CVE-2026-104935", "login-secure.tk",
                       "185.220.101.4",
                       "5d41402abc4b2a76b9719d911017c592",
                       "http://malware-drop.ru/payload.exe"):
            self.assertIn(needle, out)


class TestPerformance(unittest.TestCase):
    def test_large_input_fast(self):
        lines = ["hit %d from 45.155.204.9 evil%d.example.net "
                 "http://c2.example.net/b" % (i, i) for i in range(3000)]
        t0 = time.time()
        extract("\n".join(lines), ALL)
        self.assertLess(time.time() - t0, 10)


if __name__ == "__main__":
    unittest.main()


class TestReDoS(unittest.TestCase):
    def test_domain_repetitive_input_fast(self):
        # Regression: the old single-regex domain pattern took 0.6s for
        # 4k chars of "a.a.a..." (quadratic backtracking).
        t0 = time.time()
        list(ioc_hunt.PATTERNS["domain"].finditer("a." * 20000))
        self.assertLess(time.time() - t0, 2)

    def test_all_patterns_adversarial_fast(self):
        evil = {
            "url": "http://" + "a/" * 8000,
            "email": "a@" * 8000 + "b.com",
            "ipv6": ":" * 16000,
            "ipv4": "1" * 16000 + ".",
            "md5": "f" * 30000,
            "cve": "CVE-" + "1" * 16000,
        }
        t0 = time.time()
        for name, s in evil.items():
            list(ioc_hunt.PATTERNS[name].finditer(s))
        self.assertLess(time.time() - t0, 10)

    def test_extract_pathological_fast(self):
        t0 = time.time()
        extract("a." * 20000 + "\n" + "1." * 10000, ALL)
        self.assertLess(time.time() - t0, 5)


class TestMainErrors(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_file_is_directory(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc, _, err = self._run([d])
            self.assertEqual(rc, 1)
            self.assertIn("not a file", err)


class TestSigpipe(unittest.TestCase):
    def test_broken_pipe_no_traceback(self):
        import signal
        self.assertEqual(signal.getsignal(signal.SIGPIPE), signal.SIG_DFL)


class TestTypesValidation(unittest.TestCase):
    def test_unknown_type_errors(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["--types", "domain,bogus", "tests/sample.log"])
        self.assertNotEqual(rc, 0)
        self.assertIn("unknown type", err.getvalue())

    def test_valid_types_subset(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["--types", "ipv4", "tests/sample.log"])
        self.assertEqual(rc, 0)
        self.assertIn("ipv4", out.getvalue())


class TestIncludePrivate(unittest.TestCase):
    def _run(self, argv, inp):
        import io as _io
        old = sys.stdin
        sys.stdin = _io.StringIO(inp)
        try:
            buf = _io.StringIO()
            with redirect_stdout(buf), redirect_stderr(_io.StringIO()):
                rc = main(argv)
            return rc, buf.getvalue()
        finally:
            sys.stdin = old

    def test_private_filtered_by_default(self):
        rc, out = self._run([], "host 192.168.1.5 dan 45.155.204.9\n")
        self.assertEqual(rc, 0)
        self.assertNotIn("192.168.1.5", out)
        self.assertIn("45.155.204.9", out)

    def test_include_private_flag(self):
        rc, out = self._run(["--include-private"], "host 192.168.1.5\n")
        self.assertEqual(rc, 0)
        self.assertIn("192.168.1.5", out)
