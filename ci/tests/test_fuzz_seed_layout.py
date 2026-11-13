#!/usr/bin/env python3
"""Verify committed scan seeds retain the complete nine-byte input layout."""

import re
from pathlib import Path

EXPECTED = {
    "confluence": b'${(#a=@java.lang.Runtime@getRuntime().exec("id"))}',
    "crlf": b"x%0d%0aset-cookie:evil",
    "exploit_path": b"/wls-wsat/coordinatorporttype",
    "imdsv2": b"/latest/api/token",
    "log4shell": b"${jndi:ldap://x/a}",
    "nullbyte": b"file.php%00.jpg",
    "overlong": b"/%c0%af%c0%af",
    "plain": b"GET /index.html normal request",
    "shellshock": b"() { :;}; /bin/bash -c id",
    "ssrf": b"169.254.169.254/latest/meta-data",
    "ssti": b"{{7*7}}",
    "struts": b"Content-Type: %{(#_=multipart/form-data)}",
    "traversal": b"../../../../etc/passwd",
    "traversal_enc": b"..%2f..%2f..%2fetc%2fpasswd",
    "union_select": b"id=1 union select username,password from users",
    "xss": b"<script>document.cookie</script>",
}
GENERATED_CORPUS_NAME = re.compile(r"[0-9a-f]{40}")


def named_seed_entries(root: Path) -> set[str]:
    return {
        path.name
        for path in root.iterdir()
        if GENERATED_CORPUS_NAME.fullmatch(path.name) is None
    }


def test_scan_seed_layout() -> None:
    root = Path(__file__).parents[2] / "ci/fuzz/corpus/fuzz_scan"
    assert named_seed_entries(root) == set(EXPECTED)
    for name, payload in EXPECTED.items():
        data = (root / name).read_bytes()
        assert data[:8] == bytes(8), name
        assert data[8] == 0, name
        assert data[9:] == payload, name


def test_gzip_seed_layout() -> None:
    root = Path(__file__).parents[2] / "ci/fuzz/corpus/fuzz_gzip"
    header = (root / "header").read_bytes()
    plain = (root / "plain").read_bytes()
    assert len(header) > 4
    assert header[2:4] == b"\x1f\x8b"
    assert plain[2:4] != b"\x1f\x8b"


def test_generated_corpus_names_are_ignored() -> None:
    assert GENERATED_CORPUS_NAME.fullmatch("a" * 40) is not None
    assert GENERATED_CORPUS_NAME.fullmatch("handwritten-seed") is None


if __name__ == "__main__":
    test_scan_seed_layout()
    test_gzip_seed_layout()
    test_generated_corpus_names_are_ignored()
    print("ok   fuzz seeds retain scanner layout and real gzip coverage")
