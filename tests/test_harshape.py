import contextlib
import copy
import io
import json
import math
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

from harshape.cli import main
from harshape.core import ShapeError, project_file, project_har


def entry(url="https://private.example/api/user?id=SECRET", date="2026-01-01T10:00:00+08:00"):
    return {
        "startedDateTime": date,
        "time": 120.5,
        "request": {
            "url": url,
            "method": "GET",
            "httpVersion": "HTTP/2",
            "headersSize": 230,
            "bodySize": 0,
        },
        "response": {
            "status": 200,
            "statusText": "OK",
            "httpVersion": "HTTP/2",
            "headersSize": 220,
            "bodySize": 32,
            "content": {
                "size": 64,
                "compression": 32,
                "mimeType": "application/json; secret=PRIVATE",
            },
        },
        "timings": {
            "blocked": 0,
            "dns": -1,
            "connect": -1,
            "send": 5,
            "wait": 100,
            "receive": 15.5,
            "ssl": -1,
        },
    }


def capture(*entries):
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "Original private browser", "version": "secret"},
            "entries": list(entries),
        }
    }


class ProjectionTests(unittest.TestCase):
    def test_all_free_text_canaries_removed(self):
        secret = "CANARY_0745eeca_PRIVATE"  # noqa: S105 - synthetic canary, never a credential
        item = entry(f"https://{secret.lower()}.example/user/{secret}?{secret}={secret}#{secret}")
        item.update(
            comment=secret,
            pageref=secret,
            serverIPAddress=secret,
            connection=secret,
            _securityDetails={"name": secret},
            _initiator={"url": secret},
        )
        item["request"].update(
            cookies=[{"name": secret, "value": secret}],
            headers=[{"name": "Authorization", "value": secret}],
            queryString=[{"name": secret, "value": secret}],
            postData={"mimeType": "text/plain", "text": secret},
            comment=secret,
            _unknown=secret,
        )
        item["response"].update(
            cookies=[{"name": secret, "value": secret}],
            headers=[{"name": "X-Secret", "value": secret}],
            statusText=secret,
            redirectURL=f"https://private.example/{secret}",
            _unknown=secret,
        )
        item["response"]["content"].update(text=secret, encoding=secret, comment=secret)
        item["cache"] = {"beforeRequest": {"comment": secret}}
        item["timings"]["comment"] = secret
        document = capture(item)
        document["log"].update(
            pages=[{"title": secret}], browser={"name": secret}, comment=secret, _extension=secret
        )
        document["private"] = secret
        projected, summary = project_har(document)
        serialized = json.dumps(projected)
        self.assertNotIn(secret, serialized)
        self.assertNotIn(secret.lower(), serialized)
        self.assertNotIn("private.example", serialized)
        self.assertNotIn("2026-01", serialized)
        self.assertEqual(summary["entries"], 1)
        result = projected["log"]["entries"][0]
        self.assertEqual(
            set(result), {"startedDateTime", "time", "request", "response", "cache", "timings"}
        )
        self.assertEqual(set(result["response"]["content"]), {"size", "mimeType", "compression"})
        self.assertEqual(result["request"]["headers"], [])

    def test_metrics_preserved_without_mutating_source(self):
        document = capture(entry())
        original = copy.deepcopy(document)
        projected, _ = project_har(document)
        result = projected["log"]["entries"][0]
        self.assertEqual(document, original)
        self.assertEqual(result["time"], 120.5)
        self.assertEqual(result["timings"], original["log"]["entries"][0]["timings"])
        self.assertEqual(result["response"]["content"]["compression"], 32)
        self.assertEqual(result["response"]["content"]["mimeType"], "application/json")
        self.assertEqual(result["request"]["headersSize"], 230)

    def test_relative_timestamp_offsets_and_unsorted_entries(self):
        document = capture(
            entry(date="2026-01-01T02:00:01.125Z"), entry(date="2026-01-01T10:00:00+08:00")
        )
        result, _ = project_har(document)
        first, second = [e["startedDateTime"] for e in result["log"]["entries"]]
        self.assertEqual(second, "2000-01-01T00:00:00.000000Z")
        self.assertEqual(
            (datetime.fromisoformat(first) - datetime.fromisoformat(second)).total_seconds(), 1.125
        )

    def test_endpoint_groups_ignore_query_fragment_and_userinfo(self):
        document = capture(
            entry("https://user:pass@PRIVATE.example:443/api/user?q=ONE#frag"),
            entry("https://private.example/api/user?q=TWO"),
            entry("https://private.example/api/order"),
        )
        result, summary = project_har(document)
        urls = [e["request"]["url"] for e in result["log"]["entries"]]
        self.assertEqual(urls[0], urls[1])
        self.assertNotEqual(urls[0], urls[2])
        self.assertEqual(summary["origin_groups"], 1)
        self.assertEqual(summary["endpoint_groups"], 2)
        parsed = urlsplit(urls[0])
        self.assertTrue(parsed.hostname.endswith(".invalid"))
        self.assertFalse(parsed.query or parsed.fragment or parsed.username)
        self.assertEqual(len(parsed.path.split("/")), 3)

    def test_origin_separation_by_host_scheme_and_port(self):
        values = (
            "https://one.example/a",
            "https://two.example/a",
            "http://one.example/a",
            "https://one.example:8443/a",
            "https://one.example:0/a",
        )
        _result, summary = project_har(capture(*(entry(value) for value in values)))
        self.assertEqual(summary["origin_groups"], 5)

    def test_same_segment_is_scoped_to_origin_and_parent(self):
        result, _ = project_har(
            capture(
                entry("https://a.example/a/user"),
                entry("https://a.example/b/user"),
                entry("https://b.example/a/user"),
            )
        )
        tails = [e["request"]["url"].rsplit("/", 1)[1] for e in result["log"]["entries"]]
        self.assertEqual(len(set(tails)), 3)

    def test_fresh_random_key_per_projection(self):
        first, _ = project_har(capture(entry()))
        second, _ = project_har(capture(entry()))
        self.assertNotEqual(
            first["log"]["entries"][0]["request"]["url"],
            second["log"]["entries"][0]["request"]["url"],
        )

    def test_opaque_urls_never_copy_payload_or_local_path(self):
        document = capture(
            entry("data:text/plain,SECRET_VALUE"),
            entry("file:///home/private/SECRET"),
            entry("blob:https://private.example/SECRET"),
        )
        result, summary = project_har(document)
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("/home/private", json.dumps(result))
        self.assertEqual(summary["origin_groups"], 3)

    def test_unicode_ipv6_and_escaped_paths(self):
        result, _ = project_har(capture(entry("https://[::1]/用户/%2Fsecret")))
        self.assertNotIn("用户", json.dumps(result, ensure_ascii=False))

    def test_empty_capture(self):
        result, summary = project_har(capture())
        self.assertEqual(result["log"]["entries"], [])
        self.assertEqual(summary["origin_groups"], 0)

    def test_unknown_enum_values_are_fixed_placeholders(self):
        item = entry()
        item["request"].update(method="PRIVATE_METHOD", httpVersion="PRIVATE_PROTOCOL")
        item["response"]["content"]["mimeType"] = "PRIVATE_MIME"
        result, _ = project_har(capture(item))
        serialized = json.dumps(result)
        self.assertNotIn("PRIVATE_", serialized)
        request = result["log"]["entries"][0]["request"]
        self.assertEqual(request["method"], "OTHER")
        self.assertEqual(request["httpVersion"], "unknown")

    def test_missing_optional_metrics_get_unknown_values(self):
        item = entry()
        item["request"].pop("headersSize")
        item["timings"] = {}
        item["response"]["content"].pop("compression")
        item["response"]["content"]["mimeType"] = None
        result, _ = project_har(capture(item))
        projected = result["log"]["entries"][0]
        self.assertEqual(projected["request"]["headersSize"], -1)
        self.assertEqual(projected["timings"]["wait"], -1)
        self.assertEqual(projected["response"]["content"]["mimeType"], "application/octet-stream")

    def test_bad_types_statuses_and_ranges_fail(self):
        mutations = [
            lambda e: e.update(time=True),
            lambda e: e.update(time=-2),
            lambda e: e.update(time=math.inf),
            lambda e: e["response"].update(status=42),
            lambda e: e["response"].update(status=600),
            lambda e: e["response"].update(status=True),
            lambda e: e["request"].update(bodySize=1.5),
            lambda e: e["response"]["content"].update(size=-1),
            lambda e: e["response"]["content"].update(size=10**300),
            lambda e: e["timings"].update(wait=-2),
            lambda e: e.update(request=None),
            lambda e: e.update(timings=[]),
        ]
        for mutate in mutations:
            item = entry()
            mutate(item)
            with self.assertRaises(ShapeError):
                project_har(capture(item))

    def test_status_zero_for_aborted_requests(self):
        item = entry()
        item["response"]["status"] = 0
        _result, summary = project_har(capture(item))
        self.assertEqual(summary["status_counts"], {"0": 1})

    def test_fractional_negative_timing_is_invalid(self):
        item = entry()
        item["timings"]["wait"] = -0.5
        with self.assertRaises(ShapeError):
            project_har(capture(item))

    def test_bad_root_version_and_entry_limit(self):
        for document in (
            [],
            {},
            {"log": []},
            {"log": {"version": "1.1", "entries": []}},
            {"log": {"version": "1.2", "entries": {}}},
            capture(None),
        ):
            with self.assertRaises(ShapeError):
                project_har(document)
        with patch("harshape.core.MAX_ENTRIES", 0), self.assertRaises(ShapeError):
            project_har(capture(entry()))

    def test_invalid_timestamp_and_capture_span(self):
        for value in (
            None,
            "PRIVATE_DATE",
            "2026-01-01T00:00:00",
            "x" * 129,
            "9999-12-31T23:59:59-01:00",
        ):
            with self.assertRaises(ShapeError):
                project_har(capture(entry(date=value)))
        with self.assertRaises(ShapeError):
            project_har(
                capture(entry(date="2020-01-01T00:00:00Z"), entry(date="2022-01-01T00:00:00Z"))
            )

    def test_bad_urls_and_segment_limits(self):
        for value in (
            None,
            "",
            "relative/path",
            "https:///secret",
            "https://host:invalid/a",
            "https://[invalid/a",
            "https://host/a\nSECRET",
            "https://host/\ud800",
            "https://host/" + "a" * 8192,
            "https://host/" + "a/" * 128,
        ):
            with self.subTest(value=repr(value)[:40]), self.assertRaises(ShapeError):
                project_har(capture(entry(value)))
        with patch("harshape.core.MAX_TOTAL_SEGMENTS", 1), self.assertRaises(ShapeError):
            project_har(capture(entry()))


class FileAndCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.har"
        self.output = self.root / "share.har"

    def write(self, document=None):
        self.source.write_text(
            json.dumps(capture(entry()) if document is None else document), encoding="utf-8"
        )

    def test_complete_file_flow_and_input_preservation(self):
        self.write()
        original = self.source.read_bytes()
        summary = project_file(self.source, self.output)
        self.assertTrue(summary["created"])
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(json.loads(self.output.read_text())["log"]["version"], "1.2")

    def test_har_utf8_bom_is_supported(self):
        self.write()
        self.source.write_bytes(b"\xef\xbb\xbf" + self.source.read_bytes())
        self.assertTrue(project_file(self.source, self.output)["created"])

    def test_explicit_depth_cap_and_quoted_brackets(self):
        for count, valid in ((126, True), (127, False)):
            nested = 0
            for _ in range(count):
                nested = [nested]
            document = capture()
            document["log"]["_unknown"] = nested
            self.write(document)
            if valid:
                project_file(self.source, self.output)
                self.output.unlink()
            else:
                with self.assertRaises(ShapeError):
                    project_file(self.source, self.output)
        document = capture()
        document["log"]["_unknown"] = "[" * 1000 + '\\"'
        self.write(document)
        self.assertTrue(project_file(self.source, self.output)["created"])

    def test_changed_source_is_rejected(self):
        self.write()
        first = SimpleNamespace(st_size=self.source.stat().st_size, st_mtime_ns=1)
        second = SimpleNamespace(st_size=first.st_size, st_mtime_ns=2)
        with (
            patch("harshape.core.os.fstat", side_effect=[first, second]),
            self.assertRaises(ShapeError),
        ):
            project_file(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_cli_output_has_no_source_values(self):
        self.write()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main([str(self.source), "--output", str(self.output)]), 0)
        self.assertNotIn("private.example", output.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.source), "--output", str(self.output)]), 2)

    def test_existing_output_is_never_overwritten(self):
        self.write()
        self.output.write_bytes(b"important")
        with self.assertRaises(FileExistsError):
            project_file(self.source, self.output)
        self.assertEqual(self.output.read_bytes(), b"important")

    def test_no_output_on_invalid_input(self):
        for raw in (b"not-json", b"\xff", b'{"log":NaN}', b'{"log":1,"log":2}', b"[" * 2000):
            self.source.write_bytes(raw)
            with self.assertRaises(ShapeError):
                project_file(self.source, self.output)
            self.assertFalse(self.output.exists())

    def test_input_and_output_byte_limits(self):
        self.write()
        with self.assertRaises(ShapeError):
            project_file(self.source, self.output, max_input_bytes=5)
        for limit in (0, -1, True, 268435457):
            with self.assertRaises(ShapeError):
                project_file(self.source, self.output, max_input_bytes=limit)
        with patch("harshape.core.MAX_OUTPUT_BYTES", 1), self.assertRaises(ShapeError):
            project_file(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_nonregular_or_missing_source(self):
        with self.assertRaises(ShapeError):
            project_file(self.root, self.output)
        with self.assertRaises(FileNotFoundError):
            project_file(self.source, self.output)

    def test_write_failure_removes_only_new_output(self):
        self.write()
        with (
            patch("harshape.core.os.fsync", side_effect=OSError("disk full")),
            self.assertRaises(OSError),
        ):
            project_file(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.assertTrue(self.source.exists())

    def test_diagnostic_does_not_echo_invalid_secret(self):
        self.write(capture(entry("https://host:SECRET_PORT/a")))
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            self.assertEqual(main([str(self.source), "--output", str(self.output)]), 2)
        self.assertNotIn("SECRET_PORT", error.getvalue())

    @unittest.skipIf(os.name == "nt", "POSIX permission semantics")
    def test_output_mode(self):
        self.write()
        project_file(self.source, self.output)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
