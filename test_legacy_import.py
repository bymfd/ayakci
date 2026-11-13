"""Stdlib unittest checks for the legacy HTML importer (no network, no server)."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import extractors
import ayakci
import preview_server
import export_push


class EmbeddedExtractionTests(unittest.TestCase):
    def test_embedded_base64_js(self):
        payload = {
            "report_vulns": [
                {
                    "title": "Embedded Title",
                    "poc": "curl http://example.com",
                    "retest_status": "passed",
                }
            ]
        }
        encoded = base64.b64encode(
            urllib.parse.quote(json.dumps(payload)).encode("utf-8")
        ).decode("ascii")
        html = f"<html><script>const base64_data = '{encoded}';</script></html>"

        embedded = extractors.extract_embedded(html)

        self.assertIsNotNone(embedded)
        cand = embedded["report_vulns"][0]
        self.assertEqual(cand["title"], "Embedded Title")
        self.assertEqual(cand["poc"], "curl http://example.com")
        self.assertEqual(cand["retest_status"], "passed")

    def test_embedded_script_json(self):
        payload = {
            "report_vulns": [
                {"title": "Script Title", "poc": "poc-here", "retest_status": "failed"}
            ]
        }
        html = (
            '<html><script type="application/json">'
            + json.dumps(payload)
            + "</script></html>"
        )

        embedded = extractors.extract_embedded(html)

        self.assertIsNotNone(embedded)
        cand = embedded["report_vulns"][0]
        self.assertEqual(cand["title"], "Script Title")
        self.assertEqual(cand["poc"], "poc-here")
        self.assertEqual(cand["retest_status"], "failed")

    def test_plain_data_key_base64_json(self):
        inner = {"report_vulns": [{"title": "Plain Data", "poc": "p"}]}
        wrapped = {
            "data": base64.b64encode(json.dumps(inner).encode("utf-8")).decode("ascii")
        }
        html = (
            '<script type="application/json">'
            + json.dumps(wrapped)
            + "</script>"
        )

        embedded = extractors.extract_embedded(html)

        self.assertIsNotNone(embedded)
        self.assertEqual(embedded["report_vulns"][0]["title"], "Plain Data")

    def test_encrypted_v2_payload_with_password(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        password = "secret"
        salt = b"0123456789abcdef"
        iv = b"012345678901"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000
        )
        key = kdf.derive(password.encode("utf-8"))
        plaintext = json.dumps(
            {"report_vulns": [{"title": "Encrypted Title"}]}
        ).encode("utf-8")
        blob = b"v2" + salt + iv + AESGCM(key).encrypt(iv, plaintext, None)
        encoded = base64.b64encode(blob).decode("ascii")
        html = f"<script>const encrypted_data = '{encoded}';</script>"

        embedded = extractors.extract_embedded(html, password=password)

        self.assertIsNotNone(embedded)
        self.assertEqual(embedded["report_vulns"][0]["title"], "Encrypted Title")
        with self.assertRaises(ValueError):
            extractors.extract_embedded(html)

    def test_empty_embedded_falls_through_to_manual(self):
        html = (
            "<html><title>Manual Fallback</title><body>"
            '<script type="application/json">{"report_vulns": []}</script>'
            "<h1>Manual Fallback</h1><p>hello</p></body></html>"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plain.html"
            path.write_text(html, encoding="utf-8")
            report = extractors.extract(path, use_ai=False)

        self.assertEqual(len(report["report_vulns"]), 1)
        self.assertEqual(report["report_vulns"][0]["_source"], "manual")

    def test_single_quoted_js_with_double_quotes(self):
        html = (
            "<script>const x = '"
            '{"report_vulns":[{"title":"Single Quoted"}]}'
            "';</script>"
        )

        embedded = extractors.extract_embedded(html)

        self.assertIsNotNone(embedded)
        self.assertEqual(embedded["report_vulns"][0]["title"], "Single Quoted")


class NormalizationTests(unittest.TestCase):
    def test_turkish_enum_mapping(self):
        cand = extractors.normalize_candidate(
            {
                "title": "x",
                "severity": "Yüksek",
                "status": "Devam ediyor",
                "retest_status": "Başarılı",
            }
        )
        self.assertEqual(cand["severity"], "High")
        self.assertEqual(cand["status"], 2)
        self.assertEqual(cand["retest_status"], "passed")

    def test_turkish_casefold(self):
        self.assertIn("onem derecesi", extractors.normalize_text("ÖNEM DERECESİ"))
        self.assertEqual(extractors.normalize_text("DURUM"), "durum")

    def test_missing_retest(self):
        cand = extractors.normalize_candidate({"title": "x"})
        self.assertEqual(cand["retest_status"], "")
        self.assertEqual(cand["retest_history"], [])

    def test_turkish_accented_keys(self):
        cand = extractors.normalize_candidate(
            {"başlık": "Başlık", "açıklama": "Açıklama", "önem": "ÖNEMLİ"}
        )
        self.assertEqual(cand["title"], "Başlık")
        self.assertEqual(cand["desc"], "Açıklama")
        self.assertEqual(cand["severity"], "High")

    def test_turkish_month_date(self):
        expected = int(
            datetime(2024, 2, 12, tzinfo=timezone.utc).timestamp() * 1000
        )
        self.assertEqual(extractors._to_ms("12 Şubat 2024"), expected)
        self.assertEqual(
            extractors._to_ms("12 Mayıs 2024"),
            int(datetime(2024, 5, 12, tzinfo=timezone.utc).timestamp() * 1000),
        )
        self.assertEqual(
            extractors._to_ms("12 Ağustos 2024"),
            int(datetime(2024, 8, 12, tzinfo=timezone.utc).timestamp() * 1000),
        )

    def test_yyyymmdd_date(self):
        expected = int(
            datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp() * 1000
        )
        self.assertEqual(extractors._to_ms("20240101"), expected)


class PreviewUpdateTests(unittest.TestCase):
    def test_apply_update_retest_date_and_severity(self):
        cand = {"retest_date": 1}
        form = {
            "f_retest_date": "2024-02-12",
            "f_severity": "High",
            "f_status": "3",
            "f_tags": "a, b",
        }

        preview_server._apply_update(cand, form)

        expected = int(
            datetime(2024, 2, 12, tzinfo=timezone.utc).timestamp() * 1000
        )
        self.assertEqual(cand["retest_date"], expected)
        self.assertIsInstance(cand["retest_date"], int)
        self.assertEqual(cand["severity"], "High")

    def test_apply_update_empty_retest_date_is_none(self):
        cand = {"retest_date": 123}
        preview_server._apply_update(cand, {"f_retest_date": ""})
        self.assertIsNone(cand["retest_date"])


class ProfileAndManualTests(unittest.TestCase):
    def test_profile_extraction(self):
        html = (
            '<div class="finding">'
            "<h2>SQL Injection</h2>"
            '<span class="severity">High</span>'
            '<div class="desc">desc</div>'
            "<pre>poc</pre>"
            '<div class="remediation">fix</div>'
            "</div>"
        )
        report = extractors.extract_profile(
            html, Path(__file__).parent / "profiles/example.json"
        )

        self.assertIsNotNone(report)
        cand = report["report_vulns"][0]
        self.assertEqual(cand["title"], "SQL Injection")
        self.assertEqual(cand["severity"], "High")
        self.assertEqual(cand["desc"], "desc")
        self.assertEqual(cand["poc"], "poc")
        self.assertEqual(cand["remediation"], "fix")

    def test_manual_fallback(self):
        html = (
            "<html><title>Manual</title><body>"
            "<h1>Manual</h1><p>hello</p></body></html>"
        )
        report = extractors.manual_report(html, "x.html")

        self.assertEqual(len(report["report_vulns"]), 1)
        self.assertTrue(report["report_vulns"][0]["desc"])


class WriterAndPushTests(unittest.TestCase):
    def test_legacy_writer(self):
        report = {
            "report_name": "x",
            "_warnings": ["w"],
            "report_vulns": [
                {"title": "t", "_source": "manual", "_warnings": ["a"]}
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.json"
            export_push.save_legacy(report, path)

            with open(path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)

        self.assertTrue(loaded["report_vulns"])
        self.assertFalse(any(k.startswith("_") for k in loaded))
        self.assertFalse(
            any(k.startswith("_") for k in loaded["report_vulns"][0])
        )

    def test_push_findings_mock(self):
        report = {"report_name": "x", "report_vulns": [{"title": "t"}]}
        with mock.patch("requests.post") as post:
            post.return_value.status_code = 200
            post.return_value.json.return_value = {"ok": True}

            result = export_push.push_findings(report, "http://x", "tok", 1, 2, 3)

        self.assertEqual(result, {"ok": True})
        args, kwargs = post.call_args
        url = args[0] if args else kwargs["url"]
        self.assertTrue(
            url.endswith("/api/v1/products/1/engagements/2/tests/3/findings/import")
        )
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer tok")
        self.assertIn("file", kwargs["files"])
        self.assertEqual(kwargs["files"]["file"][0], "candidates.json")

    def test_clean_report(self):
        report = {
            "report_name": "x",
            "_warnings": ["w"],
            "report_vulns": [
                {"title": "t", "_source": "manual", "nested": {"_x": 1, "y": 2}}
            ],
        }
        cleaned = extractors.clean_report(report)

        def assert_no_internal(value):
            if isinstance(value, dict):
                for key, inner in value.items():
                    self.assertFalse(key.startswith("_"), key)
                    assert_no_internal(inner)
            elif isinstance(value, list):
                for inner in value:
                    assert_no_internal(inner)

        assert_no_internal(cleaned)


if __name__ == "__main__":
    unittest.main()
