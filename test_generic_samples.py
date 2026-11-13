"""Generic structural extraction checks against the six sample reports."""

from __future__ import annotations

import unittest
from pathlib import Path

import extractors
import ayakci

HERE = Path(__file__).resolve().parent


def run(name: str) -> dict:
    return extractors.extract(HERE / "examples" / name, use_ai=False)


def by_ref(report: dict, ref: str) -> dict:
    for cand in report["report_vulns"]:
        if cand.get("ref") == ref:
            return cand
    raise AssertionError(f"missing ref {ref}: {[c.get('ref') for c in report['report_vulns']]}")


class GenericSampleTests(unittest.TestCase):
    def test_sample_1_summary_table_plus_blocks(self):
        report = run("1.html")
        cands = report["report_vulns"]

        self.assertEqual(len(cands), 3)
        self.assertTrue(all(c["_source"] == "generic" for c in cands))
        self.assertTrue(all(c["status"] == 1 for c in cands))

        idor = by_ref(report, "F-01")
        self.assertIn("IDOR", idor["title"])
        self.assertEqual(idor["severity"], "Critical")
        self.assertTrue(idor["desc"])
        self.assertTrue(idor["poc"])
        self.assertTrue(idor["remediation"])
        self.assertIn("GET /api/v1/invoices/{invoice_id}", idor["asset"])

        xss = by_ref(report, "F-02")
        self.assertIn("XSS", xss["title"])
        self.assertEqual(xss["severity"], "High")

        headers = by_ref(report, "F-03")
        self.assertIn("Güvenlik Başlıkları", headers["title"])
        self.assertEqual(headers["severity"], "Low")
        self.assertIn("ornekteknoloji.com", headers["asset"])

    def test_sample_2_blocks_with_cvss_cve(self):
        report = run("2.html")
        self.assertEqual(len(report["report_vulns"]), 2)

        openssh = next(c for c in report["report_vulns"] if "OpenSSH" in c["title"])
        self.assertEqual(openssh["severity"], "Critical")
        self.assertEqual(openssh["cvss"], "9.8")
        self.assertEqual(openssh["cve"], "CVE-2024-6387")
        self.assertTrue(openssh["remediation"])
        self.assertIn("192.168.10.45", openssh["asset"])
        self.assertIn("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", openssh["cvss_vector"])

        ssl = next(c for c in report["report_vulns"] if "SSL/TLS" in c["title"])
        self.assertEqual(ssl["severity"], "Medium")
        self.assertEqual(ssl["cvss"], "5.3")
        self.assertEqual(ssl["cve"], "CVE-2016-2183")
        self.assertIn("192.168.10.45", ssl["asset"])
        self.assertTrue(ssl["cvss_vector"])

    def test_sample_2_and_3_cross_file_dedupe(self):
        reports = [run("2.html"), run("3.html.htm")]
        merged = ayakci._merge_reports(reports)
        self.assertEqual(len(merged["report_vulns"]), 2)
        for cand in merged["report_vulns"]:
            self.assertIn("AV:N/AC:L/PR:N/UI:N", cand["cvss_vector"])

    def test_sample_3_matches_sample_2(self):
        report = run("3.html.htm")
        self.assertEqual(len(report["report_vulns"]), 2)
        by_cve = {c["cve"]: c for c in report["report_vulns"]}
        self.assertEqual(by_cve["CVE-2024-6387"]["severity"], "Critical")
        self.assertEqual(by_cve["CVE-2024-6387"]["cvss"], "9.8")
        self.assertEqual(by_cve["CVE-2016-2183"]["severity"], "Medium")
        self.assertEqual(by_cve["CVE-2016-2183"]["cvss"], "5.3")

    def test_sample_4_report_only_no_manual_fallback(self):
        report = run("4.html.htm")
        self.assertEqual(report["report_vulns"], [])
        self.assertIn("no individual findings detected", report["_warnings"])

    def test_generic_plain_security_risk_is_not_report_only(self):
        self.assertIsNone(
            extractors.extract_generic("<html><body>security risk</body></html>")
        )

    def test_sample_5_retest_status_table_and_blocks(self):
        report = run("5.html")
        self.assertEqual(len(report["report_vulns"]), 4)
        self.assertTrue(all("Dummy Bankacılık API" in c["asset"] for c in report["report_vulns"]))

        rt01 = by_ref(report, "RT-01")
        self.assertIn("JWT", rt01["title"])
        self.assertEqual(rt01["severity"], "Critical")
        self.assertEqual(rt01["retest_status"], "passed")
        self.assertIsInstance(rt01["retest_date"], int)

        rt02 = by_ref(report, "RT-02")
        self.assertIn("Rate-Limit", rt02["title"])
        self.assertEqual(rt02["severity"], "High")
        self.assertEqual(rt02["retest_status"], "failed")
        self.assertTrue(rt02["desc"])
        self.assertTrue(
            "IP bazlı hız sınırı" in rt02["desc"] or "X-Forwarded-For" in rt02["desc"]
        )

        rt03 = by_ref(report, "RT-03")
        self.assertIn("DOM", rt03["title"])
        self.assertEqual(rt03["severity"], "Medium")
        self.assertEqual(rt03["retest_status"], "failed")

        rt04 = by_ref(report, "RT-04")
        self.assertIn("TLS 1.1", rt04["title"])
        self.assertEqual(rt04["severity"], "Low")
        self.assertEqual(rt04["status"], 4)
        self.assertEqual(rt04["retest_status"], "")

    def test_sample_6_retest_history(self):
        report = run("6.html.htm")
        self.assertEqual(len(report["report_vulns"]), 1)

        cand = report["report_vulns"][0]
        self.assertEqual(cand["ref"], "VULN-882")
        self.assertIn("IDOR", cand["title"])
        self.assertEqual(cand["status"], 3)
        self.assertEqual(cand["retest_status"], "passed")
        self.assertTrue(cand["retest_by"])
        self.assertIsInstance(cand["retest_date"], int)
        self.assertEqual(len(cand["retest_history"]), 2)
        self.assertIn("GET /api/export", cand["poc"])
        self.assertIn("Response", cand["poc"])


if __name__ == "__main__":
    unittest.main()
