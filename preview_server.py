"""Localhost preview server for legacy HTML import review."""
from __future__ import annotations

import email
import html
import json
import secrets
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

import extractors
import export_push

_SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "Info"]
_STATUS_OPTIONS = [
    (1, "Open"), (2, "In Progress"), (3, "Fixed"), (4, "Won't Fix"),
    (5, "Retest Pending"), (6, "Passed"), (7, "Still Present"), (8, "Closed"),
]
_RETEST_OPTIONS = [
    ("", "-- none --"), ("passed", "Passed"), ("failed", "Failed"), ("pending", "Pending"),
]

_API_REQUIRED = ("api_url", "token", "product_id", "engagement_id", "test_id")

_UPDATE_FIELDS = {
    "f_title": "title",
    "f_cve": "cve",
    "f_cvss": "cvss",
    "f_cvss_vector": "cvss_vector",
    "f_cwe": "cwe",
    "f_desc": "desc",
    "f_poc": "poc",
    "f_remediation": "remediation",
    "f_ref": "ref",
    "f_asset": "asset",
    "f_retest_status": "retest_status",
    "f_retest_by": "retest_by",
}


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _token_path(token: str) -> str:
    return urllib.parse.quote(token, safe="")


def _tags_str(cand: dict) -> str:
    tags = cand.get("tags") or []
    if not isinstance(tags, list):
        return ""
    return ", ".join(
        str(t.get("name", "")) for t in tags if isinstance(t, dict)
    )


def _parse_multipart(body: bytes, content_type: str) -> dict[str, str]:
    raw = (
        b"Content-Type: " + content_type.encode("latin-1", "replace")
        + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    msg = email.message_from_bytes(raw)
    form: dict[str, str] = {}
    if not msg.is_multipart():
        return form
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            value = payload.decode(charset)
        except (LookupError, UnicodeDecodeError):
            value = payload.decode("utf-8", errors="replace")
        form[str(name)] = value
    return form


def _parse_form(body: bytes, content_type: str = "") -> dict[str, str]:
    if not body:
        return {}
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if ctype == "multipart/form-data":
        return _parse_multipart(body, content_type)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("utf-8", errors="replace")
    parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
    return {key: values[0] for key, values in parsed.items()}


def _vulns(report: dict) -> list:
    vulns = report.get("report_vulns")
    if not isinstance(vulns, list):
        vulns = []
        report["report_vulns"] = vulns
    return vulns


def _apply_update(cand: dict, form: dict[str, str]) -> None:
    for field, key in _UPDATE_FIELDS.items():
        cand[key] = form.get(field, "")
    cand["severity"] = extractors._normalize_severity(form.get("f_severity", ""))
    retest_date = form.get("f_retest_date", "").strip()
    cand["retest_date"] = extractors._to_ms(retest_date) if retest_date else None
    try:
        cand["status"] = int(form.get("f_status", "1"))
    except (TypeError, ValueError):
        cand["status"] = 1
    parts = [part.strip() for part in form.get("f_tags", "").split(",")]
    cand["tags"] = [{"name": part} for part in parts if part]


def _api_missing(api_config: Optional[dict]) -> list[str]:
    if not isinstance(api_config, dict):
        return list(_API_REQUIRED)
    return [key for key in _API_REQUIRED if api_config.get(key) in (None, "")]


def _api_kwargs(api_config: Optional[dict]) -> tuple[Optional[dict], list[str]]:
    missing = _api_missing(api_config)
    if missing:
        return None, missing
    kwargs = {key: api_config[key] for key in _API_REQUIRED}
    kwargs["verify"] = api_config.get("verify", True)
    return kwargs, []


def _api_info(api_config: Optional[dict]) -> str:
    if not isinstance(api_config, dict):
        return "not configured"
    missing = _api_missing(api_config)
    if missing:
        return "incomplete (missing " + ", ".join(missing) + ")"
    return (
        f"configured for {api_config.get('api_url')} "
        f"product={api_config.get('product_id')} "
        f"engagement={api_config.get('engagement_id')} "
        f"test={api_config.get('test_id')}"
    )


def _candidate_html(cand: dict, idx: int, token_path: str) -> str:
    warnings = cand.get("_warnings") or []
    if not isinstance(warnings, list):
        warnings = [warnings]
    meta = "\n".join([
        f"_source: {cand.get('_source', '')}",
        f"_warnings: {'; '.join(str(w) for w in warnings)}",
        "_source_snippet:",
        str(cand.get("_source_snippet") or ""),
    ])
    tags = _esc(_tags_str(cand))

    lines = [f'<div class="card" data-index="{idx}">']
    lines.append(
        "<h3>" + _esc(cand.get("title", "")) +
        f' <small>#{idx}</small></h3>'
    )
    lines.append("<pre>" + _esc(meta) + "</pre>")
    lines.append(
        f'<form id="edit_{idx}" method="post" action="/preview/{token_path}/update">'
    )
    lines.append(f'<input type="hidden" name="index" value="{idx}">')
    lines.append('<div class="grid">')
    for label, key in [("Title", "title"), ("CVE", "cve"), ("CVSS", "cvss"),
                       ("CVSS Vector", "cvss_vector"), ("CWE", "cwe"),
                       ("Asset", "asset")]:
        lines.append(
            f'<label>{label}<input name="f_{key}" value="{_esc(cand.get(key, ""))}"></label>'
        )
    lines.append("</div>")
    lines.append('<div class="grid">')
    lines.append('<label>Severity<select name="f_severity">')
    lines.append('<option value="">-- none --</option>')
    for opt in _SEVERITY_OPTIONS:
        sel = " selected" if cand.get("severity") == opt else ""
        lines.append(f'<option{sel}>{opt}</option>')
    lines.append("</select></label>")
    lines.append('<label>Status<select name="f_status">')
    for val, label in _STATUS_OPTIONS:
        sel = " selected" if str(cand.get("status")) == str(val) else ""
        lines.append(f'<option{sel} value="{val}">{label}</option>')
    lines.append("</select></label>")
    lines.append('<label>Retest<select name="f_retest_status">')
    for val, label in _RETEST_OPTIONS:
        sel = " selected" if cand.get("retest_status") == val else ""
        lines.append(f'<option{sel} value="{val}">{label}</option>')
    lines.append("</select></label>")
    lines.append("</div>")
    for label, key in [("Description", "desc"), ("PoC", "poc"),
                       ("Remediation", "remediation")]:
        lines.append(
            f'<label>{label}<textarea name="f_{key}">{_esc(cand.get(key, ""))}</textarea></label>'
        )
    for label, key in [("Ref", "ref")]:
        lines.append(
            f'<label>{label}<input name="f_{key}" value="{_esc(cand.get(key, ""))}"></label>'
        )
    lines.append(
        f'<label>Tags (comma separated)<input name="f_tags" value="{tags}"></label>'
    )
    lines.append(
        f'<label>Retest By<input name="f_retest_by" value="{_esc(cand.get("retest_by", ""))}"></label>'
    )
    lines.append(
        f'<label>Retest Date (ms epoch or ISO)<input name="f_retest_date" value="{_esc(cand.get("retest_date", ""))}"></label>'
    )
    lines.append('<div class="actions">')
    lines.append('<button type="submit" class="save">Save</button>')
    lines.append("</div>")
    lines.append("</form>")
    lines.append(
        f'<form id="del_{idx}" method="post" action="/preview/{token_path}/delete">'
    )
    lines.append(f'<input type="hidden" name="index" value="{idx}">')
    lines.append('<button type="submit" class="del">Delete</button>')
    lines.append("</form>")
    lines.append("</div>")
    return "\n".join(lines)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Legacy HTML Import Preview</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 0; background: #f5f5f5; color: #222; }}
header {{ background: #1f2937; color: #fff; padding: 1rem; }}
header h1 {{ margin: 0; font-size: 1.2rem; }}
header .meta {{ font-size: 0.85rem; opacity: 0.85; }}
main {{ padding: 1rem; max-width: 980px; margin: 0 auto; }}
.card {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
.card h3 {{ margin-top: 0; }}
.grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }}
.grid label, main > form label {{ display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.4rem; }}
.grid input, .grid select, textarea, main > form input {{ width: 100%; box-sizing: border-box; margin-top: 0.15rem; padding: 0.35rem; font-size: 0.9rem; border: 1px solid #bbb; border-radius: 4px; }}
textarea {{ min-height: 4rem; resize: vertical; }}
.actions {{ margin-top: 0.5rem; }}
.actions button, .toolbar button {{ padding: 0.35rem 0.8rem; font-size: 0.85rem; border: none; border-radius: 4px; cursor: pointer; }}
button.save {{ background: #2563eb; color: #fff; }}
button.del {{ background: #dc2626; color: #fff; }}
button.primary {{ background: #16a34a; color: #fff; }}
.warnings {{ color: #b45309; font-size: 0.8rem; margin-bottom: 0.5rem; }}
pre {{ background: #1f2937; color: #f9fafb; padding: 0.5rem; border-radius: 4px; overflow-x: auto; font-size: 0.75rem; }}
.toolbar {{ margin-bottom: 1rem; }}
.toolbar form {{ display: inline; }}
.toolbar button {{ margin-right: 0.5rem; }}
.banner {{ background: #dcfce7; color: #166534; padding: 0.5rem; border-radius: 4px; margin-bottom: 1rem; }}
.error {{ background: #fee2e2; color: #991b1b; padding: 0.5rem; border-radius: 4px; margin-bottom: 1rem; }}
</style>
</head>
<body>
<header>
<h1>Legacy HTML Import Preview</h1>
<div class="meta">Token: <code>{token}</code> &middot; {n_candidates} candidate(s)</div>
</header>
<main>
{msg_html}
<form id="report-form" method="post" action="/preview/{token_path}/report">
<label>Report Name<input name="report_name" value="{report_name}"></label>
<label>Report Scope<input name="report_scope" value="{report_scope}"></label>
<button type="submit" class="primary">Save Report</button>
</form>
<hr>
{candidates_html}
<hr>
<div class="toolbar">
<form id="save-legacy-form" method="post" action="/preview/{token_path}/save-legacy">
<button type="submit" class="primary">Save Legacy JSON</button>
</form>
<form id="push-findings-form" method="post" action="/preview/{token_path}/push-findings">
<button type="submit">Send to Findings API</button>
</form>
<form id="push-both-form" method="post" action="/preview/{token_path}/push-both">
<button type="submit">Send Findings + Save Legacy</button>
</form>
<a href="/preview/{token_path}/download"><button type="button">Download JSON</button></a>
</div>
<p><small>API: {api_info}</small></p>
</main>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    server: Any

    def _send(self, status: int, body: str | bytes, content_type: str = "text/html; charset=utf-8",
              headers: Optional[dict[str, str]] = None) -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, message: str) -> None:
        location = (
            f"/preview/{_token_path(self.server.token)}"
            f"?msg={urllib.parse.quote(message)}"
        )
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _not_found(self) -> None:
        self._send(
            404,
            '<!DOCTYPE html><html><head><meta charset="utf-8"><title>404</title></head>'
            "<body><h1>404 Not Found</h1></body></html>",
        )

    def _error(self, message: str, status: int = 400) -> None:
        token_path = _token_path(self.server.token)
        body = (
            '<!DOCTYPE html><html><head><meta charset="utf-8">'
            "<title>Preview error</title>"
            "<style>body{font-family:system-ui,sans-serif;margin:2rem}"
            ".error{background:#fee2e2;color:#991b1b;padding:1rem;border-radius:4px}"
            f"</style></head><body><div class=\"error\">{_esc(message)}</div>"
            f'<p><a href="/preview/{token_path}">Back to preview</a></p>'
            "</body></html>"
        )
        self._send(status, body)

    def _read_form(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""
        return _parse_form(body, self.headers.get("Content-Type", ""))

    def _split_path(self) -> tuple[str, dict[str, list[str]]]:
        parts = urllib.parse.urlsplit(self.path)
        return parts.path, urllib.parse.parse_qs(parts.query, keep_blank_values=True)

    def _render_page(self, message: str = "") -> None:
        with self.server.lock:
            report = self.server.report
            vulns = _vulns(report)
            candidates_html = "\n".join(
                _candidate_html(cand, idx, _token_path(self.server.token))
                for idx, cand in enumerate(vulns)
                if isinstance(cand, dict)
            )
            body = _HTML_TEMPLATE.format(
                token=_esc(self.server.token),
                token_path=_token_path(self.server.token),
                n_candidates=len(vulns),
                msg_html=(
                    f'<div class="banner">{_esc(message)}</div>' if message else ""
                ),
                report_name=_esc(report.get("report_name", "")),
                report_scope=_esc(report.get("report_scope", "")),
                candidates_html=candidates_html,
                api_info=_esc(_api_info(self.server.api_config)),
            )
        self._send(200, body)

    def do_GET(self) -> None:
        path, query = self._split_path()
        prefix = f"/preview/{_token_path(self.server.token)}"
        if path == prefix:
            self._render_page(query.get("msg", [""])[0])
        elif path == prefix + "/download":
            with self.server.lock:
                payload = json.dumps(
                    extractors.clean_report(self.server.report),
                    ensure_ascii=False,
                    indent=2,
                ).encode("utf-8")
            filename = Path(self.server.legacy_out).name or "legacy-report.json"
            self._send(
                200,
                payload,
                content_type="application/json; charset=utf-8",
                headers={
                    "Content-Disposition": (
                        "attachment; filename*=UTF-8''"
                        + urllib.parse.quote(filename)
                    )
                },
            )
        else:
            self._not_found()

    def do_POST(self) -> None:
        path, _ = self._split_path()
        prefix = f"/preview/{_token_path(self.server.token)}"

        if path == prefix + "/report":
            form = self._read_form()
            with self.server.lock:
                self.server.report["report_name"] = form.get("report_name", "")
                self.server.report["report_scope"] = form.get("report_scope", "")
                _vulns(self.server.report)
            self._redirect("Report saved.")
            return

        if path == prefix + "/update":
            form = self._read_form()
            try:
                idx = int(form.get("index", ""))
            except (TypeError, ValueError):
                self._error("Invalid candidate index.")
                return
            with self.server.lock:
                vulns = _vulns(self.server.report)
                if not 0 <= idx < len(vulns):
                    self._error("Candidate not found.")
                    return
                cand = vulns[idx]
                if not isinstance(cand, dict):
                    cand = {}
                    vulns[idx] = cand
                _apply_update(cand, form)
            self._redirect("Candidate saved.")
            return

        if path == prefix + "/delete":
            form = self._read_form()
            try:
                idx = int(form.get("index", ""))
            except (TypeError, ValueError):
                self._error("Invalid candidate index.")
                return
            with self.server.lock:
                vulns = _vulns(self.server.report)
                if not 0 <= idx < len(vulns):
                    self._error("Candidate not found.")
                    return
                del vulns[idx]
            self._redirect("Candidate deleted.")
            return

        if path == prefix + "/save-legacy":
            self._read_form()
            try:
                with self.server.lock:
                    out = export_push.save_legacy(
                        self.server.report, self.server.legacy_out
                    )
            except Exception as exc:
                self._error(f"Could not save legacy JSON: {exc}", 500)
                return
            self._redirect(f"Saved legacy JSON to {out}.")
            return

        if path == prefix + "/push-findings":
            self._read_form()
            kwargs, missing = _api_kwargs(self.server.api_config)
            if missing:
                self._error(
                    "API configuration incomplete: missing " + ", ".join(missing)
                )
                return
            try:
                with self.server.lock:
                    export_push.push_findings(self.server.report, **kwargs)
            except Exception as exc:
                self._error(f"Could not push findings: {exc}", 500)
                return
            self._redirect("Findings sent to API.")
            return

        if path == prefix + "/push-both":
            self._read_form()
            kwargs, missing = _api_kwargs(self.server.api_config)
            if missing:
                self._error(
                    "API configuration incomplete: missing " + ", ".join(missing)
                )
                return
            try:
                with self.server.lock:
                    out = export_push.save_legacy(
                        self.server.report, self.server.legacy_out
                    )
                    export_push.push_findings(self.server.report, **kwargs)
            except Exception as exc:
                self._error(f"Could not save/push findings: {exc}", 500)
                return
            self._redirect(f"Saved legacy JSON to {out} and sent findings to API.")
            return

        self._not_found()


def serve(
    report: dict,
    *,
    token: Optional[str] = None,
    host: str = "127.0.0.1",
    port: int = 0,
    open_browser: bool = False,
    api_config: Optional[dict] = None,
    legacy_out: str = "legacy-report.json",
) -> None:
    token = token or secrets.token_urlsafe(24)
    _vulns(report)

    server = ThreadingHTTPServer((host, int(port)), _Handler)
    server.report = report
    server.token = token
    server.api_config = api_config
    server.legacy_out = legacy_out
    server.lock = threading.Lock()

    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}/preview/{_token_path(token)}"
    print(url, flush=True)
    if open_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
