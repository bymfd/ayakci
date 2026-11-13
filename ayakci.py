"""CLI for importing legacy security-report HTML into export."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.parse
from pathlib import Path

import extractors
import preview_server
import export_push

import random

def print_banner():
    l1 = [
        r"""
    █████╗ ██╗   ██╗ █████╗ ██╗  ██╗ ██████╗██╗
    ██╔══██╗╚██╗ ██╔╝██╔══██╗██║ ██╔╝██╔════╝██║
    ███████║ ╚████╔╝ ███████║█████╔╝ ██║     ██║
    ██╔══██║  ╚██╔╝  ██╔══██║██╔═██╗ ██║     ██║
    ██║  ██║   ██║   ██║  ██║██║  ██╗╚██████╗██║
    ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝██║
        [ HTML Bloat In  ──►  Pure JSON Out ]
        """,
        r"""
    ▄▄▄      ▓██   ██▓ ▄▄▄       ██ ▄█▀ ▄████▄   ██▓
   ▒████▄     ▒██  ██▒▒████▄     ██▄█▒ ▒██▀ ▀█  ▓██▒
   ▒██  ▀█▄    ▒██ ██░▒██  ▀█▄  ▓███▄░ ▒▓█    ▄ ▒██▒
   ░██▄▄▄▄██   ░ ▐██▓░░██▄▄▄▄██ ▓██ █▄ ▒▓▓▄ ▄██▒░██░
   ▓█   ▓██▒  ░ ██▒▓░ ▓█   ▓██▒██▒ █▄ ▒ ▓███▀ ░░██░
   ▒▒   ▓▒█░   ██▒▒▒  ▒▒   ▓▒█░▒ ▒▒ ▓▒░ ░▒ ▒  ░░▓  
    ▒   ▒▒ ░ ▓██ ░▒░   ▒   ▒▒ ░░ ░▒ ▒░  ░  ▒    ▒ ░
    ░   ▒    ▒ ▒ ░░    ░   ▒   ░ ░░ ░ ░         ▒ ░
        ░  ░ ░ ░           ░  ░░  ░   ░ ░       ░  
           ░ ░                      ░            
    [ "Don't sweat it, I'll carry the HTML." ]
        """,
        r"""
        ___                 __         _ 
       /   | __  __ ____ _ / /__ _____(_)
      / /| |/ / / // __ `// //_// ___// / 
     / ___ / /_/ // /_/ // ,<  / /__ / /  
    /_/  |_\__, / \__,_//_/|_| \___//_/   
          /____/                          
     :: Your loyal HTML-to-JSON pentest gofer ::
        """,
        r"""
           _______________________________________________________________________________        
            ______________________________________________/\\\_____________________________       
              ___________________/\\\__/\\\________________\/\\\________________________/\\\_      
               __/\\\\\\\\\______\//\\\/\\\___/\\\\\\\\\____\/\\\\\\\\________/\\\\\\\\_\///__     
                _\////////\\\______\//\\\\\___\////////\\\___\/\\\////\\\____/\\\//////___/\\\_    
                 ___/\\\\\\\\\\______\//\\\______/\\\\\\\\\\__\/\\\\\\\\/____/\\\_________\/\\\_   
                  __/\\\/////\\\___/\\_/\\\______/\\\/////\\\__\/\\\///\\\___\//\\\________\/\\\_  
                   _\//\\\\\\\\/\\_\//\\\\/______\//\\\\\\\\/\\_\/\\\_\///\\\__\///\\\\\\\\_\/\\\_ 
                    __\////////\//___\////_________\////////\//__\///____\///_____\////////__\///__ 

        """

    ]
    
    # Listeden rastgele bir tanesini seçiyoruz
    selected = random.choice(l1)
    
    # İsteğe bağlı ANSI renk kodu (Cyan renk için \033[96m, sıfırlamak için \033[0m)
    CYAN = "\033[96m"
    RESET = "\033[0m"
    
    print(f"{CYAN}{selected}{RESET}")



def _env(name: str):
    return os.environ.get(name)


def _add_api_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--api-url", default=_env("export_API_URL"))
    parser.add_argument("--token", default=_env("export_TOKEN"))
    parser.add_argument("--product", default=_env("export_PRODUCT_ID"))
    parser.add_argument("--engagement", default=_env("export_ENGAGEMENT_ID"))
    parser.add_argument("--test", default=_env("export_TEST_ID"))
    parser.add_argument("--legacy-out", default="legacy-report.json")
    parser.add_argument("--insecure", action="store_true")


def _api_config(args):
    values = [args.api_url, args.token, args.product, args.engagement, args.test]
    if not all(values):
        return None
    return {
        "api_url": args.api_url,
        "token": args.token,
        "product_id": args.product,
        "engagement_id": args.engagement,
        "test_id": args.test,
        "verify": not args.insecure,
    }


def _require_connection(args) -> None:
    missing = [
        flag
        for attr, flag in (
            ("api_url", "api-url"),
            ("token", "token"),
            ("product", "product"),
            ("engagement", "engagement"),
            ("test", "test"),
        )
        if not getattr(args, attr)
    ]
    if missing:
        sys.stderr.write(
            "missing required connection values: " + ", ".join("--" + m for m in missing) + "\n"
        )
        raise SystemExit(2)


def _expand_paths(paths) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in (".html", ".htm"):
                    files.append(child)
        elif path.is_file():
            files.append(path)
        else:
            sys.stderr.write(f"[warn] not found: {raw}\n")
    seen: set[str] = set()
    unique: list[Path] = []
    for path in files:
        key = str(path.resolve())
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _merge_reports(reports) -> dict:
    merged = {
        "report_name": None,
        "report_scope": None,
        "report_createdate": None,
        "report_vulns": [],
        "_warnings": [],
    }
    merge_fields = (
        "desc", "poc", "remediation", "asset", "cve", "cvss", "cvss_vector",
        "cwe", "status", "retest_status", "retest_by", "retest_date", "retest_history",
    )
    by_key: dict[tuple[str, str], dict] = {}
    for report in reports:
        if not merged["report_name"] and report.get("report_name"):
            merged["report_name"] = report["report_name"]
        if not merged["report_scope"] and report.get("report_scope"):
            merged["report_scope"] = report["report_scope"]
        if merged["report_createdate"] is None and report.get("report_createdate") is not None:
            merged["report_createdate"] = report["report_createdate"]
        merged["_warnings"].extend(report.get("_warnings") or [])
        for cand in report.get("report_vulns") or []:
            key = (
                extractors._norm_ref(cand.get("ref", "")),
                extractors.normalize_text(cand.get("title", "")),
            )
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = cand
                merged["report_vulns"].append(cand)
                continue
            for field in merge_fields:
                value = cand.get(field)
                if existing.get(field) in (None, "", [], {}) and value not in (None, "", [], {}):
                    existing[field] = value
    return merged


def _print_table(report: dict) -> None:
    rows = [["idx", "title", "severity", "retest", "source"]]
    for idx, cand in enumerate(report.get("report_vulns", [])):
        rows.append([
            str(idx),
            str(cand.get("title", "")),
            str(cand.get("severity", "")),
            str(cand.get("retest_status", "")),
            str(cand.get("_source", "")),
        ])
    widths = [max(len(row[i]) for row in rows) for i in range(5)]
    for row in rows:
        print("  ".join(row[i].ljust(widths[i]) for i in range(5)))


def _load_json(path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _cmd_extract(args) -> int:
    files = _expand_paths(args.paths)
    if not files:
        sys.stderr.write("no input files\n")
        return 2

    reports = []
    failed = 0
    for path in files:
        try:
            reports.append(
                extractors.extract(
                    path,
                    password=args.password,
                    profile=args.profile,
                    use_ai=not args.no_ai,
                    ai_endpoint=args.ai_endpoint,
                    ai_api_key=args.ai_key,
                    ai_model=args.ai_model,
                )
            )
        except Exception as exc:
            failed += 1
            sys.stderr.write(f"[error] {path}: {exc}\n")

    if not reports:
        sys.stderr.write("all input files failed; nothing to write\n")
        return 2
    if failed:
        sys.stderr.write(
            f"[warn] {failed} file(s) failed; continuing with {len(reports)} report(s)\n"
        )

    report = _merge_reports(reports)
    export_push.save_legacy(report, args.out)
    print(f"wrote {args.out}")

    if args.no_serve:
        _print_table(report)
        return 0

    preview_server.serve(
        report,
        port=args.port,
        open_browser=args.open,
        api_config=_api_config(args),
        legacy_out=args.legacy_out,
    )
    return 0


def _cmd_preview(args) -> int:
    report = _load_json(args.file)
    preview_server.serve(
        report,
        port=args.port,
        open_browser=args.open,
        api_config=_api_config(args),
        legacy_out=args.legacy_out,
    )
    return 0


def _cmd_push(args) -> int:
    report = _load_json(args.file)

    if args.target in ("findings", "both"):
        _require_connection(args)
        result = export_push.push_findings(
            report,
            args.api_url,
            args.token,
            args.product,
            args.engagement,
            args.test,
            close_stale=args.close_stale,
            verify=not args.insecure,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))

    if args.target in ("legacy", "both"):
        path = export_push.save_legacy(report, args.legacy_out)
        print(f"wrote legacy report: {path}")
        print("upload it manually at /reports/import")

    return 0


def _cmd_selftest(args) -> int:
    payload = {"report_vulns": [{"title": "Embedded Title", "poc": "curl http://example.com"}]}
    encoded = base64.b64encode(
        urllib.parse.quote(json.dumps(payload)).encode("utf-8")
    ).decode("ascii")
    html = f"<html><script>const base64_data = '{encoded}';</script></html>"
    embedded = extractors.extract_embedded(html)
    assert embedded and embedded.get("report_vulns"), embedded
    cand = embedded["report_vulns"][0]
    assert cand.get("title") == "Embedded Title", cand
    assert cand.get("poc") == "curl http://example.com", cand

    normalized = extractors.normalize_candidate({
        "title": "x",
        "severity": "Yüksek",
        "status": "Devam ediyor",
        "retest_status": "Başarılı",
    })
    assert normalized["severity"] == "High", normalized
    assert normalized["status"] == 2, normalized
    assert normalized["retest_status"] == "passed", normalized

    cleaned = extractors.clean_report({
        "report_name": "x",
        "_warnings": ["w"],
        "report_vulns": [{"title": "t", "_source": "manual", "_warnings": ["a"]}],
    })
    assert not any(k.startswith("_") for k in cleaned), cleaned
    assert not any(k.startswith("_") for k in cleaned["report_vulns"][0]), cleaned

    print("selftest ok")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ayakci Import legacy security-report HTML into export")
    sub = parser.add_subparsers(dest="command", required=True)

    extract = sub.add_parser("extract", help="extract candidates from HTML files")
    extract.add_argument("paths", nargs="*")
    extract.add_argument("--profile")
    extract.add_argument("--password")
    extract.add_argument("--no-ai", action="store_true")
    extract.add_argument("--ai-endpoint", default=_env("AI_ENDPOINT"))
    extract.add_argument("--ai-key", default=_env("AI_API_KEY"))
    extract.add_argument("--ai-model", default=_env("AI_MODEL"))
    extract.add_argument("--out", default="candidates.json")
    extract.add_argument("--no-serve", action="store_true")
    extract.add_argument("--open", action="store_true")
    extract.add_argument("--port", type=int, default=0)
    _add_api_args(extract)
    extract.set_defaults(func=_cmd_extract)

    preview = sub.add_parser("preview", help="preview a candidates JSON file")
    preview.add_argument("file")
    preview.add_argument("--port", type=int, default=0)
    preview.add_argument("--open", action="store_true")
    _add_api_args(preview)
    preview.set_defaults(func=_cmd_preview)

    push = sub.add_parser("push", help="push a candidates JSON file")
    push.add_argument("file")
    push.add_argument("--target", choices=("findings", "legacy", "both"), required=True)
    push.add_argument("--close-stale", action="store_true")
    _add_api_args(push)
    push.set_defaults(func=_cmd_push)

    selftest = sub.add_parser("selftest", help="run built-in checks")
    selftest.set_defaults(func=_cmd_selftest)

    return parser


def main() -> int:
    print_banner()
    parser = _build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
