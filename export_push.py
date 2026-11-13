"""Push findings to export REST API and write legacy report JSON."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from extractors import clean_report


def save_legacy(report: dict, path) -> Path:
    """Write clean_report(report) as pretty JSON to path. Returns Path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    cleaned = clean_report(report)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(cleaned, fh, ensure_ascii=False, indent=2)
    return out


def push_findings(
    report: dict,
    api_url: str,
    token: str,
    product_id,
    engagement_id,
    test_id,
    close_stale: bool = False,
    verify: bool = True,
) -> dict:
    """Push candidates.json to export findings import endpoint."""
    import requests

    api_url = api_url.rstrip("/")
    if api_url.endswith("/api/v1"):
        api_url = api_url[: -len("/api/v1")]
    url = f"{api_url}/api/v1/products/{product_id}/engagements/{engagement_id}/tests/{test_id}/findings/import"

    cleaned = clean_report(report)
    payload = json.dumps(cleaned, ensure_ascii=False).encode("utf-8")

    files = {"file": ("candidates.json", payload, "application/json")}
    data = {}
    if close_stale:
        data["close_stale"] = "on"
    headers = {"Authorization": f"Bearer {token}"}

    resp = requests.post(
        url,
        headers=headers,
        files=files,
        data=data,
        timeout=120,
        verify=verify,
    )
    if not (200 <= resp.status_code < 300):
        raise RuntimeError(f"push_findings failed ({resp.status_code}): {resp.text}")
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text}
