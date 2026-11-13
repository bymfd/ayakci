"""HTML extraction: embedded JSON, profiles, AI, manual, normalization."""

from __future__ import annotations

import base64
import difflib
import json
import re
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Any, Optional

from bs4 import BeautifulSoup

_HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Field aliases loaded from aliases.json (English + Turkish).
# ---------------------------------------------------------------------------
FIELD_ALIASES: dict[str, list[str]] = {}
SEVERITY_MAP: dict[str, str] = {}
STATUS_MAP: dict[str, int] = {}
RETEST_STATUS_MAP: dict[str, str] = {}
MONTHS: dict[str, int] = {}

_DEFAULT_ALIASES: dict[str, list[str]] = {
    "title": ["title", "name", "baslik", "vulnerability", "finding"],
    "desc": ["desc", "description", "aciklama", "details", "body", "content"],
    "poc": ["poc", "proof", "proof_of_concept", "kanit", "reproduction", "steps"],
    "remediation": ["remediation", "remed", "solution", "cozum", "oneri", "fix"],
    "severity": ["severity", "onem", "risk", "level", "priority"],
    "status": ["status", "durum", "state", "phase"],
    "cve": ["cve", "cve_id", "cveid"],
    "cvss": ["cvss", "cvss_score", "score"],
    "cvss_vector": ["cvss_vector", "cvssvec", "vector"],
    "cwe": ["cwe", "cwe_id", "weakness"],
    "tags": ["tags", "etiketler", "labels", "label", "category"],
    "asset": ["asset", "varlik", "host", "target", "url", "endpoint", "affected"],
    "retest_status": ["retest_status", "retest_result", "retest_sonucu", "retest", "test_result"],
    "retest_by": ["retest_by", "tester", "test_eden", "tested_by", "reviewer"],
    "retest_date": ["retest_date", "retest_tarihi", "test_date"],
}

_DEFAULT_SEVERITY_MAP = {
    "critical": "Critical", "kritik": "Critical", "acil": "Critical",
    "high": "High", "yüksek": "High", "onemli": "High", "önemli": "High",
    "medium": "Medium", "orta": "Medium", "moderate": "Medium",
    "low": "Low", "düşük": "Low", "dusuk": "Low",
    "info": "Info", "bilgi": "Info", "informational": "Info", "bilgilendirme": "Info",
}

_DEFAULT_STATUS_MAP = {
    "open": 1, "acik": 1, "new": 1, "yeni": 1,
    "in progress": 2, "devam ediyor": 2, "islemde": 2, "in_progress": 2,
    "fixed": 3, "duzeltilmis": 3, "giderildi": 3, "solved": 3, "resolved": 3,
    "won't fix": 4, "duzeltilmeyecek": 4, "giderilmeyecek": 4, "won_t_fix": 4, "wontfix": 4,
    "retest pending": 5, "retest bekliyor": 5, "retest_pending": 5,
    "passed": 6, "dogrulandi": 6, "test_gecti": 6, "gecti": 6, "basarili": 6,
    "still present": 7, "hala mevcut": 7, "test_basarisiz": 7, "failed": 7,
    "closed": 8, "kapatildi": 8,
}

_DEFAULT_RETEST_STATUS_MAP = {
    "passed": "passed", "gecti": "passed", "basarili": "passed", "dogrulandi": "passed",
    "failed": "failed", "basarisiz": "failed", "gecmedi": "failed", "hala mevcut": "failed", "still present": "failed",
    "pending": "pending", "beklemede": "pending", "bekliyor": "pending", "in progress": "pending",
}

_DEFAULT_MONTHS = {
    "ocak": 1, "subat": 2, "mart": 3, "nisan": 4, "mayis": 5, "haziran": 6,
    "temmuz": 7, "agustos": 8, "eylul": 9, "ekim": 10, "kas": 11, "aralik": 12,
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
}


def _load_aliases_file() -> dict:
    path = _HERE / "aliases.json"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _init_aliases() -> None:
    global FIELD_ALIASES, SEVERITY_MAP, STATUS_MAP, RETEST_STATUS_MAP, MONTHS
    data = _load_aliases_file()
    FIELD_ALIASES = {k: [str(x).lower() for x in v] for k, v in data.items() if isinstance(v, list)}
    if not FIELD_ALIASES:
        FIELD_ALIASES = dict(_DEFAULT_ALIASES)
    SEVERITY_MAP = {normalize_text(str(k)): v for k, v in data.get("severity_map", _DEFAULT_SEVERITY_MAP).items()}
    STATUS_MAP = {normalize_text(str(k)): v for k, v in data.get("status_map", _DEFAULT_STATUS_MAP).items()}
    RETEST_STATUS_MAP = {normalize_text(str(k)): v for k, v in data.get("retest_status_map", _DEFAULT_RETEST_STATUS_MAP).items()}
    MONTHS = {normalize_text(str(k)): v for k, v in data.get("months", _DEFAULT_MONTHS).items()}


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

_TURKISH_TRANS = str.maketrans({
    "ı": "i", "İ": "i", "ş": "s", "ğ": "g", "ç": "c", "ö": "o", "ü": "u",
    "I": "i", "Ş": "s", "Ğ": "g", "Ç": "c", "Ö": "o", "Ü": "u",
})


def read_html(path) -> str:
    """Read bytes, decode utf-8-sig, fallback latin-1."""
    data = Path(path).read_bytes()
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def normalize_text(s: str) -> str:
    """Normalize for label matching only. Never used for output text."""
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", s)
    s = s.translate(_TURKISH_TRANS)
    s = s.casefold()
    s = re.sub(r"[\s_\-\.:;,]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


_init_aliases()


def _b64_decode(data: str) -> bytes:
    """Decode base64 with padding fix."""
    data = re.sub(r"\s+", "", data)
    pad = (-len(data)) % 4
    data += "=" * pad
    return base64.b64decode(data)


def _looks_like_json(text: str) -> bool:
    t = text.lstrip()
    return t.startswith("{") or t.startswith("[")


def _parse_json_robust(text: str) -> Optional[Any]:
    """Parse JSON robustly: strip fences, find first { or [."""
    if not text:
        return None
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)
    start = min(
        (i for i, ch in enumerate(text) if ch in "{["),
        default=None,
    )
    if start is None:
        return None
    candidate = text[start:]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    # Try to find matching closing bracket
    opener = candidate[0]
    closer = "}" if opener == "{" else "]"
    depth = 0
    for i, ch in enumerate(candidate):
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(candidate[: i + 1])
                except json.JSONDecodeError:
                    break
    return None


def _normalize_candidates_list(raw: Any) -> list[dict]:
    """Accept dict/list of candidates and return a list of dicts."""
    if raw is None:
        return []
    if isinstance(raw, dict):
        if any(k in raw for k in ("title", "desc", "severity", "status")):
            return [raw]
        return [v for v in raw.values() if isinstance(v, dict)]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    return []


def _find_candidates_key(data: dict) -> Optional[str]:
    for key in ("report_vulns", "findings", "vulnerabilities", "issues", "candidates", "results"):
        if key in data and isinstance(data[key], (list, dict)):
            return key
    return None


def _decrypt_payload(payload: bytes, password: Optional[str]) -> bytes:
    """Decrypt v2 (AESGCM) or legacy (Salted__ OpenSSL) payload."""
    if not password:
        raise ValueError("Encrypted embedded JSON requires a password")
    if payload[:2] == b"v2":
        salt = payload[2:18]
        iv = payload[18:30]
        ciphertext = payload[30:]
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        key = kdf.derive(password.encode("utf-8"))
        return AESGCM(key).decrypt(iv, ciphertext, None)
    if payload[:8] == b"Salted__":
        salt = payload[8:16]
        data = payload[16:]
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        # OpenSSL EVP_BytesToKey MD5
        d = b""
        prev = b""
        while len(d) < 48:
            prev = _md5(prev + password.encode("utf-8") + salt)
            d += prev
        key = d[:32]
        iv = d[32:48]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(data) + dec.finalize()
        # PKCS7 unpad
        pad = padded[-1]
        if 1 <= pad <= 16 and padded[-pad:] == bytes([pad]) * pad:
            return padded[:-pad]
        return padded
    raise ValueError("Unknown encrypted payload format")


def _md5(data: bytes) -> bytes:
    import hashlib
    return hashlib.md5(data).digest()


def _decrypt_json(raw: bytes, password: Optional[str]) -> Optional[dict]:
    """Decrypt a payload and parse the plaintext JSON object."""
    try:
        plain = _decrypt_payload(raw, password)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Could not decrypt embedded payload: {exc}") from exc
    text = plain.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = _parse_json_robust(text)
    return parsed if isinstance(parsed, dict) else None


# ---------------------------------------------------------------------------
# Embedded JSON extraction
# ---------------------------------------------------------------------------

_EMBED_PATTERNS = [
    # const/let/var name = '...' or "..."
    re.compile(
        r"(?:const|let|var)\s+(\w+)\s*=\s*(?P<q>['\"])(?P<val>.*?)(?P=q)",
        re.DOTALL,
    ),
    # atob('...') / atob("...")
    re.compile(r"atob\(\s*(?P<q>['\"])(?P<val>.*?)(?P=q)\s*\)", re.DOTALL),
    # window.__REPORT__ = {...}; etc.
    re.compile(
        r"window\.__\w+\s*=\s*(?P<val>\{.*?\}|\[.*?\])",
        re.DOTALL,
    ),
]

_SCRIPT_JSON_RE = re.compile(
    r"<script\b[^>]*type\s*=\s*['\"]?application/json['\"]?[^>]*>(?P<val>.*?)</script>",
    re.DOTALL | re.IGNORECASE,
)


def _try_decode_embedded(text: str, password: Optional[str]) -> Optional[dict]:
    """Try to decode embedded JSON from JS/HTML patterns."""
    candidates: list[tuple[str, str]] = []

    # 1. raw JSON
    if _looks_like_json(text):
        parsed = _parse_json_robust(text)
        if isinstance(parsed, dict):
            candidates.append(("raw", text))

    # 2. script type=application/json
    for m in _SCRIPT_JSON_RE.finditer(text):
        candidates.append(("script-json", m.group("val")))

    # 3. JS variable / atob patterns
    for pat in _EMBED_PATTERNS:
        for m in pat.finditer(text):
            val = m.group("val")
            if not val:
                continue
            if pat == _EMBED_PATTERNS[2]:
                # window.__X = {...} raw JSON
                parsed = _parse_json_robust(val)
                if isinstance(parsed, dict):
                    return _normalize_embedded_dict(parsed, password)
                continue
            # base64, encrypted, or plain JSON string
            try:
                raw = _b64_decode(val)
            except Exception:
                raw = b""
            if raw[:2] == b"v2" or raw[:8] == b"Salted__":
                inner = _decrypt_json(raw, password)
                if isinstance(inner, dict):
                    return _normalize_embedded_dict(inner, password)
                continue
            decoded = None
            if raw:
                try:
                    decoded = json.loads(raw.decode("utf-8"))
                except Exception:
                    try:
                        decoded = json.loads(urllib.parse.unquote(raw.decode("utf-8", errors="replace")))
                    except Exception:
                        decoded = _parse_json_robust(val)
            else:
                decoded = _parse_json_robust(val)
            if isinstance(decoded, dict):
                return _normalize_embedded_dict(decoded, password)
            if isinstance(decoded, str):
                try:
                    decoded = json.loads(decoded)
                except Exception:
                    pass
            if isinstance(decoded, dict):
                return _normalize_embedded_dict(decoded, password)

    # Try each candidate block
    for _, raw in candidates:
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = _parse_json_robust(raw)
        if isinstance(parsed, dict):
            return _normalize_embedded_dict(parsed, password)

    return None


def _normalize_embedded_dict(data: dict, password: Optional[str]) -> dict:
    """Normalize an embedded dict into the internal report shape."""
    # Handle encryption wrapper
    for key in ("encrypted_data", "encrypted", "payload", "data"):
        if key not in data or not isinstance(data[key], str):
            continue
        val = data[key]
        try:
            raw = _b64_decode(val)
        except Exception:
            raw = val.encode("utf-8")
        encrypted = (
            raw[:2] == b"v2"
            or raw[:8] == b"Salted__"
            or key.startswith("encrypted")
        )
        if encrypted:
            inner = _decrypt_json(raw, password)
            if isinstance(inner, dict):
                data = inner
                break
            continue
        # Plain data/payload: try JSON on decoded bytes and on the raw string.
        decoded = None
        for text in (raw.decode("utf-8", errors="replace"), val):
            try:
                decoded = json.loads(text)
                break
            except Exception:
                parsed = _parse_json_robust(text)
                if isinstance(parsed, dict):
                    decoded = parsed
                    break
        if isinstance(decoded, dict):
            data = decoded
            break

    key = _find_candidates_key(data)
    if key is None:
        # Maybe the dict itself is a candidate
        if any(k in data for k in ("title", "desc", "severity", "status")):
            data["_source"] = "embedded"
            return {
                "report_name": data.get("report_name") or data.get("name") or "Imported legacy report",
                "report_scope": data.get("report_scope") or data.get("scope") or "",
                "report_createdate": _to_ms(data.get("report_createdate") or data.get("createdate") or data.get("date")),
                "report_vulns": [data],
                "_warnings": [],
            }
        return {"report_vulns": [], "_warnings": ["embedded JSON had no recognizable findings"]}

    raw_vulns = data[key]
    vulns = _normalize_candidates_list(raw_vulns)
    for vuln in vulns:
        vuln["_source"] = "embedded"
    return {
        "report_name": data.get("report_name") or data.get("name") or "Imported legacy report",
        "report_scope": data.get("report_scope") or data.get("scope") or "",
        "report_createdate": _to_ms(data.get("report_createdate") or data.get("createdate") or data.get("date")),
        "report_vulns": vulns,
        "_warnings": [],
    }


def extract_embedded(html: str, password: Optional[str] = None) -> Optional[dict]:
    """Find embedded JSON in HTML. Returns internal report dict or None."""
    try:
        return _try_decode_embedded(html, password)
    except ValueError:
        raise
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Profile extraction
# ---------------------------------------------------------------------------

def _load_profile(path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _select_first(node, selector: str):
    """Select first element via CSS selector, tolerating bs4 quirks."""
    try:
        return node.select_one(selector)
    except Exception:
        return None


def _select_all(node, selector: str):
    try:
        return node.select(selector)
    except Exception:
        return []


def _field_from_profile(node, spec: dict) -> str:
    """Extract a field value from a finding node using profile spec."""
    sel = spec.get("selector")
    if sel:
        if isinstance(sel, list):
            for s in sel:
                el = _select_first(node, s)
                if el:
                    return el.get_text("\n", strip=True)
        else:
            el = _select_first(node, sel)
            if el:
                return el.get_text("\n", strip=True)
    # generic label extraction
    return _generic_label_extract(node, spec.get("field", ""))


def _generic_label_extract(node, field: str) -> str:
    """Find a label whose normalized text matches an alias for `field`."""
    aliases = FIELD_ALIASES.get(field, [])
    norm_aliases = {normalize_text(a) for a in aliases}
    if not norm_aliases:
        return ""
    candidates = node.find_all(["h1", "h2", "h3", "h4", "h5", "h6", "dt", "th", "strong", "b", "label", "span", "div", "p"])
    for el in candidates:
        txt = el.get_text(" ", strip=True)
        ntxt = normalize_text(txt)
        if not ntxt:
            continue
        for na in norm_aliases:
            if ntxt == na or ntxt.startswith(na + " ") or ntxt.startswith(na + ":") or ntxt.startswith(na + "-"):
                # value is next sibling text or parent's next sibling
                nxt = el.find_next_sibling()
                if nxt:
                    return nxt.get_text("\n", strip=True)
                parent = el.parent
                if parent:
                    # find el index in parent
                    sibs = list(parent.children)
                    try:
                        idx = sibs.index(el)
                    except ValueError:
                        idx = -1
                    if idx >= 0 and idx + 1 < len(sibs):
                        nxt2 = sibs[idx + 1]
                        if hasattr(nxt2, "get_text"):
                            return nxt2.get_text("\n", strip=True)
                # "Label: value" inside same element
                # try colon split
                if ":" in txt:
                    return txt.split(":", 1)[1].strip()
                if "-" in txt:
                    return txt.split("-", 1)[1].strip()
                return ""
    return ""


def extract_profile(html: str, profile_path) -> Optional[dict]:
    """Extract findings using a JSON profile with CSS selectors."""
    profile = _load_profile(profile_path)
    soup = BeautifulSoup(html, "html.parser")

    finding = profile.get("finding")
    if isinstance(finding, dict):
        finding_sel = finding.get("selector") or finding.get("finding_selector")
        fields = profile.get("fields") or finding.get("fields") or {}
    elif isinstance(finding, str):
        finding_sel = finding
        fields = profile.get("fields") or {}
    else:
        finding_sel = profile.get("finding_selector") or profile.get("selector")
        fields = profile.get("fields") or {}
    if not finding_sel:
        return None
    nodes = _select_all(soup, finding_sel)
    if not nodes:
        return None

    candidates = []
    for node in nodes:
        cand: dict[str, Any] = {}
        for fname, spec in fields.items():
            if isinstance(spec, dict):
                val = _field_from_profile(node, dict(spec, field=fname))
            elif isinstance(spec, str):
                el = _select_first(node, spec)
                val = el.get_text("\n", strip=True) if el else ""
            else:
                val = ""
            if val:
                cand[fname] = val
        if not cand:
            continue
        # fallback generic extraction for missing fields
        for fname in FIELD_ALIASES:
            if fname in cand:
                continue
            val = _generic_label_extract(node, fname)
            if val:
                cand[fname] = val
        cand["_source"] = "profile"
        candidates.append(cand)

    if not candidates:
        return None
    return {
        "report_name": profile.get("report_name") or "Imported legacy report",
        "report_scope": profile.get("report_scope") or "",
        "report_createdate": _to_ms(profile.get("report_createdate")),
        "report_vulns": candidates,
        "_warnings": [],
    }


# ---------------------------------------------------------------------------
# Generic structural extraction (summary tables + repeated finding blocks)
# ---------------------------------------------------------------------------

_GENERIC_BLOCK_WORDS = (
    "finding", "vuln", "issue", "retest", "bug", "weakness",
    "risk item", "report item",
)

# ponytail: fixed status vocabulary for retest report dialects; extend map if a
# new customer report uses yet another word.
_GENERIC_STATUS_MAP = {
    "verified fixed": (3, "passed"),
    "fixed": (3, "passed"),
    "kapatildi": (8, "passed"),
    "closed": (8, "passed"),
    "partial": (2, "failed"),
    "kismi cozum": (2, "failed"),
    "open": (1, "failed"),
    "acik": (1, "failed"),
    "accepted": (4, ""),
    "risk kabul edildi": (4, ""),
}

_GENERIC_DESC_ALIASES = (
    "aciklama", "description", "synopsis", "details", "summary",
    "analist notu", "analyst note", "note",
)
_GENERIC_POC_ALIASES = (
    "kanit", "proof", "plugin output", "retest kaniti", "initial test", "final retest",
)
_GENERIC_REMEDIATION_ALIASES = (
    "cozum onerisi", "cozum", "remediation", "recommendation", "uygulanan yama",
    "fix", "solution",
)
_GENERIC_ASSET_ALIASES = (
    "etkilenen bilesen", "target host", "hedef sistem", "host", "port", "url",
    "endpoint", "asset", "varlik",
)
_GENERIC_REPORT_WORDS = (
    "yonetici ozeti", "executive summary", "bulgularin ozeti", "risk dagilimi",
    "kritik bulgular", "yuksek bulgular", "orta bulgular", "dusuk bulgular",
    "critical findings", "high findings", "medium findings", "low findings",
)


def _table_header_fields(text: str) -> set[str]:
    """Map a normalized table header to zero or more internal fields."""
    n = normalize_text(text)
    fields: set[str] = set()
    if not n:
        return fields

    is_id = n == "id" or "bulgu id" in n or "finding id" in n
    if is_id and "plugin id" not in n:
        fields.add("ref")

    if not is_id and any(
        k in n for k in ("bulgu", "finding", "vulnerability", "zafiyet", "baslik", "title", "name")
    ):
        fields.add("title")

    if any(k in n for k in ("risk", "severity", "onem", "level")) and not any(
        k in n for k in ("retest", "sonrasi", "after")
    ):
        fields.add("severity")

    if "cvss" in n:
        fields.add("cvss")

    if ("durum" in n or "status" in n) and "retest" not in n:
        fields.add("status")

    if any(k in n for k in ("retest", "yeniden test", "dogrulama", "verification")) and not any(
        k in n for k in ("risk", "severity", "onem")
    ):
        if any(k in n for k in ("tarih", "date")):
            fields.add("retest_date")
        else:
            fields.add("retest_status")

    if "cve" in n:
        fields.add("cve")
    if "cwe" in n:
        fields.add("cwe")
    if any(k in n for k in ("asset", "host", "target", "url", "hedef sistem", "varlik")):
        fields.add("asset")

    return fields


def _severity_from_text(text: str) -> str:
    if not text:
        return ""
    for word in re.findall(r"[A-Za-zÇĞİÖŞÜçğıöşü]+", text):
        sev = SEVERITY_MAP.get(normalize_text(word))
        if sev:
            return sev
    return ""


def _parse_cvss_value(text: str) -> tuple[str, str]:
    """Return (score, vector) from strings like '9.8 (AV:N/...)' or 'CVSS: 9.1'."""
    if not text:
        return "", ""
    m = re.search(r"(?<![\d.])(\d{1,2}(?:\.\d)?)\s*\((AV:[^)]+)\)", text)
    if m:
        return m.group(1), m.group(2).strip()
    m = re.search(
        r"CVSS(?:\s*v?\d(?:\.\d)?)?(?:\s*Base)?\s*[:=]?\s*(\d{1,2}(?:\.\d)?)",
        text,
        re.IGNORECASE,
    )
    if m:
        return m.group(1), ""
    m = re.search(r"(?<![\d.])(\d{1,2}\.\d)(?![\d.])", text)
    if m:
        return m.group(1), ""
    return "", ""


def _status_values(value) -> tuple[Optional[int], Optional[str]]:
    """Return (status, retest_status) for a status-ish value."""
    if value is None or value == "":
        return None, None
    n = normalize_text(str(value))
    for key in sorted(_GENERIC_STATUS_MAP, key=len, reverse=True):
        if key in n:
            return _GENERIC_STATUS_MAP[key]
    if n in STATUS_MAP:
        status = STATUS_MAP[n]
        if status in (3, 8):
            return status, "passed"
        if status in (1, 2, 7):
            return status, "failed"
        return status, ""
    retest = RETEST_STATUS_MAP.get(n)
    if retest:
        return None, retest
    return None, None


def _event_result(value) -> str:
    n = normalize_text(str(value or ""))
    if "pass" in n or "fixed" in n or "verified" in n:
        return "passed"
    if "fail" in n or "vulnerable" in n or "still" in n:
        return "failed"
    if "pending" in n or "progress" in n:
        return "pending"
    return ""


def _label_values(node) -> list[tuple[str, str, Any]]:
    """Collect (label, value, value_node) pairs for common report markup."""
    pairs: list[tuple[str, str, Any]] = []

    for td in node.find_all("td"):
        classes = [str(c).lower() for c in (td.get("class") or [])]
        if any("label" in c for c in classes):
            nxt = td.find_next_sibling("td")
            if nxt is not None:
                pairs.append((td.get_text(" ", strip=True), nxt.get_text("\n", strip=True), nxt))

    for dt in node.find_all("dt"):
        dd = dt.find_next_sibling("dd")
        if dd is not None:
            pairs.append((dt.get_text(" ", strip=True), dd.get_text("\n", strip=True), dd))

    for strong in node.find_all(["strong", "b"]):
        label = strong.get_text(" ", strip=True)
        if not label:
            continue
        values: list[str] = []
        value_node = None
        for sib in strong.next_siblings:
            name = getattr(sib, "name", None)
            if name in ("strong", "b"):
                break
            if hasattr(sib, "get_text"):
                values.append(sib.get_text(" ", strip=True))
                value_node = sib
            else:
                values.append(str(sib))
        value = " ".join(v.strip() for v in values if v.strip()).strip()
        if not value and strong.parent is not None:
            nxt = strong.parent.find_next_sibling()
            if nxt is not None and hasattr(nxt, "get_text"):
                value = nxt.get_text("\n", strip=True)
                value_node = nxt
        value = value.strip(" \t\r\n|—-")
        if value:
            pairs.append((label, value, value_node))
    return pairs


def _find_pair_value(
    pairs: list[tuple[str, str, Any]],
    aliases: tuple[str, ...],
    exclude: tuple[str, ...] = (),
) -> str:
    norm_aliases = [normalize_text(a) for a in aliases]
    for label, value, _ in pairs:
        nl = normalize_text(label)
        if not nl or any(ex in nl for ex in exclude):
            continue
        for na in norm_aliases:
            if not na:
                continue
            padded = f" {nl} "
            if nl == na or nl.startswith(na + " ") or nl.endswith(" " + na) or f" {na} " in padded:
                return value
    return ""


def _extract_events(block) -> list[dict]:
    events: list[dict] = []
    seen: set[int] = set()
    for el in block.find_all(True):
        classes = normalize_text(" ".join(el.get("class") or []))
        if "event" not in classes and not el.has_attr("data-result"):
            continue
        if any(id(parent) in seen for parent in el.parents):
            continue
        cycle = el.get("data-cycle")
        if cycle is not None and str(cycle).strip() == "0":
            continue
        text = el.get_text(" ", strip=True)
        ntext = normalize_text(text)
        if "initial discovery" in ntext and "retest" not in ntext:
            continue

        date = None
        m = re.search(
            r"\d{4}-\d{1,2}-\d{1,2}|\d{1,2}[./]\d{1,2}[./]\d{4}|"
            r"\d{1,2}\s+[A-Za-zÇĞİÖŞÜçğıöşü]+\s+\d{4}",
            text,
        )
        if m:
            date = _to_ms(m.group(0))

        tester = ""
        tm = re.search(r"Tester\s*[:=]\s*([^|()\n]+)", text, re.IGNORECASE)
        if tm:
            tester = tm.group(1).strip()

        result = _event_result(el.get("data-result") or "")
        if not result:
            rm = re.search(r"\b(PASSED|FAILED|VULNERABLE|FIXED)\b", text, re.IGNORECASE)
            if rm:
                result = _event_result(rm.group(1))

        note = ""
        p = el.find("p")
        if p is not None:
            note = p.get_text(" ", strip=True)

        events.append({"date": date, "tester": tester, "result": result, "note": note})
        seen.add(id(el))
    return events


def _extract_block(block, page_asset: str = "") -> Optional[dict]:
    cand: dict[str, Any] = {}
    pairs = _label_values(block)

    heading = block.find(["h1", "h2", "h3", "h4"])
    title = heading.get_text(" ", strip=True) if heading else ""
    if not title:
        for el in block.find_all(True):
            classes = " ".join(el.get("class") or [])
            if re.search(r"\b(title|name)\b", classes, re.IGNORECASE):
                title = el.get_text(" ", strip=True)
                if title:
                    break
    if not title:
        for strong in block.find_all("strong"):
            title = strong.get_text(" ", strip=True)
            if len(title) >= 3:
                break
    if not title:
        return None

    ref = ""
    severity = ""
    m = re.match(r"^\s*\[([^\]]+)\]\s*(.*)$", title, re.DOTALL)
    if m:
        token = m.group(1).strip()
        title = m.group(2).strip()
        token_severity = _severity_from_text(token)
        if token_severity:
            severity = token_severity
        else:
            ref = token

    if not ref:
        m = re.match(r"^\s*([A-Za-z]{1,12}[-_ ]?\d{1,8})\s*[:.\-–—]\s*(.+)$", title, re.DOTALL)
        if m:
            ref = m.group(1).strip()
            title = m.group(2).strip()

    suffix_status = suffix_retest = None
    m = re.search(r"\s*[—–-]\s*([^—–-]{2,40})\s*$", title)
    if m:
        st, rs = _status_values(m.group(1))
        if st is not None or rs:
            suffix_status, suffix_retest = st, rs
            title = title[: m.start()].strip()

    if not severity:
        severity = _severity_from_text(" ".join(block.get("class") or []))
    if not severity:
        for el in block.find_all(["span", "div", "p", "strong", "b"]):
            classes = normalize_text(" ".join(el.get("class") or []))
            if any(k in classes for k in ("severity", "sev", "badge", "risk", "status")):
                severity = _severity_from_text(el.get_text(" ", strip=True))
                if severity:
                    break
    if not severity:
        severity = _severity_from_text(title)

    cvss, vector = "", ""
    for label, value, _ in pairs:
        if "cvss" in normalize_text(label):
            cvss, vector = _parse_cvss_value(value)
            if cvss:
                break
    if not cvss:
        text_all = block.get_text(" ", strip=True)
        if "cvss" in normalize_text(text_all):
            cvss, vector = _parse_cvss_value(text_all)
        else:
            # Only trust an explicit score+vector pair; avoid dates/HTTP versions.
            m = re.search(r"(?<![\d.])(\d{1,2}(?:\.\d)?)\s*\((AV:[^)]+)\)", text_all)
            if m:
                cvss, vector = m.group(1), m.group(2).strip()

    text_all = block.get_text(" ", strip=True)
    m = re.search(r"CVE-\d{4}-\d{4,7}", text_all, re.IGNORECASE)
    cve = m.group(0).upper() if m else ""
    m = re.search(r"CWE-\d+", text_all, re.IGNORECASE)
    cwe = m.group(0).upper() if m else ""

    status_val, retest_val = suffix_status, suffix_retest
    if block.has_attr("data-status"):
        st, rs = _status_values(block.get("data-status"))
        if status_val is None:
            status_val = st
        if not retest_val:
            retest_val = rs

    for label, value, _ in pairs:
        nl = normalize_text(label)
        if "retest" in nl and any(k in nl for k in ("status", "durum", "sonuc", "result")):
            _, rs = _status_values(value)
            if not retest_val:
                retest_val = rs
        elif "status" in nl or "durum" in nl:
            st, rs = _status_values(value)
            if status_val is None:
                status_val = st
            if not retest_val:
                retest_val = rs

    if status_val is None or not retest_val:
        for el in block.find_all(["span", "div", "p", "strong", "b"]):
            classes = normalize_text(" ".join(el.get("class") or []))
            if any(k in classes for k in ("badge", "status", "st-")):
                st, rs = _status_values(el.get_text(" ", strip=True))
                if status_val is None and st is not None:
                    status_val = st
                if not retest_val and rs:
                    retest_val = rs
                if status_val is not None and retest_val:
                    break

    retest_by = ""
    retest_by_value = _find_pair_value(pairs, ("tester", "retest by", "test eden", "retest yapan"))
    if retest_by_value:
        retest_by = retest_by_value
    retest_date = _to_ms(
        _find_pair_value(pairs, ("retest tarihi", "dogrulama tarihi", "verification date", "retest date"))
    )

    events = _extract_events(block)
    if events:
        cand["retest_history"] = events
        last = events[-1]
        if last.get("result"):
            retest_val = last["result"]
        if last.get("tester"):
            retest_by = last["tester"]
        if last.get("date") is not None:
            retest_date = last["date"]

    desc = _find_pair_value(pairs, _GENERIC_DESC_ALIASES)
    if not desc:
        for p in block.find_all("p"):
            if p.find(["strong", "b"]):
                continue
            desc = p.get_text(" ", strip=True)
            if desc:
                break

    poc = ""
    pre = block.find("pre")
    if pre is not None:
        poc = pre.get_text("\n", strip=True)
    if not poc:
        diffcols = [
            el for el in block.find_all(True)
            if any("diff-col" in str(c) for c in (el.get("class") or []))
        ]
        if diffcols:
            poc = "\n\n".join(el.get_text("\n", strip=True) for el in diffcols)
    if not poc:
        poc = _find_pair_value(pairs, _GENERIC_POC_ALIASES)

    remediation = _find_pair_value(pairs, _GENERIC_REMEDIATION_ALIASES)

    asset = _find_pair_value(pairs, _GENERIC_ASSET_ALIASES)
    if re.search(r"\b\d{1,5}\s*/\s*(tcp|udp)\b", asset, re.IGNORECASE) and page_asset:
        asset = f"{page_asset} — {asset}"
    elif not asset:
        asset = page_asset

    cand["title"] = title
    if ref:
        cand["ref"] = ref
    if severity:
        cand["severity"] = severity
    if cvss:
        cand["cvss"] = cvss
    if vector:
        cand["cvss_vector"] = vector
    if cve:
        cand["cve"] = cve
    if cwe:
        cand["cwe"] = cwe
    if status_val is not None:
        cand["status"] = status_val
    if retest_val:
        cand["retest_status"] = retest_val
    if retest_by:
        cand["retest_by"] = retest_by
    if retest_date is not None:
        cand["retest_date"] = retest_date
    if desc:
        cand["desc"] = desc
    if poc:
        cand["poc"] = poc
    if remediation:
        cand["remediation"] = remediation
    if asset:
        cand["asset"] = asset
    cand["_source"] = "generic"
    return cand


def _extract_repeated_blocks(soup, page_asset: str = "") -> list[dict]:
    found = []
    for el in soup.find_all(True):
        if el.name in ("html", "body", "head"):
            continue
        classes = " ".join(el.get("class") or [])
        ident = el.get("id") or ""
        cid = normalize_text(classes + " " + ident)
        if not cid or "header" in cid or "title" in cid:
            continue
        if not any(word in cid for word in _GENERIC_BLOCK_WORDS):
            continue
        if not el.find(["h1", "h2", "h3", "h4"]):
            continue
        found.append(el)

    # Prefer the innermost candidate when blocks are nested.
    found_ids = {id(el) for el in found}
    candidates = [
        el for el in found
        if not any(id(desc) in found_ids for desc in el.find_all(True))
    ]

    results = []
    for el in candidates:
        cand = _extract_block(el, page_asset)
        if cand and cand.get("title"):
            results.append(cand)
    return results


def _extract_table_candidates(soup, page_asset: str = "") -> list[dict]:
    results: list[dict] = []
    for table in soup.find_all("table"):
        rows = table.find_all("tr")
        header_row = None
        header: list[str] = []
        for row in rows:
            ths = row.find_all("th")
            if ths:
                header = [th.get_text(" ", strip=True) for th in ths]
                header_row = row
                break
        if header_row is None or not header:
            continue

        field_idx: dict[str, int] = {}
        for idx, text in enumerate(header):
            for field in _table_header_fields(text):
                field_idx.setdefault(field, idx)
        if "title" not in field_idx or len(field_idx) < 2:
            continue

        started = False
        for row in rows:
            if row is header_row:
                started = True
                continue
            if not started:
                continue
            cells = row.find_all("td")
            if not cells:
                continue

            def cell_text(field: str) -> str:
                idx = field_idx.get(field)
                if idx is None or idx >= len(cells):
                    return ""
                return cells[idx].get_text(" ", strip=True)

            title = cell_text("title")
            if not title:
                continue

            cand: dict[str, Any] = {"title": title, "_source": "generic"}
            ref = cell_text("ref")
            if ref:
                cand["ref"] = ref

            sev_text = cell_text("severity")
            cvss_text = cell_text("cvss")
            severity = _severity_from_text(sev_text) or _severity_from_text(cvss_text)
            if severity:
                cand["severity"] = severity
            cvss, vector = _parse_cvss_value(cvss_text or sev_text)
            if cvss:
                cand["cvss"] = cvss
            if vector:
                cand["cvss_vector"] = vector

            status_val, retest_val = None, None
            if row.has_attr("data-status"):
                status_val, retest_val = _status_values(row.get("data-status"))
            status_text = cell_text("status")
            if status_val is None and status_text:
                status_val = _status_values(status_text)[0]
            retest_text = cell_text("retest_status")
            if not retest_val and retest_text:
                retest_val = _status_values(retest_text)[1]
            if status_val is not None:
                cand["status"] = status_val
            if retest_val:
                cand["retest_status"] = retest_val

            retest_date_text = cell_text("retest_date")
            if retest_date_text:
                retest_date = _to_ms(retest_date_text)
                if retest_date is not None:
                    cand["retest_date"] = retest_date

            cve_text = cell_text("cve")
            if cve_text:
                cve = _normalize_cve(cve_text)
                if cve:
                    cand["cve"] = cve
            cwe_text = cell_text("cwe")
            if cwe_text:
                cand["cwe"] = cwe_text
            asset_text = cell_text("asset")
            asset = asset_text or page_asset
            if asset:
                cand["asset"] = asset

            results.append(cand)
    return results


def _norm_ref(value) -> str:
    return re.sub(r"[^a-z0-9]", "", normalize_text(str(value or "")))


def _title_similar(a: str, b: str) -> bool:
    if not a or not b:
        return False
    if a in b or b in a:
        return True
    return difflib.SequenceMatcher(None, a, b).ratio() >= 0.6


def _merge_generic(table_cands: list[dict], block_cands: list[dict]) -> list[dict]:
    merged = [dict(c) for c in table_cands]
    win_fields = (
        "desc", "poc", "remediation", "asset", "cve", "cvss", "cvss_vector",
        "cwe", "status", "retest_status", "retest_by", "retest_date", "retest_history",
    )

    for block in block_cands:
        block_ref = _norm_ref(block.get("ref", ""))
        match_idx = None
        for idx, row in enumerate(merged):
            row_ref = _norm_ref(row.get("ref", ""))
            if block_ref and row_ref and block_ref == row_ref:
                match_idx = idx
                break
        if match_idx is None:
            block_title = normalize_text(block.get("title", ""))
            for idx, row in enumerate(merged):
                if _title_similar(block_title, normalize_text(row.get("title", ""))):
                    match_idx = idx
                    break

        if match_idx is None:
            merged.append(dict(block))
            continue

        row = merged[match_idx]
        for field in win_fields:
            value = block.get(field)
            if value not in (None, "", [], {}):
                row[field] = value
        if not row.get("ref") and block.get("ref"):
            row["ref"] = block["ref"]

    deduped: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for cand in merged:
        key = (_norm_ref(cand.get("ref", "")), normalize_text(cand.get("title", "")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cand)
    return deduped


def _page_asset(soup) -> str:
    el = soup.select_one(".host-header") or soup.select_one("[data-host]")
    if el is not None:
        value = (el.get("data-host") or "").strip() or el.get_text(" ", strip=True)
        if value:
            return value

    value = _find_pair_value(
        _label_values(soup),
        ("hedef sistem", "target host", "target system", "host", "url", "asset"),
    )
    if value:
        return value

    for table in soup.find_all("table"):
        header_row = None
        header: list[str] = []
        for row in table.find_all("tr"):
            ths = row.find_all("th")
            if ths:
                header = [th.get_text(" ", strip=True) for th in ths]
                header_row = row
                break
        if header_row is None:
            continue
        for idx, text in enumerate(header):
            if "asset" not in _table_header_fields(text):
                continue
            started = False
            for row in table.find_all("tr"):
                if row is header_row:
                    started = True
                    continue
                if not started:
                    continue
                cells = row.find_all("td")
                if idx < len(cells):
                    cell = cells[idx].get_text(" ", strip=True)
                    if cell:
                        return cell
    return ""


def _generic_report_title(soup, filename: str) -> str:
    if soup.title is not None:
        title = soup.title.get_text(" ", strip=True)
        if title:
            return title
    h1 = soup.find("h1")
    if h1 is not None:
        title = h1.get_text(" ", strip=True)
        if title:
            return title
    return Path(filename).stem if filename else "Imported legacy report"


def extract_generic(html: str, filename: str = "") -> Optional[dict]:
    """Extract findings from summary tables and repeated finding blocks.

    Returns a report dict, a report-only dict (no findings) for recognized
    security reports, or None when the page does not look like a report.
    """
    soup = BeautifulSoup(html, "html.parser")
    page_asset = _page_asset(soup)

    table_candidates = _extract_table_candidates(soup, page_asset)
    block_candidates = _extract_repeated_blocks(soup, page_asset)
    candidates = _merge_generic(table_candidates, block_candidates)

    for cand in candidates:
        cand["_source"] = "generic"

    if candidates:
        return {
            "report_name": _generic_report_title(soup, filename),
            "report_scope": "",
            "report_createdate": None,
            "report_vulns": candidates,
            "_warnings": [],
        }

    page_text = normalize_text(soup.get_text(" ", strip=True))
    if any(word in page_text for word in _GENERIC_REPORT_WORDS):
        return {
            "report_name": _generic_report_title(soup, filename),
            "report_scope": "",
            "report_createdate": None,
            "report_vulns": [],
            "_warnings": ["no individual findings detected"],
        }
    return None


# ---------------------------------------------------------------------------
# AI extraction
# ---------------------------------------------------------------------------

def _clean_html_for_ai(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "noscript", "header", "aside"]):
        tag.decompose()
    text = soup.get_text("\n", strip=True)
    lines = [ln.strip() for ln in text.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def _chunk_text(text: str, size: int = 20000) -> list[str]:
    chunks = []
    lines = text.splitlines()
    current: list[str] = []
    cur_len = 0
    for ln in lines:
        ln_len = len(ln) + 1
        if cur_len + ln_len > size and current:
            chunks.append("\n".join(current))
            current = [ln]
            cur_len = ln_len
        else:
            current.append(ln)
            cur_len += ln_len
    if current:
        chunks.append("\n".join(current))
    return chunks or [text]


def _ai_prompt(chunk: str) -> str:
    return (
        "You are a security findings extraction assistant. The source HTML may use Turkish or English labels.\n"
        "Return ONLY a JSON array of finding objects. Do not include any explanation, markdown, or code fences.\n"
        "Each object must use English keys: title, description, poc, remediation, severity, status, retest_status, retest_by, retest_date, cve, cvss, cvss_vector, cwe, tags, asset.\n"
        "Rules:\n"
        "- severity: normalize to one of Critical, High, Medium, Low, Info.\n"
        "- status: normalize to one of open, in_progress, fixed, wont_fix, retest_pending, passed, still_present, closed.\n"
        "- retest_status: normalize to passed, failed, pending, or null.\n"
        "- cve: if present, format as CVE-YYYY-NNNN.\n"
        "- tags: array of strings.\n"
        "- Preserve title/description/poc/remediation text in the original language. Do not translate.\n"
        "- Do not invent missing fields. If a field is absent, omit it.\n"
        "- If no findings are present, return an empty array [].\n\n"
        "HTML TEXT:\n" + chunk
    )


def _call_ai(chunk: str, endpoint: str, api_key: str, model: str) -> Optional[list[dict]]:
    import requests
    if not endpoint or not api_key:
        return None
    url = endpoint.rstrip("/")
    if "/chat/" not in url and "/chat" not in url:
        url = url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model or "gpt-4o-mini",
        "messages": [{"role": "user", "content": _ai_prompt(chunk)}],
        "temperature": 0,
    }
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=120)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"[warn] AI request failed: {exc}")
        return None
    try:
        content = data["choices"][0]["message"]["content"]
    except Exception:
        return None
    parsed = _parse_json_robust(content)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for k in ("findings", "issues", "vulnerabilities", "results", "candidates"):
            if k in parsed and isinstance(parsed[k], list):
                return parsed[k]
    return None


def extract_ai(html: str, endpoint: Optional[str] = None, api_key: Optional[str] = None, model: Optional[str] = None) -> Optional[list[dict]]:
    """Extract findings via an OpenAI-compatible chat API. Returns list of candidate dicts or None."""
    if not endpoint or not api_key:
        return None
    cleaned = _clean_html_for_ai(html)
    chunks = _chunk_text(cleaned)
    all_findings: list[dict] = []
    for chunk in chunks:
        findings = _call_ai(chunk, endpoint, api_key, model)
        if findings:
            for finding in findings:
                if isinstance(finding, dict):
                    finding["_source"] = "ai"
                    all_findings.append(finding)
    return all_findings or None


# ---------------------------------------------------------------------------
# Date / value helpers
# ---------------------------------------------------------------------------

def _to_ms(value) -> Optional[int]:
    """Convert various date representations to ms epoch."""
    import datetime as dt

    if value is None:
        return None
    if isinstance(value, (int, float)):
        v = int(value)
        return v if v >= 10**12 else v * 1000
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if s.isdigit():
        if len(s) == 8:
            try:
                d = dt.datetime(
                    int(s[:4]), int(s[4:6]), int(s[6:8]), tzinfo=dt.timezone.utc
                )
                return int(d.timestamp() * 1000)
            except Exception:
                return None
        v = int(s)
        return v if v >= 10**12 else v * 1000
    # ISO yyyy-mm-dd
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})", s)
    if m:
        try:
            d = dt.datetime(
                int(m.group(1)), int(m.group(2)), int(m.group(3)),
                tzinfo=dt.timezone.utc,
            )
            return int(d.timestamp() * 1000)
        except Exception:
            pass
    # dd.mm.yyyy or dd/mm/yyyy
    m = re.match(r"^(\d{1,2})[./](\d{1,2})[./](\d{4})", s)
    if m:
        try:
            d = dt.datetime(
                int(m.group(3)), int(m.group(2)), int(m.group(1)),
                tzinfo=dt.timezone.utc,
            )
            return int(d.timestamp() * 1000)
        except Exception:
            pass
    # dd Month yyyy / dd Mon yyyy
    m = re.match(r"^(\d{1,2})\s+([A-Za-zğüşıöçĞÜŞİÖÇ]+)\s+(\d{4})", s)
    if m:
        month = MONTHS.get(normalize_text(m.group(2)))
        if month:
            try:
                d = dt.datetime(
                    int(m.group(3)), month, int(m.group(1)),
                    tzinfo=dt.timezone.utc,
                )
                return int(d.timestamp() * 1000)
            except Exception:
                pass
    return None


def _normalize_tags(value) -> list[dict]:
    """Normalize tags into [{"name": str}, ...]."""
    if value is None:
        return []
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, str):
                out.append({"name": item})
            elif isinstance(item, dict):
                name = item.get("name") or item.get("tag") or item.get("label")
                if name:
                    out.append({"name": str(name)})
            elif isinstance(item, (int, float)):
                out.append({"name": str(item)})
        return out
    if isinstance(value, dict):
        name = value.get("name") or value.get("tag")
        return [{"name": str(name)}] if name else []
    if isinstance(value, str):
        parts = [p.strip() for p in re.split(r"[,\n;]", value) if p.strip()]
        return [{"name": p} for p in parts]
    return []


def _normalize_cve(value) -> str:
    if not value:
        return ""
    s = str(value).strip()
    m = re.search(r"CVE-(\d{4})-(\d{4,7})", s, re.IGNORECASE)
    if m:
        return f"CVE-{m.group(1)}-{m.group(2)}"
    return s.upper()


def _normalize_cvss(value) -> str:
    if value is None:
        return ""
    s = str(value).strip().replace(",", ".")
    return s


def _normalize_severity(value) -> str:
    if not value:
        return ""
    if isinstance(value, (int, float)):
        v = int(value)
        return {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}.get(v, "")
    return SEVERITY_MAP.get(normalize_text(str(value)), "")


def _normalize_status(value) -> int:
    if value is None:
        return 1
    if isinstance(value, int):
        if 1 <= value <= 8:
            return value
        return 1
    if isinstance(value, (float,)):
        return _normalize_status(int(value))
    s = normalize_text(str(value))
    if s in STATUS_MAP:
        return STATUS_MAP[s]
    # try direct int
    if s.isdigit():
        v = int(s)
        return v if 1 <= v <= 8 else 1
    return 1


def _normalize_retest_status(value) -> str:
    if value is None:
        return ""
    return RETEST_STATUS_MAP.get(normalize_text(str(value)), "")


def _normalize_retest_history(value) -> list[dict]:
    if not value or not isinstance(value, list):
        return []
    out = []
    for item in value:
        if not isinstance(item, dict):
            continue
        entry = {}
        if "date" in item:
            entry["date"] = _to_ms(item["date"])
        if "tester" in item or "retest_by" in item or "test_eden" in item:
            entry["tester"] = str(item.get("tester") or item.get("retest_by") or item.get("test_eden") or "")
        if "result" in item or "retest_status" in item or "retest_sonucu" in item:
            entry["result"] = _normalize_retest_status(item.get("result") or item.get("retest_status") or item.get("retest_sonucu"))
        if "note" in item:
            entry["note"] = str(item["note"])
        if "attachments" in item:
            entry["attachments"] = item["attachments"]
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Candidate normalization
# ---------------------------------------------------------------------------

_ALIAS_KEYS = {
    "title": ["title", "name", "baslik", "vulnerability", "finding", "baslik"],
    "desc": ["desc", "description", "aciklama", "details", "body", "content", "explain"],
    "poc": ["poc", "proof", "proof_of_concept", "kanit", "reproduction", "steps"],
    "remediation": ["remediation", "remed", "solution", "cozum", "oneri", "fix", "recommendation"],
    "severity": ["severity", "onem", "risk", "level", "priority"],
    "status": ["status", "durum", "state", "phase"],
    "cve": ["cve", "cve_id", "cveid"],
    "cvss": ["cvss", "cvss_score", "score"],
    "cvss_vector": ["cvss_vector", "cvssvec", "vector"],
    "cwe": ["cwe", "cwe_id", "weakness"],
    "tags": ["tags", "etiketler", "labels", "label", "category"],
    "asset": ["asset", "varlik", "host", "target", "url", "endpoint", "affected"],
    "retest_status": ["retest_status", "retest_result", "retest_sonucu", "retest", "test_result", "test_sonucu"],
    "retest_by": ["retest_by", "tester", "test_eden", "tested_by", "reviewer"],
    "retest_date": ["retest_date", "retest_tarihi", "test_date"],
}


def _pick_alias(raw: dict, field: str) -> Any:
    keys = list(FIELD_ALIASES.get(field, []))
    if field not in keys:
        keys.append(field)
    for key in keys:
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    normalized: dict[str, Any] = {}
    for key, value in raw.items():
        if value in (None, ""):
            continue
        normalized.setdefault(normalize_text(str(key)), value)
    for key in keys:
        nkey = normalize_text(str(key))
        if nkey in normalized:
            return normalized[nkey]
    for key in _ALIAS_KEYS.get(field, []):
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    return None


def normalize_candidate(raw: dict, aliases: Optional[dict] = None) -> dict:
    """Normalize a raw candidate dict into the internal schema."""
    raw = raw or {}
    title = _pick_alias(raw, "title")
    if title is None:
        for k in ("baslik", "baslik", "name"):
            if k in raw and raw[k]:
                title = raw[k]
                break
    title = str(title).strip() if title is not None else ""

    desc = _pick_alias(raw, "desc")
    desc = str(desc).strip() if desc is not None else ""

    poc = _pick_alias(raw, "poc")
    poc = str(poc).strip() if poc is not None else ""

    remediation = _pick_alias(raw, "remediation")
    remediation = str(remediation).strip() if remediation is not None else ""

    severity = _normalize_severity(_pick_alias(raw, "severity"))
    status = _normalize_status(_pick_alias(raw, "status"))
    cve = _normalize_cve(_pick_alias(raw, "cve"))
    cvss = _normalize_cvss(_pick_alias(raw, "cvss"))
    cvss_vector = str(_pick_alias(raw, "cvss_vector") or "").strip()
    cwe = str(_pick_alias(raw, "cwe") or "").strip()
    asset = str(_pick_alias(raw, "asset") or "").strip()
    tags = _normalize_tags(_pick_alias(raw, "tags"))
    retest_status = _normalize_retest_status(_pick_alias(raw, "retest_status"))
    retest_by = str(_pick_alias(raw, "retest_by") or "").strip()
    retest_date = _to_ms(_pick_alias(raw, "retest_date"))
    retest_history = _normalize_retest_history(raw.get("retest_history"))

    ref = str(raw.get("ref") or raw.get("reference") or "").strip()

    warnings: list[str] = []
    if not title:
        warnings.append("missing title")
    if raw.get("_warnings"):
        warnings.extend(str(w) for w in raw["_warnings"])

    return {
        "title": title,
        "severity": severity,
        "status": status,
        "cve": cve,
        "cvss": cvss,
        "cvss_vector": cvss_vector,
        "cwe": cwe,
        "desc": desc,
        "poc": poc,
        "remediation": remediation,
        "ref": ref,
        "asset": asset,
        "tags": tags,
        "retest_status": retest_status,
        "retest_by": retest_by,
        "retest_date": retest_date,
        "retest_history": retest_history,
        "_source": str(raw.get("_source", "")),
        "_warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Manual fallback
# ---------------------------------------------------------------------------

def manual_report(html: str, filename: str = "") -> dict:
    """Build a single-candidate manual skeleton report."""
    soup = BeautifulSoup(html, "html.parser")
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    if not title:
        h1 = soup.find("h1")
        if h1:
            title = h1.get_text(strip=True)
    if not title:
        title = Path(filename).stem if filename else "Imported legacy report"
    for tag in soup(["script", "style", "nav", "footer", "noscript"]):
        tag.decompose()
    desc = soup.get_text("\n", strip=True)
    desc = re.sub(r"\n{3,}", "\n\n", desc)
    return {
        "report_name": title,
        "report_scope": "",
        "report_createdate": None,
        "report_vulns": [
            {
                "title": title,
                "severity": "",
                "status": 1,
                "cve": "",
                "cvss": "",
                "cvss_vector": "",
                "cwe": "",
                "desc": desc,
                "poc": "",
                "remediation": "",
                "ref": "",
                "asset": "",
                "tags": [],
                "retest_status": "",
                "retest_by": "",
                "retest_date": None,
                "retest_history": [],
                "_source": "manual",
                "_warnings": ["manual skeleton"],
            }
        ],
        "_warnings": ["manual skeleton"],
    }


# ---------------------------------------------------------------------------
# Report cleaning
# ---------------------------------------------------------------------------

def _strip_underscore(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_underscore(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [_strip_underscore(v) for v in obj]
    return obj


def clean_report(report: dict) -> dict:
    """Deep-copy and remove keys starting with '_'. Ensure report_vulns list."""
    cleaned = _strip_underscore(dict(report))
    if "report_vulns" not in cleaned or not isinstance(cleaned.get("report_vulns"), list):
        cleaned["report_vulns"] = []
    if not cleaned.get("report_name"):
        cleaned["report_name"] = "Imported legacy report"
    return cleaned


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def _auto_match_profile(filename: str, profiles_dir: Path) -> Optional[Path]:
    """Find a profile whose 'match' regex matches the filename."""
    if not profiles_dir.exists():
        return None
    for path in sorted(profiles_dir.glob("*.json")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                prof = json.load(fh)
        except Exception:
            continue
        match = prof.get("match")
        if not match:
            continue
        try:
            if re.search(match, filename, re.IGNORECASE):
                return path
        except re.error:
            continue
    return None


def extract(
    path,
    password: Optional[str] = None,
    profile: Optional[str] = None,
    use_ai: bool = True,
    ai_endpoint: Optional[str] = None,
    ai_api_key: Optional[str] = None,
    ai_model: Optional[str] = None,
) -> dict:
    """Extract a report from HTML using the cascade: embedded -> profile -> AI -> manual."""
    html = read_html(path)
    filename = Path(path).name
    warnings: list[str] = []

    # 1. Embedded
    try:
        embedded = extract_embedded(html, password=password)
    except ValueError as exc:
        raise
    except Exception as exc:
        embedded = None
        warnings.append(f"embedded extraction error: {exc}")

    if embedded and embedded.get("report_vulns"):
        embedded["_warnings"] = list(embedded.get("_warnings", [])) + warnings
        return _finalize_report(embedded, filename)

    # 2. Profile
    profile_path = None
    if profile:
        profile_path = Path(profile)
        if not profile_path.exists():
            warnings.append(f"profile not found: {profile}")
            profile_path = None
    if profile_path is None:
        profiles_dir = _HERE / "profiles"
        profile_path = _auto_match_profile(filename, profiles_dir)

    if profile_path:
        try:
            prof_report = extract_profile(html, profile_path)
        except Exception as exc:
            prof_report = None
            warnings.append(f"profile extraction error: {exc}")
        if prof_report:
            prof_report["_warnings"] = list(prof_report.get("_warnings", [])) + warnings
            return _finalize_report(prof_report, filename)

    # 3. Generic structural extraction
    generic = extract_generic(html, filename)
    if generic is not None:
        generic["_warnings"] = list(generic.get("_warnings", [])) + warnings
        return _finalize_report(generic, filename)

    # 4. AI
    if use_ai:
        try:
            ai_findings = extract_ai(html, endpoint=ai_endpoint, api_key=ai_api_key, model=ai_model)
        except Exception as exc:
            ai_findings = None
            warnings.append(f"AI extraction error: {exc}")
        if ai_findings:
            ai_report = {
                "report_name": f"AI-extracted from {filename}",
                "report_scope": "",
                "report_createdate": None,
                "report_vulns": ai_findings,
                "_warnings": [],
            }
            ai_report["_warnings"] = warnings
            return _finalize_report(ai_report, filename)

    # 5. Manual fallback
    manual = manual_report(html, filename)
    manual["_warnings"] = list(manual.get("_warnings", [])) + warnings
    return _finalize_report(manual, filename)


def _finalize_report(report: dict, filename: str) -> dict:
    """Normalize candidates inside a report, dropping title-less ones (except manual)."""
    vulns = report.get("report_vulns", [])
    normalized: list[dict] = []
    for raw in vulns:
        if not isinstance(raw, dict):
            continue
        cand = normalize_candidate(raw)
        if not cand["title"]:
            if cand["_source"] == "manual":
                pass
            else:
                report.setdefault("_warnings", []).append("dropped candidate with empty title")
                continue
        normalized.append(cand)
    report["report_vulns"] = normalized
    if not report.get("report_name"):
        report["report_name"] = "Imported legacy report"
    return report
