"""
SecureTrace - Stealth Source Watermark Engine

This version avoids explicit watermark markers and embeds forensic bits only via:
1) trailing whitespace pattern
2) subtle comment punctuation/casing variants
"""

import hashlib
import hmac
import os
import re
from datetime import datetime
from difflib import SequenceMatcher


_SECRET = "securetrace-source-v1"
_WS_BITS = 32
_COMMENT_BITS = 12


_LANG_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
}


_COMMENT_PREFIX = {
    "python": "#",
    "javascript": "//",
    "java": "//",
    "cpp": "//",
}


def detect_language(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    return _LANG_MAP.get(ext, "python")


def _bitstring_from_bytes(raw: bytes) -> str:
    return "".join(format(b, "08b") for b in raw)


def _fingerprints(employee_id: str, filename: str) -> tuple[str, str]:
    """Return fixed-length bit fingerprints for whitespace and comment layers."""
    payload = f"{employee_id}|{filename}".encode("utf-8")
    digest = hmac.new(_SECRET.encode("utf-8"), payload, hashlib.sha256).digest()
    bits = _bitstring_from_bytes(digest)
    ws_bits = bits[:_WS_BITS]
    cm_bits = bits[_WS_BITS:_WS_BITS + _COMMENT_BITS]
    return ws_bits, cm_bits


def _normalize_newline(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    return line, ""


def _encode_whitespace(lines: list[str], bits: str) -> tuple[list[str], int]:
    """
    Encode bits using trailing spaces on non-empty lines.
    1 trailing space -> 0
    2 trailing spaces -> 1
    """
    out: list[str] = []
    bit_idx = 0

    for line in lines:
        body, nl = _normalize_newline(line)
        clean = body.rstrip(" \t")

        if bit_idx < len(bits) and clean.strip():
            trailer = "  " if bits[bit_idx] == "1" else " "
            out.append(clean + trailer + nl)
            bit_idx += 1
        else:
            out.append(body + nl)

    return out, bit_idx


def _decode_whitespace(lines: list[str]) -> str:
    bits: list[str] = []
    for line in lines:
        body, _ = _normalize_newline(line)
        if not body.strip():
            continue
        trailing_spaces = len(body) - len(body.rstrip(" "))
        if trailing_spaces == 1:
            bits.append("0")
        elif trailing_spaces == 2:
            bits.append("1")
    return "".join(bits)


def _comment_line_regex(lang: str) -> re.Pattern:
    if lang == "python":
        return re.compile(r"^(\s*)#(.*)$")
    return re.compile(r"^(\s*)//(.*)$")


def _encode_comment_variants(lines: list[str], bits: str, lang: str) -> tuple[list[str], int]:
    """
    Encode bits on comment lines via punctuation:
    bit 0 => no trailing period
    bit 1 => trailing period
    """
    rx = _comment_line_regex(lang)
    out = lines[:]
    bit_idx = 0

    for i, line in enumerate(out):
        if bit_idx >= len(bits):
            break

        body, nl = _normalize_newline(line)
        m = rx.match(body)
        if not m:
            continue

        indent = m.group(1)
        content = m.group(2).rstrip()
        if not content.strip():
            continue

        text = content.rstrip(".")
        if bits[bit_idx] == "1":
            text = text + "."
        out[i] = f"{indent}{_COMMENT_PREFIX.get(lang, '#')}{text}{nl}"
        bit_idx += 1

    return out, bit_idx


def _decode_comment_variants(lines: list[str], lang: str) -> str:
    rx = _comment_line_regex(lang)
    bits: list[str] = []

    for line in lines:
        body, _ = _normalize_newline(line)
        m = rx.match(body)
        if not m:
            continue

        content = m.group(2).rstrip()
        if not content.strip():
            continue

        bits.append("1" if content.endswith(".") else "0")

    return "".join(bits)


def _decode_comment_variants_ocr(lines: list[str]) -> str:
    """
    OCR fallback: decode only neutral filler tokens used by this engine.
    Accepts lines like '# note', '// review.', or even 'note.' after OCR cleanup.
    """
    def _norm_word(w: str) -> str:
        w = w.lower()
        w = w.replace("0", "o").replace("1", "i").replace("3", "e").replace("5", "s")
        return re.sub(r"[^a-z]", "", w)

    def _is_marker(w: str) -> bool:
        if not w:
            return False
        for target in ("note", "review"):
            if SequenceMatcher(a=w, b=target).ratio() >= 0.62:
                return True
        return False

    bits: list[str] = []
    text = "\n".join(_normalize_newline(line)[0] for line in lines)

    tokens = re.findall(r"[A-Za-z0-9_]+|[.,;:]", text)
    for i, tok in enumerate(tokens):
        marker = _norm_word(tok)
        if not _is_marker(marker):
            continue

        punct = tokens[i + 1] if i + 1 < len(tokens) else ""
        bits.append("1" if punct in (".", ",", ";", ":") else "0")

    return "".join(bits)


def watermark_source(source_code: str, filename: str, employee_id: str, employee_name: str) -> tuple[str, dict]:
    """Apply stealth source watermark using whitespace + subtle comment variants."""
    lang = detect_language(filename)
    lines = source_code.splitlines(keepends=True)

    ws_bits, cm_bits = _fingerprints(employee_id, filename)

    ws_encoded, ws_count = _encode_whitespace(lines, ws_bits)
    cm_encoded, cm_count = _encode_comment_variants(ws_encoded, cm_bits, lang)

    if cm_count < len(cm_bits):
        prefix = _COMMENT_PREFIX.get(lang, "#")
        fillers: list[str] = []
        missing = len(cm_bits) - cm_count
        for j in range(missing):
            bit = cm_bits[cm_count + j]
            token = " note" if j % 2 == 0 else " review"
            ending = "." if bit == "1" else ""
            fillers.append(f"{prefix}{token}{ending}\n")
        cm_encoded.extend(fillers)
        cm_count = len(cm_bits)

    watermarked = "".join(cm_encoded)

    metadata = {
        "employee_name": employee_name,
        "filename": filename,
        "language": lang,
        "timestamp": datetime.utcnow().isoformat(),
        "ws_bits_embedded": ws_count,
        "comment_bits_embedded": cm_count,
        "ws_signature": ws_bits[:16],
        "comment_signature": cm_bits,
        "recipient_hash": hashlib.sha256(employee_id.encode("utf-8")).hexdigest()[:16],
    }
    return watermarked, metadata


def extract_watermark(source_code: str, filename: str, ocr_mode: bool = False) -> dict:
    """Extract stealth watermark signals from whitespace + subtle comment variants."""
    lang = detect_language(filename)
    lines = source_code.splitlines(keepends=True)

    ws_recovered = _decode_whitespace(lines)
    cm_primary = _decode_comment_variants(lines, lang)
    cm_ocr = _decode_comment_variants_ocr(lines) if ocr_mode else ""
    cm_recovered = cm_primary if len(cm_primary) >= len(cm_ocr) else cm_ocr

    ws_sample = ws_recovered[:_WS_BITS]
    cm_sample = cm_recovered[:_COMMENT_BITS]

    confidence = 0
    if ocr_mode:
        if len(cm_sample) >= 3:
            confidence += 35
        if len(cm_sample) >= 6:
            confidence += 25
        if len(ws_sample) >= 8:
            confidence += 40
    else:
        if len(ws_sample) >= 16:
            confidence += 65
        if len(cm_sample) >= 6:
            confidence += 35

    return {
        "filename": filename,
        "language": lang,
        "confidence": confidence,
        "layers": {
            "whitespace": {
                "bits_recovered": len(ws_recovered),
                "sample": ws_sample,
            },
            "comment": {
                "bits_recovered": len(cm_recovered),
                "sample": cm_sample,
            },
        },
        "emp_hex": None,
    }


def _bit_match_ratio(expected: str, recovered: str) -> tuple[int, int, float]:
    recovered_total = len(recovered)
    total = min(len(expected), recovered_total)
    if total == 0:
        return 0, 0, 0.0

    n = len(expected)
    m = len(recovered)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        ei = expected[i - 1]
        row = dp[i]
        prev = dp[i - 1]
        for j in range(1, m + 1):
            if ei == recovered[j - 1]:
                row[j] = prev[j - 1] + 1
            else:
                row[j] = row[j - 1] if row[j - 1] >= prev[j] else prev[j]

    matches = min(dp[n][m], total)
    return matches, total, (matches / total)


def score_employee_match(extraction_result: dict, employee_id: str, filename_override: str | None = None) -> dict:
    """Return match score and layer evidence for an employee candidate."""
    filename = filename_override or extraction_result.get("filename", "")
    expected_ws, expected_cm = _fingerprints(employee_id, filename)

    got_ws = extraction_result.get("layers", {}).get("whitespace", {}).get("sample", "")
    got_cm = extraction_result.get("layers", {}).get("comment", {}).get("sample", "")
    ws_recovered_total = extraction_result.get("layers", {}).get("whitespace", {}).get("bits_recovered", len(got_ws))
    cm_recovered_total = extraction_result.get("layers", {}).get("comment", {}).get("bits_recovered", len(got_cm))

    ws_match_len, ws_total, ws_ratio = _bit_match_ratio(expected_ws, got_ws)
    cm_match_len, cm_total, cm_ratio = _bit_match_ratio(expected_cm, got_cm)

    if ws_total and cm_total:
        ws_weight, cm_weight = 70, 30
    elif ws_total:
        ws_weight, cm_weight = 100, 0
    elif cm_total:
        ws_weight, cm_weight = 0, 100
    else:
        ws_weight, cm_weight = 0, 0

    score = int(ws_ratio * ws_weight) + int(cm_ratio * cm_weight)

    return {
        "score": score,
        "ws_match_len": ws_match_len,
        "cm_match_len": cm_match_len,
        "ws_total": ws_total,
        "cm_total": cm_total,
        "ws_ratio": round(ws_ratio, 3),
        "cm_ratio": round(cm_ratio, 3),
        "ws_recovered_total": ws_recovered_total,
        "cm_recovered_total": cm_recovered_total,
    }


def match_employee(extraction_result: dict, employee_id: str, filename_override: str | None = None) -> bool:
    """Match extracted signals against expected employee fingerprints."""
    score_info = score_employee_match(extraction_result, employee_id, filename_override)
    ws_ok = score_info["ws_total"] >= 8 and score_info["ws_ratio"] >= 0.75
    cm_ok = score_info["cm_total"] >= 4 and score_info["cm_ratio"] >= 0.66
    return ws_ok or cm_ok