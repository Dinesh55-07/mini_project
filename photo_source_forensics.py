"""
SecureTrace - Photo Based Source Forensics

Pipeline:
1) Image preprocessing (OpenCV if available)
2) OCR (pytesseract)
3) OCR cleanup for source-like text
4) Watermark extraction from reconstructed text
"""

from __future__ import annotations

import os
import shutil
from typing import Tuple

from source_watermark_engine import extract_watermark

try:
    import cv2 
except Exception: 
    cv2 = None

try:
    import numpy as np  
except Exception:  
    np = None

try:
    from PIL import Image, ImageOps, ImageFilter  
except Exception:  
    Image = None
    ImageOps = None
    ImageFilter = None

try:
    import pytesseract  
except Exception:  
    pytesseract = None


def _resolve_tesseract_cmd() -> str | None:
    env_cmd = os.getenv("TESSERACT_CMD", "").strip()
    if env_cmd and os.path.exists(env_cmd):
        return env_cmd

    in_path = shutil.which("tesseract")
    if in_path:
        return in_path

    home = os.path.expanduser("~")
    candidates = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.join(home, r"AppData\Local\Programs\Tesseract-OCR\tesseract.exe"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def _deps_available() -> Tuple[bool, list[str]]:
    missing: list[str] = []
    if pytesseract is None:
        missing.append("pytesseract")
    if cv2 is None and Image is None:
        missing.append("opencv-python or pillow")
    if _resolve_tesseract_cmd() is None:
        missing.append("tesseract-ocr")
    return (len(missing) == 0), missing


def _preprocess_with_cv2(image_path: str):
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError("Unable to read image")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    gray = cv2.GaussianBlur(gray, (3, 3), 0)

    enhanced = cv2.adaptiveThreshold(
        gray,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31,
        11,
    )
    return enhanced


def _preprocess_with_pillow(image_path: str):
    if Image is None or ImageOps is None or ImageFilter is None:
        raise ValueError("Pillow unavailable")

    img = Image.open(image_path).convert("L")
    img = ImageOps.autocontrast(img)
    img = img.filter(ImageFilter.SHARPEN)
    return img


def _ocr_text(preprocessed) -> str:
    if pytesseract is None:
        raise RuntimeError("pytesseract not installed")

    resolved = _resolve_tesseract_cmd()
    if resolved:
        pytesseract.pytesseract.tesseract_cmd = resolved

    configs = [
        "--oem 3 --psm 6",
        "--oem 3 --psm 4",
        "--oem 3 --psm 11",
    ]

    variants = [preprocessed]
    if cv2 is not None:
        try:
            if len(preprocessed.shape) == 2:
                variants.append(cv2.bitwise_not(preprocessed))
        except Exception:
            pass

    texts: list[str] = []
    seen: set[str] = set()
    for img in variants:
        for cfg in configs:
            text = pytesseract.image_to_string(img, config=cfg)
            key = text.strip()
            if key and key not in seen:
                seen.add(key)
                texts.append(text)

    return "\n".join(texts)


def _normalize_ocr_code(text: str) -> str:
    fixed = text.replace("\r\n", "\n")
    fixed = fixed.replace("\u2018", "'").replace("\u2019", "'")
    fixed = fixed.replace("\u201c", '"').replace("\u201d", '"')
    fixed = fixed.replace("`", "'")

    lines = []
    for raw in fixed.split("\n"):
        line = raw.rstrip()
        if len(line.strip()) == 0:
            continue
        if len(line) > 500:
            line = line[:500]
        lines.append(line)

    return "\n".join(lines) + ("\n" if lines else "")


def analyze_source_photo(image_path: str, guessed_source_name: str = "suspect.py") -> dict:
    """Run image -> OCR -> watermark extraction for source leak attribution."""
    ok, missing = _deps_available()
    if not ok:
        return {
            "success": False,
            "error": "Missing dependencies",
            "missing": missing,
        }

    if not os.path.exists(image_path):
        return {
            "success": False,
            "error": "Image not found",
        }

    try:
        if cv2 is not None:
            pre = _preprocess_with_cv2(image_path)
        else:
            pre = _preprocess_with_pillow(image_path)

        raw_text = _ocr_text(pre)
        normalized = _normalize_ocr_code(raw_text)
        extraction = extract_watermark(normalized, guessed_source_name, ocr_mode=True)

        return {
            "success": True,
            "ocr_text": normalized,
            "ocr_chars": len(normalized),
            "extraction": extraction,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }
