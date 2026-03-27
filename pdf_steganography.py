"""
SecureTrace - PDF Steganography Module

Converts PDF → Image, embeds encrypted watermark via LSB steganography,
then converts back to PDF. Detection extracts and decrypts the watermark.
"""

import os
import json
import hashlib
import hmac
import glob
import re
import tempfile
from typing import Tuple, Dict, Optional, Any
from datetime import datetime

try:
    from pdf2image import convert_from_path
except ImportError:
    convert_from_path = None

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    import numpy as np
except ImportError:
    np = None

try:
    from img2pdf import convert as img_to_pdf
except ImportError:
    img_to_pdf = None

try:
    from pypdf import PdfReader, PdfWriter
except ImportError:
    PdfReader = None
    PdfWriter = None

from cryptography.fernet import Fernet
import base64


PAYLOAD_SIGNATURE = b"STG1"
PDF_METADATA_TOKEN_KEY = "/SecureTraceToken"


def _check_dependencies() -> Tuple[bool, list]:
    """Check if all required dependencies are available."""
    missing = []
    if convert_from_path is None:
        missing.append("pdf2image (pip install pdf2image)")
    if Image is None:
        missing.append("Pillow (pip install Pillow)")
    if np is None:
        missing.append("numpy (pip install numpy)")
    if img_to_pdf is None:
        missing.append("img2pdf (pip install img2pdf)")
    return len(missing) == 0, missing


def _resolve_poppler_path() -> Optional[str]:
    """Resolve Poppler bin path on Windows; return None on non-Windows or if unavailable."""
    if os.name != 'nt':
        return None

    candidates = []

    env_path = os.getenv('POPPLER_PATH')
    if env_path:
        candidates.append(env_path)

    candidates.extend([
        r"C:\Program Files\poppler\Library\bin",
        r"C:\Program Files (x86)\poppler\Library\bin",
    ])

    # Support versioned folder names like poppler-25.12.0
    candidates.extend(glob.glob(r"C:\Program Files\poppler-*\Library\bin"))
    candidates.extend(glob.glob(r"C:\Program Files (x86)\poppler-*\Library\bin"))

    for candidate in candidates:
        if not candidate:
            continue
        pdfinfo_exe = os.path.join(candidate, 'pdfinfo.exe')
        if os.path.isfile(pdfinfo_exe):
            return candidate

    return None


def _derive_encryption_key(employee_email: str, pdf_filename: str) -> bytes:
    """Derive a deterministic encryption key from employee email and PDF filename."""
    payload = f"{employee_email}|{pdf_filename}".encode('utf-8')
    key_material = hashlib.sha256(payload).digest()
    # Fernet requires base64-encoded 32-byte key
    fernet_key = base64.urlsafe_b64encode(key_material)
    return fernet_key


def _encrypt_watermark_data(
    employee_email: str,
    employee_name: str,
    pdf_filename: str,
    encryption_key: bytes
) -> str:
    """Encrypt watermark metadata using Fernet (symmetric encryption)."""
    cipher = Fernet(encryption_key)
    
    watermark_dict = {
        'employee_email': employee_email,
        'employee_name': employee_name,
        'pdf_filename': pdf_filename,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    plaintext = json.dumps(watermark_dict).encode('utf-8')
    encrypted = cipher.encrypt(plaintext)
    
    # Return as base64 string for easy storage
    return encrypted.decode('utf-8')


def _decrypt_watermark_data(
    encrypted_data: str,
    encryption_key: bytes
) -> Optional[Dict]:
    """Decrypt watermark metadata."""
    try:
        cipher = Fernet(encryption_key)
        plaintext = cipher.decrypt(encrypted_data.encode('utf-8'))
        return json.loads(plaintext.decode('utf-8'))
    except Exception:
        return None


def _extract_candidate_encrypted_token(image: Any) -> Optional[str]:
    """Extract likely Fernet token from an image's LSB payload."""
    watermark_bits = _extract_lsb_watermark(image)
    if not watermark_bits:
        return None

    if len(watermark_bits) % 8 != 0:
        return None

    try:
        watermark_bytes = _bits_to_bytes(watermark_bits)
    except Exception:
        return None

    decoded = watermark_bytes.decode('utf-8', errors='ignore')
    if not decoded:
        return None

    # Fernet tokens typically begin with gAAAAA and are URL-safe base64.
    token_match = re.search(r"gAAAAA[0-9A-Za-z_-]+=*", decoded)
    if not token_match:
        return None

    token = token_match.group(0)
    return token if len(token) >= 80 else None


def _write_pdf_metadata_token(pdf_path: str, encrypted_token: str) -> bool:
    """Persist encrypted watermark token into PDF metadata as a reliable fallback channel."""
    if PdfReader is None or PdfWriter is None:
        return False

    try:
        reader = PdfReader(pdf_path)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        current_meta = {}
        if reader.metadata:
            for key, value in reader.metadata.items():
                if isinstance(key, str) and isinstance(value, str):
                    current_meta[key] = value

        current_meta[PDF_METADATA_TOKEN_KEY] = encrypted_token
        writer.add_metadata(current_meta)

        with open(pdf_path, 'wb') as f:
            writer.write(f)
        return True
    except Exception:
        return False


def _read_pdf_metadata_token(pdf_path: str) -> Optional[str]:
    """Read encrypted watermark token from PDF metadata if present."""
    if PdfReader is None:
        return None

    try:
        reader = PdfReader(pdf_path)
        metadata = reader.metadata
        if not metadata:
            return None

        token = metadata.get(PDF_METADATA_TOKEN_KEY)
        if isinstance(token, str) and token.startswith('gAAAAA') and len(token) >= 80:
            return token
        return None
    except Exception:
        return None


def _bytes_to_bits(data: bytes) -> str:
    """Convert bytes to binary string."""
    return ''.join(format(byte, '08b') for byte in data)


def _bits_to_bytes(bits: str) -> bytes:
    """Convert binary string back to bytes."""
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))


def _embed_lsb_watermark(
    image: Any,
    watermark_bits: str,
    start_pixel: int = 0
) -> Any:
    """
    Embed watermark bits into image using LSB (Least Significant Bit) steganography.
    
    Args:
        image: PIL Image object (RGB or RGBA)
        watermark_bits: Binary string to embed
        start_pixel: Which pixel index to start embedding
    
    Returns:
        Modified PIL Image with embedded watermark
    """
    img_array = np.array(image.convert('RGB'))
    pixels = img_array.reshape(-1, 3)  # Flatten to (N, 3) for each pixel's RGB
    
    bit_idx = 0
    pixel_idx = start_pixel
    
    # Framed payload format: signature(32 bits) + length(32 bits) + payload(bits)
    signature_bits = _bytes_to_bits(PAYLOAD_SIGNATURE)

    # Store total bits count in 32 bits (so we know how many to extract later)
    bits_count = format(len(watermark_bits), '032b')
    full_bits = signature_bits + bits_count + watermark_bits
    
    for bit in full_bits:
        if pixel_idx >= len(pixels):
            break
        
        pixel = pixels[pixel_idx]
        # Embed into LSB of first color channel (R)
        pixel[0] = (pixel[0] & 0xFE) | int(bit)
        pixel_idx += 1
    
    # Reconstruct image
    img_array.flat[:] = pixels.reshape(-1)
    return Image.fromarray(img_array, 'RGB')


def _extract_lsb_watermark(
    image: Any,
    start_pixel: int = 0
) -> str:
    """
    Extract watermark bits from image using LSB steganography.
    
    Args:
        image: PIL Image object
        start_pixel: Which pixel index to start extracting
    
    Returns:
        Binary string of extracted watermark
    """
    img_array = np.array(image.convert('RGB'))
    pixels = img_array.reshape(-1, 3)
    
    total_pixels = len(pixels)
    signature_bits = _bytes_to_bits(PAYLOAD_SIGNATURE)

    def _read_bits(offset: int, count: int) -> Optional[str]:
        if offset < 0 or offset + count > total_pixels:
            return None
        return ''.join(str(pixels[offset + i][0] & 1) for i in range(count))

    def _read_payload_at(offset: int, framed: bool) -> Optional[str]:
        len_offset = offset + 32 if framed else offset
        bits_count_str = _read_bits(len_offset, 32)
        if not bits_count_str:
            return None

        bits_count = int(bits_count_str, 2)
        if bits_count <= 0:
            return None

        max_available = total_pixels - (len_offset + 32)
        if bits_count > max_available:
            return None

        payload = _read_bits(len_offset + 32, bits_count)
        return payload

    # 1) Fast path: framed payload at start_pixel
    sig_at_start = _read_bits(start_pixel, 32)
    if sig_at_start == signature_bits:
        payload = _read_payload_at(start_pixel, framed=True)
        if payload:
            return payload

    # 2) Backward compatibility: legacy payload at start_pixel
    legacy_payload = _read_payload_at(start_pixel, framed=False)
    if legacy_payload:
        return legacy_payload

    # 3) Robustness scan: search signature in first few thousand pixels
    scan_limit = min(total_pixels - 64, start_pixel + 4096)
    for offset in range(start_pixel, max(start_pixel, scan_limit)):
        sig = _read_bits(offset, 32)
        if sig == signature_bits:
            payload = _read_payload_at(offset, framed=True)
            if payload:
                return payload

    return ''


def watermark_pdf(
    pdf_path: str,
    employee_email: str,
    employee_name: str,
    output_path: str
) -> Tuple[bool, str, Optional[Dict]]:
    """
    Watermark a PDF with encrypted employee information using LSB steganography.
    
    Args:
        pdf_path: Path to input PDF
        employee_email: Employee email
        employee_name: Employee name
        output_path: Path to save watermarked PDF
    
    Returns:
        (success, message, metadata_dict)
    """
    deps_ok, missing = _check_dependencies()
    if not deps_ok:
        return False, f"Missing dependencies: {', '.join(missing)}", None
    
    try:
        # Step 1: Convert PDF to images
        if not os.path.exists(pdf_path):
            return False, f"PDF file not found: {pdf_path}", None
        
        pdf_filename = os.path.basename(pdf_path)
        poppler_path = _resolve_poppler_path()
        convert_kwargs = {'poppler_path': poppler_path} if poppler_path else {}
        images = convert_from_path(pdf_path, **convert_kwargs)
        
        if not images:
            return False, "Failed to convert PDF to images", None
        
        # Step 2: Generate encryption key
        encryption_key = _derive_encryption_key(employee_email, pdf_filename)
        
        # Step 3: Encrypt watermark data
        encrypted_watermark = _encrypt_watermark_data(
            employee_email,
            employee_name,
            pdf_filename,
            encryption_key
        )
        
        # Step 4: Convert encrypted data to bits
        watermark_bytes = encrypted_watermark.encode('utf-8')
        watermark_bits = _bytes_to_bits(watermark_bytes)
        
        # Step 5: Embed watermark into first image using LSB
        watermarked_image = _embed_lsb_watermark(images[0], watermark_bits)
        
        # If multiple pages, keep others unchanged
        all_images = [watermarked_image] + images[1:]
        
        # Step 6: Convert back to PDF while preserving per-page PNG data.
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix='securetrace_steg_') as tmp_dir:
            image_paths = []
            for idx, img in enumerate(all_images):
                page_path = os.path.join(tmp_dir, f'page_{idx}.png')
                img.convert('RGB').save(page_path, format='PNG')
                image_paths.append(page_path)

            pdf_bytes = img_to_pdf(*image_paths)
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)

        # Save encrypted token in PDF metadata as a reliable extraction path.
        _write_pdf_metadata_token(output_path, encrypted_watermark)
        
        metadata = {
            'success': True,
            'employee_email': employee_email,
            'employee_name': employee_name,
            'filename': pdf_filename,
            'watermark_timestamp': datetime.utcnow().isoformat(),
            'pages': len(all_images)
        }
        
        return True, f"PDF watermarked successfully: {output_path}", metadata
        
    except Exception as e:
        return False, f"Error watermarking PDF: {str(e)}", None


def detect_watermark_in_pdf(pdf_path: str) -> Tuple[bool, Optional[Dict]]:
    """
    Detect and extract encrypted watermark from a PDF.
    
    Args:
        pdf_path: Path to suspected watermarked PDF
    
    Returns:
        (success, extracted_data_dict)
    """
    deps_ok, missing = _check_dependencies()
    if not deps_ok:
        return False, None
    
    try:
        if not os.path.exists(pdf_path):
            return False, None
        
        # Step 1: Read reliable metadata token first (fast path).
        metadata_token = _read_pdf_metadata_token(pdf_path)
        if metadata_token:
            extraction = {
                'encrypted_watermark': metadata_token,
                'pdf_filename': os.path.basename(pdf_path),
                'detection_timestamp': datetime.utcnow().isoformat(),
                'pages_analyzed': 0,
                'profile_used': {'mode': 'metadata'}
            }
            return True, extraction

        # Step 2: Convert first page only (watermark is embedded on page 1).
        # Try fast profile first, then robust fallbacks if token isn't recoverable.
        poppler_path = _resolve_poppler_path()
        render_profiles = [
            {'dpi': 96, 'grayscale': True},
            {'dpi': 150, 'grayscale': False},
            {'dpi': 200, 'grayscale': False},
        ]

        encrypted_watermark = None
        analyzed_pages = 0
        used_profile = None

        for profile in render_profiles:
            convert_kwargs = {
                'first_page': 1,
                'last_page': 1,
                'dpi': profile['dpi'],
                'grayscale': profile['grayscale'],
            }
            if poppler_path:
                convert_kwargs['poppler_path'] = poppler_path

            images = convert_from_path(pdf_path, **convert_kwargs)
            if not images:
                continue

            analyzed_pages = len(images)
            encrypted_watermark = _extract_candidate_encrypted_token(images[0])
            if encrypted_watermark:
                used_profile = profile
                break

        if not encrypted_watermark:
            return False, None
        
        # Step 3: We need to try decryption with multiple possible keys
        # For now, return the encrypted data so app can try to match against known employees
        extraction = {
            'encrypted_watermark': encrypted_watermark,
            'pdf_filename': os.path.basename(pdf_path),
            'detection_timestamp': datetime.utcnow().isoformat(),
            'pages_analyzed': analyzed_pages,
            'profile_used': used_profile
        }
        
        return True, extraction
        
    except Exception as e:
        print(f"Error detecting watermark: {e}")
        return False, None


def match_watermark_to_employee(
    encrypted_watermark: str,
    employee_email: str,
    pdf_filename: str
) -> Tuple[bool, Optional[Dict]]:
    """
    Try to decrypt watermark using employee credentials.
    
    Args:
        encrypted_watermark: Encrypted watermark string
        employee_email: Suspected employee email
        pdf_filename: PDF filename
    
    Returns:
        (match_success, decrypted_data_dict)
    """
    try:
        encryption_key = _derive_encryption_key(employee_email, pdf_filename)
        decrypted = _decrypt_watermark_data(encrypted_watermark, encryption_key)
        
        if decrypted:
            return True, decrypted
        return False, None
    except Exception as e:
        print(f"Error matching watermark: {e}")
        return False, None
