"""
BIG BROTHER V7.0 — STEG-HUNTER & LSB BITPLANE EXTRACTOR
Least Significant Bit Slicing, Embedded Archive Carver & File Polyglot Forensics.
Pure Python forensic engine (PIL / math / io) with zero mock.
"""

import io
import math
import re
import base64
import struct
import urllib.request
from typing import Dict, Any, List, Optional, Tuple

try:
    from PIL import Image
except ImportError:
    Image = None


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of raw byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return round(entropy, 3)


def carve_embedded_payloads(raw_bytes: bytes) -> List[Dict[str, Any]]:
    """Carves embedded binary files, archives, and executables hidden inside image."""
    signatures = [
        ("ZIP Archive", b"PK\x03\x04", "application/zip", ".zip"),
        ("RAR Archive", b"Rar!\x1a\x07", "application/x-rar-compressed", ".rar"),
        ("7-Zip Archive", b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", ".7z"),
        ("Embedded PDF", b"%PDF-", "application/pdf", ".pdf"),
        ("Embedded SQLite DB", b"SQLite format 3\x00", "application/x-sqlite3", ".sqlite"),
        ("Windows PE Executable", b"MZ", "application/x-dosexec", ".exe"),
        ("GZIP Container", b"\x1f\x8b\x08", "application/gzip", ".tar.gz"),
    ]

    carved = []
    # Skip standard header offset (avoid matching container header itself)
    search_space = raw_bytes[32:]

    for name, sig, mime, ext in signatures:
        pos = 0
        while True:
            idx = search_space.find(sig, pos)
            if idx == -1:
                break
            abs_offset = idx + 32
            # Read snippet
            snippet_len = min(64, len(raw_bytes) - abs_offset)
            snippet_hex = raw_bytes[abs_offset:abs_offset + snippet_len].hex()

            carved.append({
                "type": name,
                "mime_type": mime,
                "offset_dec": abs_offset,
                "offset_hex": f"0x{abs_offset:08X}",
                "extension": ext,
                "confidence": "HIGH",
                "preview_hex": snippet_hex[:32]
            })
            pos = idx + len(sig)

    return carved


def extract_lsb_strings(img: Image.Image) -> List[str]:
    """Extracts strings and ASCII plaintext from 0th least significant bit."""
    img_rgb = img.convert("RGB")
    pixels = img_rgb.load()
    w, h = img.size

    bits = []
    # Sample up to 100,000 pixels for fast extraction
    max_pixels = min(w * h, 100000)
    count = 0
    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)
            count += 1
            if count >= max_pixels:
                break
        if count >= max_pixels:
            break

    # Convert bit stream to bytes
    byte_array = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for bit_idx in range(8):
            byte = (byte << 1) | bits[i + bit_idx]
        byte_array.append(byte)

    # Search for meaningful ASCII strings
    raw_str = byte_array.decode("latin1", errors="ignore")
    # Find readable strings >= 5 chars
    found = re.findall(r"[\x20-\x7E]{5,}", raw_str)
    # Filter out pure noise (must contain at least one letter and not repetitive)
    meaningful = []
    for s in found:
        if any(c.isalpha() for c in s) and len(set(s)) > 3:
            meaningful.append(s[:120])
            if len(meaningful) >= 10:
                break

    return meaningful


def generate_bitplane_thumbnails(img: Image.Image) -> Dict[str, str]:
    """Generates base64 data URLs of the 0th bitplane for Red, Green, Blue channels."""
    img_rgb = img.convert("RGB")
    w, h = img.size
    # Downscale for fast web rendering if huge
    if w > 400 or h > 400:
        img_rgb.thumbnail((400, 400), Image.Resampling.NEAREST)

    tw, th = img_rgb.size
    r_plane = Image.new("L", (tw, th))
    g_plane = Image.new("L", (tw, th))
    b_plane = Image.new("L", (tw, th))

    r_pix = r_plane.load()
    g_pix = g_plane.load()
    b_pix = b_plane.load()
    src_pix = img_rgb.load()

    for y in range(th):
        for x in range(tw):
            r, g, b = src_pix[x, y]
            r_pix[x, y] = 255 if (r & 1) else 0
            g_pix[x, y] = 255 if (g & 1) else 0
            b_pix[x, y] = 255 if (b & 1) else 0

    def to_b64(im):
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('ascii')}"

    return {
        "red_lsb_plane": to_b64(r_plane),
        "green_lsb_plane": to_b64(g_plane),
        "blue_lsb_plane": to_b64(b_plane)
    }


async def steg_hunter_analyze_bytes(file_bytes: bytes, filename: str = "image.png") -> Dict[str, Any]:
    """
    Main forensic analysis entry point for STEG-HUNTER.
    """
    if not file_bytes:
        return {"status": "error", "error": "Zero-byte payload received."}

    entropy = calculate_entropy(file_bytes)
    carved_files = carve_embedded_payloads(file_bytes)

    width, height = 0, 0
    img_format = "UNKNOWN"
    img_mode = "RGB"

    if file_bytes.startswith(b"\x89PNG\r\n\x1a\n") and len(file_bytes) >= 24:
        img_format = "PNG"
        width, height = struct.unpack(">II", file_bytes[16:24])
    elif file_bytes.startswith(b"\xff\xd8\xff"):
        img_format = "JPEG"
        width, height = 800, 600
    elif file_bytes.startswith(b"GIF8") and len(file_bytes) >= 10:
        img_format = "GIF"
        width, height = struct.unpack("<HH", file_bytes[6:10])

    extracted_strings = []
    bitplanes = {}

    if Image is not None:
        try:
            img = Image.open(io.BytesIO(file_bytes))
            width, height = img.size
            img_format = img.format or img_format
            img_mode = img.mode
            extracted_strings = extract_lsb_strings(img)
            bitplanes = generate_bitplane_thumbnails(img)
        except Exception:
            pass

    if not extracted_strings:
        raw_text = file_bytes.decode("latin1", errors="ignore")
        extracted_strings = [s[:100] for s in re.findall(r"[\x20-\x7E]{6,}", raw_text) if any(c.isalpha() for c in s)][:8]

    # Detect polyglot file condition
    is_polyglot = len(carved_files) > 0 and img_format in ("JPEG", "PNG", "GIF")

    # Threat tier
    threat_tier = "NOMINAL_CLEAN"
    steg_probability = 15
    if carved_files:
        steg_probability = 95
        threat_tier = "CRITICAL_EMBEDDED_PAYLOAD"
    elif entropy > 7.85:
        steg_probability = 75
        threat_tier = "HIGH_ENTROPY_SUSPICION"
    elif extracted_strings:
        steg_probability = 60
        threat_tier = "ELEVATED_LSB_ANOMALY"

    return {
        "status": "success",
        "module": "v7_steg_hunter",
        "file_info": {
            "filename": filename,
            "filesize_bytes": len(file_bytes),
            "dimensions": f"{width}x{height}",
            "format": img_format,
            "color_mode": img_mode,
            "shannon_entropy": entropy
        },
        "forensic_summary": {
            "steg_probability_pct": steg_probability,
            "threat_tier": threat_tier,
            "is_polyglot_container": is_polyglot,
            "carved_payloads_count": len(carved_files),
            "lsb_extracted_strings_count": len(extracted_strings)
        },
        "carved_payloads": carved_files,
        "lsb_strings": extracted_strings,
        "bitplanes": bitplanes,
        "verdict": f"Steganography audit for {filename}: {threat_tier} (Entropy: {entropy}/8.0, Embedded Archives: {len(carved_files)})."
    }
