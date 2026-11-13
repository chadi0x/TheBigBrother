"""
EXIF ANALYZER // VX HARDENED MEDIA METADATA AUTOPSY

Upgraded to support URL and uploaded bytes, GPS decimal conversion, camera
fingerprinting, software/provenance indicators, hashes and a risk verdict.
"""
from __future__ import annotations

import hashlib
from io import BytesIO
from typing import Any, Dict, Optional

try:
    from PIL import Image
    from PIL.ExifTags import GPSTAGS, TAGS
except ImportError:
    Image = None
    TAGS = {}
    GPSTAGS = {}

try:
    import requests
except ImportError:
    requests = None

import urllib.request

SUSPICIOUS_SOFTWARE = (
    "photoshop", "gimp", "lightroom", "affinity", "pixlr", "canva", "snapseed",
    "facetune", "picsart", "midjourney", "stable diffusion", "comfyui", "dall-e",
)

TAG_FIELDS = {
    "Make": "camera_make",
    "Model": "camera_model",
    "LensModel": "lens_model",
    "SerialNumber": "camera_serial",
    "BodySerialNumber": "camera_serial",
    "Software": "software",
    "DateTime": "datetime",
    "DateTimeOriginal": "datetime_original",
    "DateTimeDigitized": "datetime_digitized",
    "Artist": "artist",
    "Copyright": "copyright",
    "ImageDescription": "description",
    "UserComment": "user_comment",
    "HostComputer": "host_computer",
    "OwnerName": "owner_name",
    "CameraOwnerName": "owner_name",
    "XPAuthor": "author",
    "XPComment": "comment",
    "Orientation": "orientation",
    "ExposureTime": "exposure",
    "FNumber": "aperture",
    "ISOSpeedRatings": "iso",
    "FocalLength": "focal_length",
    "Flash": "flash",
    "WhiteBalance": "white_balance",
    "MeteringMode": "metering_mode",
    "ColorSpace": "color_space",
    "GPSInfo": "gps_raw",
}


def _decode(value: Any) -> Any:
    if isinstance(value, bytes):
        for enc in ("utf-8", "latin-1"):
            try:
                return value.decode(enc).strip("\x00").strip()
            except Exception:
                continue
        return str(value)
    if isinstance(value, tuple) and len(value) == 2 and all(isinstance(x, (int, float)) for x in value):
        return float(value[0]) / float(value[1]) if value[1] else 0.0
    if isinstance(value, (list, tuple)):
        return [_decode(v) for v in value]
    return value


def _to_float(value: Any) -> Optional[float]:
    try:
        if isinstance(value, tuple) and len(value) == 2:
            return float(value[0]) / float(value[1]) if value[1] else None
        return float(value)
    except Exception:
        return None


def _gps_decimal(gps: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        lat = gps.get("GPSLatitude")
        lon = gps.get("GPSLongitude")
        lat_ref = str(gps.get("GPSLatitudeRef", "N"))
        lon_ref = str(gps.get("GPSLongitudeRef", "E"))
        if not lat or not lon:
            return None
        lat_vals = [_to_float(v) or 0.0 for v in lat]
        lon_vals = [_to_float(v) or 0.0 for v in lon]
        lat_d = lat_vals[0] + lat_vals[1] / 60 + (lat_vals[2] if len(lat_vals) > 2 else 0) / 3600
        lon_d = lon_vals[0] + lon_vals[1] / 60 + (lon_vals[2] if len(lon_vals) > 2 else 0) / 3600
        if lat_ref.upper().startswith("S"):
            lat_d = -lat_d
        if lon_ref.upper().startswith("W"):
            lon_d = -lon_d
        return {
            "latitude": round(lat_d, 7),
            "longitude": round(lon_d, 7),
            "google_maps": f"https://www.google.com/maps?q={lat_d:.7f},{lon_d:.7f}",
            "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat_d:.7f}&mlon={lon_d:.7f}#map=17/{lat_d:.7f}/{lon_d:.7f}",
            "geohash_precision": 7,
        }
    except Exception:
        return None


def _analyze_image(image: "Image.Image", source: str, raw: bytes) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "source": source,
        "basic": {},
        "gps": {},
        "gps_decimal": None,
        "camera": {},
        "provenance": {},
        "hashes": {},
        "risk": {"score": 0, "tier": "NOMINAL", "findings": []},
        "error": None,
    }
    results["basic"]["format"] = image.format
    results["basic"]["mode"] = image.mode
    results["basic"]["size"] = f"{image.width}x{image.height}"
    results["basic"]["width"] = image.width
    results["basic"]["height"] = image.height
    results["basic"]["megapixels"] = round((image.width * image.height) / 1_000_000, 2)
    results["hashes"] = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "md5": hashlib.md5(raw).hexdigest(),
        "bytes": len(raw),
    }

    exif_data = None
    try:
        exif_data = image.getexif()
    except Exception:
        try:
            exif_data = image._getexif()
        except Exception:
            exif_data = None

    if not exif_data:
        results["provenance"]["exif_present"] = False
        results["risk"]["findings"].append({
            "severity": "info",
            "title": "No EXIF metadata",
            "detail": "The image carries no EXIF. This is typical of social uploads, screenshots, or deliberate stripping.",
        })
        return results

    results["provenance"]["exif_present"] = True
    for tag_id, value in exif_data.items():
        tag = TAGS.get(tag_id, tag_id) if isinstance(tag_id, int) else tag_id
        value = _decode(value)
        if tag == "GPSInfo":
            gps_raw = {}
            if isinstance(value, dict):
                for t, v in value.items():
                    sub = GPSTAGS.get(t, t) if isinstance(t, int) else t
                    gps_raw[sub] = _decode(v)
            results["gps"] = gps_raw
            results["gps_decimal"] = _gps_decimal(gps_raw)
            continue

        field = TAG_FIELDS.get(tag)
        if not field:
            if len(str(value)) < 400:
                results["basic"][str(tag)] = value
            continue
        if field.startswith("gps"):
            continue
        if field in ("camera_make", "camera_model", "lens_model", "camera_serial", "owner_name"):
            results["camera"][field] = value
        elif field in ("software", "artist", "copyright", "description", "user_comment", "host_computer", "author", "comment"):
            results["provenance"][field] = value
        elif field.startswith("datetime"):
            results["provenance"][field] = value
        else:
            results["basic"][field] = value

    make = str(results["camera"].get("camera_make", "") or "")
    model = str(results["camera"].get("camera_model", "") or "")
    software = str(results["provenance"].get("software", "") or "")
    if make or model:
        results["camera"]["device"] = f"{make} {model}".strip()
        results["provenance"]["camera_fingerprint"] = hashlib.sha1(
            f"{make}|{model}|{results['camera'].get('lens_model','')}".encode()
        ).hexdigest()[:20]

    findings = results["risk"]["findings"]
    score = 0
    if results.get("gps_decimal"):
        score += 55
        findings.append({
            "severity": "high",
            "title": "GPS coordinates embedded",
            "detail": f"Precise location {results['gps_decimal']['latitude']}, {results['gps_decimal']['longitude']} is recoverable from the file.",
            "recommendation": "Strip EXIF before publishing; use a metadata scrubber.",
        })
    if results["camera"].get("camera_serial"):
        score += 18
        findings.append({
            "severity": "medium",
            "title": "Camera serial number present",
            "detail": "The body serial can link separate images to the same physical device.",
        })
    if results["provenance"].get("artist") or results["provenance"].get("copyright") or results["provenance"].get("owner_name"):
        score += 10
        findings.append({
            "severity": "low",
            "title": "Author/owner identity embedded",
            "detail": "Artist, copyright or owner tags expose identity metadata.",
            "evidence": {k: v for k, v in results["provenance"].items() if k in ("artist", "copyright", "owner_name")},
        })
    if software and any(s in software.lower() for s in SUSPICIOUS_SOFTWARE):
        score += 22
        findings.append({
            "severity": "medium",
            "title": "Editing or generative software signature",
            "detail": f"Software tag indicates post-processing/generation: {software}.",
            "recommendation": "Treat as edited/synthetic until provenance is independently verified.",
        })
    if results["provenance"].get("datetime_original"):
        findings.append({
            "severity": "info",
            "title": "Original capture timestamp",
            "detail": str(results["provenance"]["datetime_original"]),
        })
    if not results["camera"].get("device") and not software:
        findings.append({
            "severity": "low",
            "title": "Metadata stripped or incomplete",
            "detail": "EXIF exists but lacks camera/software provenance, consistent with stripping or an export pipeline.",
        })
        score += 5

    results["risk"]["score"] = min(100, score)
    results["risk"]["tier"] = "CRITICAL" if score >= 70 else "ELEVATED" if score >= 35 else "GUARDED" if score >= 10 else "NOMINAL"
    return results


def get_exif_data_bytes(content: bytes, filename: str = "upload") -> Dict[str, Any]:
    if Image is None:
        return {"source": filename, "basic": {}, "gps": {}, "error": "Pillow is not installed"}
    try:
        image = Image.open(BytesIO(content))
        return _analyze_image(image, filename, content)
    except Exception as exc:
        return {"source": filename, "basic": {}, "gps": {}, "error": f"{type(exc).__name__}: {exc}"}


def get_exif_data(image_source: str, is_url: bool = True) -> Dict[str, Any]:
    """Extract EXIF from an image URL (or local path when is_url=False)."""
    if Image is None:
        return {"source": image_source, "basic": {}, "gps": {}, "error": "Pillow is not installed"}
    try:
        raw: Optional[bytes] = None
        if is_url:
            if requests is not None:
                resp = requests.get(
                    image_source,
                    timeout=15,
                    headers={"User-Agent": "TheBigBrother-VX/1.0"},
                )
                if resp.status_code != 200:
                    return {"source": image_source, "basic": {}, "gps": {}, "error": f"Failed to download image: HTTP {resp.status_code}"}
                raw = resp.content
            else:
                req = urllib.request.Request(image_source, headers={"User-Agent": "TheBigBrother-VX/1.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw = resp.read()
        else:
            with open(image_source, "rb") as fh:
                raw = fh.read()
        if not raw:
            return {"source": image_source, "basic": {}, "gps": {}, "error": "Empty image payload"}
        image = Image.open(BytesIO(raw))
        return _analyze_image(image, image_source, raw)
    except Exception as exc:
        return {"source": image_source, "basic": {}, "gps": {}, "error": f"{type(exc).__name__}: {exc}"}
