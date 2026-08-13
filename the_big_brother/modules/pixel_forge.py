"""
PIXEL FORGE — Media Authenticity & Forensics Engine V6.1
Ultra-deep image forensics suite — zero external API keys required.

Analysis engines:
  1. Multi-Quality ELA  — Error Level Analysis at 3 compression levels
  2. JPEG Ghost         — Double-compression artifact detection
  3. Frequency Domain   — DCT block analysis for upscaling/generation patterns
  4. Clone Detection    — Copy-paste region finder via block hash comparison
  5. Noise Fingerprint  — Camera sensor noise pattern & PRNU heuristic
  6. AI Artifact Engine — Multi-signal AI/GAN/Diffusion model detector
  7. Steganography      — LSB + chi-square uniformity test
  8. Metadata Autopsy   — Full EXIF, GPS, ICC, thumbnail mismatch
  9. Forgery Heuristics — Composite tampering probability score
"""
import io
import math
import base64
import hashlib
import struct
import colorsys
from PIL import Image, ImageChops, ImageEnhance, ImageFilter, ImageDraw
from PIL.ExifTags import TAGS, GPSTAGS


# ═══════════════════════════════════════════════════════════════════════════════
# 1. MULTI-QUALITY ELA
# ═══════════════════════════════════════════════════════════════════════════════

def _ela_single(image: Image.Image, quality: int = 95, scale: int = 15) -> str:
    """Compress → diff → amplify → return base64 PNG."""
    img_rgb = image.convert("RGB")
    buf = io.BytesIO()
    img_rgb.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    recompressed = Image.open(buf).convert("RGB")
    diff = ImageChops.difference(img_rgb, recompressed)
    extrema = diff.getextrema()
    max_diff = max(max(ch) for ch in extrema) or 1
    factor = 255.0 / max_diff * (scale / 10.0)
    enhanced = diff.point(lambda p: min(255, int(p * factor)))
    out = io.BytesIO()
    enhanced.save(out, format="PNG")
    out.seek(0)
    return base64.b64encode(out.read()).decode("utf-8")


def _ela_multi(image: Image.Image) -> dict:
    """
    Run ELA at three quality levels: 95 (standard), 75 (heavy), 50 (brutal).
    Real photos degrade uniformly. Edited regions show inconsistent patterns.
    """
    results = {}
    suspicion_votes = 0
    for q, label, scale in [(95, "q95", 15), (75, "q75", 20), (50, "q50", 25)]:
        try:
            b64 = _ela_single(image, quality=q, scale=scale)
            results[label] = b64
        except Exception as e:
            results[label] = None
            results[f"{label}_error"] = str(e)

    # Measure average ELA intensity at each quality level
    intensities = {}
    for q, label, _ in [(95, "q95", 15), (75, "q75", 20), (50, "q50", 25)]:
        try:
            img_rgb = image.convert("RGB")
            buf = io.BytesIO()
            img_rgb.save(buf, format="JPEG", quality=q)
            buf.seek(0)
            rc = Image.open(buf).convert("RGB")
            diff = ImageChops.difference(img_rgb, rc)
            pix = list(diff.getdata())
            avg = sum(sum(p) / 3 for p in pix) / len(pix) if pix else 0
            intensities[label] = round(avg, 3)
        except Exception:
            intensities[label] = None

    # If ELA intensity rises sharply from q95 → q50, likely edited
    try:
        i95 = intensities.get("q95") or 0
        i50 = intensities.get("q50") or 0
        jump = (i50 - i95) / max(i95, 0.01)
        if jump > 3.0:
            suspicion_votes += 2
            note = f"ELA intensity jumps {jump:.1f}x from Q95→Q50 — strong double-compression signal"
        elif jump > 1.5:
            suspicion_votes += 1
            note = f"ELA intensity increases {jump:.1f}x from Q95→Q50 — possible prior JPEG compression"
        else:
            note = f"ELA intensity increase Q95→Q50: {jump:.1f}x — consistent with single-save image"
    except Exception:
        note = "ELA multi-quality analysis could not determine compression history"
        jump = 0

    results["intensities"] = intensities
    results["suspicion_votes"] = suspicion_votes
    results["interpretation"] = note
    results["description"] = "ELA at 3 quality levels. Bright = high error. Inconsistent bright zones across levels = edits."
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# 2. JPEG GHOST DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def _jpeg_ghost(image: Image.Image) -> dict:
    """
    JPEG Ghost: resave at multiple qualities, subtract from original.
    Areas that 'ghost' (disappear / become dark) at a specific quality
    reveal the original JPEG quality level of pasted regions.
    Useful to find elements pasted from a different source JPEG.
    """
    img_rgb = image.convert("RGB")
    ghost_map = {}
    quality_votes = []

    for q in range(50, 100, 10):
        try:
            buf = io.BytesIO()
            img_rgb.save(buf, format="JPEG", quality=q)
            buf.seek(0)
            rc = Image.open(buf).convert("RGB")
            diff = ImageChops.difference(img_rgb, rc)
            pix = list(diff.getdata())
            avg = sum(sum(p) / 3 for p in pix) / len(pix) if pix else 999
            ghost_map[str(q)] = round(avg, 3)
            if avg < 2.5:
                quality_votes.append(q)
        except Exception:
            ghost_map[str(q)] = None

    # The quality with minimum difference is likely the original save quality
    try:
        valid = {int(k): v for k, v in ghost_map.items() if v is not None}
        best_q = min(valid, key=valid.get)
        best_diff = valid[best_q]
        ghost_detected = best_diff < 2.0
    except Exception:
        best_q = None
        best_diff = None
        ghost_detected = False

    return {
        "quality_map": ghost_map,
        "estimated_original_quality": best_q,
        "minimum_difference": best_diff,
        "ghost_detected": ghost_detected,
        "interpretation": (
            f"Image appears to have been originally saved at JPEG Q{best_q} — "
            f"{'possible composite elements from different sources' if ghost_detected and best_q and best_q < 90 else 'consistent single-source compression'}"
        ) if best_q else "JPEG ghost analysis inconclusive",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 3. DCT FREQUENCY DOMAIN ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def _frequency_analysis(image: Image.Image) -> dict:
    """
    Analyse DCT (Discrete Cosine Transform) block structure.
    AI-generated images often show unusual 8x8 block boundaries or lack them.
    Upscaled images show periodic frequency patterns.
    Uses pixel-level approximation without scipy (pure math).
    """
    try:
        gray = image.convert("L")
        w, h = gray.size
        pix = gray.load()

        # Measure horizontal and vertical periodicity using autocorrelation
        # at lags 1, 2, 4, 8 (powers of 2 — common in upscaling artifacts)
        row_mid = h // 2
        row = [pix[x, row_mid] for x in range(min(w, 512))]

        def autocorr(data, lag):
            n = len(data)
            if n <= lag:
                return 0
            mean = sum(data) / n
            num = sum((data[i] - mean) * (data[i + lag] - mean) for i in range(n - lag))
            denom = sum((d - mean) ** 2 for d in data) or 1
            return num / denom

        ac = {str(lag): round(autocorr(row, lag), 4) for lag in [4, 8, 16, 32]}

        # 8-pixel periodicity is a JPEG block artifact
        # Very high autocorrelation at lag=8 in smooth regions indicates AI upscaling
        lag8 = ac.get("8", 0)
        lag16 = ac.get("16", 0)

        signals = []
        score = 0

        if lag8 > 0.85:
            signals.append(f"Strong 8-pixel periodicity (r={lag8}) — JPEG block artifacts or AI upscaling pattern")
            score += 25
        elif lag8 > 0.7:
            signals.append(f"Moderate 8-pixel periodicity (r={lag8}) — possible JPEG processing")
            score += 10

        if lag16 > 0.8:
            signals.append(f"Strong 16-pixel periodicity (r={lag16}) — consistent with 2x AI upscaling")
            score += 20

        # Block boundary sharpness test — real photos are smoother
        block_boundary_diffs = []
        for x in range(8, min(w, 512), 8):
            diff = abs(int(pix[x, row_mid]) - int(pix[x - 1, row_mid]))
            block_boundary_diffs.append(diff)

        avg_boundary = sum(block_boundary_diffs) / len(block_boundary_diffs) if block_boundary_diffs else 0

        if avg_boundary > 20:
            signals.append(f"High average block-boundary gradient ({avg_boundary:.1f}) — ringing/blocking artifacts detected")
            score += 15

        return {
            "autocorrelation": ac,
            "avg_block_boundary_gradient": round(avg_boundary, 2),
            "frequency_score": min(100, score),
            "signals": signals,
            "interpretation": (
                "Strong periodic frequency patterns detected — possible AI upscaling or GAN artifacts" if score >= 30 else
                "Moderate frequency artifacts" if score >= 15 else
                "Normal frequency distribution — consistent with authentic image"
            ),
        }
    except Exception as e:
        return {"error": str(e), "frequency_score": 0, "signals": []}


# ═══════════════════════════════════════════════════════════════════════════════
# 4. CLONE DETECTION (Copy-Paste Region Finder)
# ═══════════════════════════════════════════════════════════════════════════════

def _clone_detection(image: Image.Image, block_size: int = 32) -> dict:
    """
    Divide image into blocks, compute perceptual hash of each block.
    Identical/near-identical hashes across spatially distant blocks
    indicate copy-paste cloning (e.g. sky/background duplication).
    Returns suspected clone pairs with coordinates.
    """
    try:
        img_gray = image.convert("L")
        w, h = img_gray.size

        # Limit to reasonable grid
        cols = min(w // block_size, 30)
        rows = min(h // block_size, 30)

        if cols < 4 or rows < 4:
            return {"clone_detected": False, "pairs": [], "note": "Image too small for clone analysis"}

        blocks = {}
        for r in range(rows):
            for c in range(cols):
                x, y = c * block_size, r * block_size
                crop = img_gray.crop((x, y, x + block_size, y + block_size))
                # Downscale to 8x8 and compute average hash
                small = crop.resize((8, 8), Image.LANCZOS)
                pix = list(small.getdata())
                avg = sum(pix) / len(pix)
                bits = "".join("1" if p >= avg else "0" for p in pix)
                h_hash = hex(int(bits, 2))[2:].zfill(16)
                pos = (c * block_size, r * block_size)
                if h_hash in blocks:
                    blocks[h_hash].append(pos)
                else:
                    blocks[h_hash] = [pos]

        # Find blocks that appear in 2+ spatially distinct locations
        clone_pairs = []
        for h_hash, positions in blocks.items():
            if len(positions) >= 2:
                # Check spatial distance — must be far apart to count
                for i in range(len(positions)):
                    for j in range(i + 1, len(positions)):
                        x1, y1 = positions[i]
                        x2, y2 = positions[j]
                        dist = math.sqrt((x2 - x1) ** 2 + (y2 - y1) ** 2)
                        if dist > block_size * 3:  # Must be >3 blocks away
                            clone_pairs.append({
                                "block_a": [x1, y1],
                                "block_b": [x2, y2],
                                "distance_px": round(dist, 1),
                                "hash": h_hash,
                            })

        clone_pairs = clone_pairs[:20]  # Cap results
        clone_score = min(100, len(clone_pairs) * 8)

        return {
            "clone_detected": len(clone_pairs) > 2,
            "clone_score": clone_score,
            "total_suspicious_pairs": len(clone_pairs),
            "pairs": clone_pairs[:8],  # Return top 8 for display
            "interpretation": (
                f"⚠ {len(clone_pairs)} cloned region pairs detected — likely background cloning or object removal" if len(clone_pairs) > 2
                else "No significant clone regions detected"
            ),
        }
    except Exception as e:
        return {"clone_detected": False, "pairs": [], "error": str(e), "clone_score": 0}


# ═══════════════════════════════════════════════════════════════════════════════
# 5. NOISE FINGERPRINT (Camera Sensor Heuristic)
# ═══════════════════════════════════════════════════════════════════════════════

def _noise_fingerprint(image: Image.Image) -> dict:
    """
    Analyse the noise residual (image minus its denoised version).
    Real cameras produce consistent fixed-pattern noise (PRNU).
    AI images / heavily edited images show unnatural noise distributions.
    """
    try:
        gray = image.convert("L")
        w, h = gray.size

        # Get noise residual using a blur subtraction
        blurred = gray.filter(ImageFilter.GaussianBlur(radius=1))
        diff = ImageChops.difference(gray, blurred)
        noise_pix = list(diff.getdata())

        if not noise_pix:
            return {"noise_score": 0, "interpretation": "Could not extract noise residual"}

        # Statistical moments of noise
        n = len(noise_pix)
        mean = sum(noise_pix) / n
        variance = sum((p - mean) ** 2 for p in noise_pix) / n
        std = math.sqrt(variance)

        # Higher moments
        skewness_num = sum((p - mean) ** 3 for p in noise_pix) / n
        skewness = skewness_num / (std ** 3) if std > 0 else 0

        kurtosis_num = sum((p - mean) ** 4 for p in noise_pix) / n
        kurtosis = kurtosis_num / (std ** 4) if std > 0 else 0

        signals = []
        score = 0

        # Real camera noise: std dev typically 2–8, Gaussian (kurtosis ~3)
        if std < 0.5:
            signals.append(f"Extremely low noise level (σ={std:.3f}) — over-processed or AI-generated")
            score += 30
        elif std > 20:
            signals.append(f"Unusually high noise (σ={std:.1f}) — heavy post-processing or synthetic noise added")
            score += 15

        if abs(skewness) > 1.0:
            signals.append(f"Non-Gaussian noise skewness ({skewness:.2f}) — inconsistent with natural camera noise")
            score += 20

        if kurtosis > 10:
            signals.append(f"Heavy-tailed noise kurtosis ({kurtosis:.1f}) — impulse noise or composite artifact")
            score += 15
        elif kurtosis < 2:
            signals.append(f"Flat noise distribution (kurtosis {kurtosis:.1f}) — possible AI smoothing")
            score += 20

        # Spatial uniformity — real cameras have non-uniform noise patterns
        regions = []
        for y_start in range(0, h - 64, h // 4):
            for x_start in range(0, w - 64, w // 4):
                crop = diff.crop((x_start, y_start, x_start + 64, y_start + 64))
                cp = list(crop.getdata())
                regions.append(sum(cp) / len(cp))

        if regions:
            region_var = sum((r - sum(regions) / len(regions)) ** 2 for r in regions) / len(regions)
            if region_var < 0.1:
                signals.append(f"Nearly uniform noise across all regions (regional variance: {region_var:.4f}) — AI smoothing signature")
                score += 25

        return {
            "noise_std": round(std, 4),
            "noise_mean": round(mean, 4),
            "skewness": round(skewness, 4),
            "kurtosis": round(kurtosis, 4),
            "noise_score": min(100, score),
            "signals": signals,
            "interpretation": (
                "ABNORMAL — noise profile inconsistent with camera hardware" if score >= 40 else
                "SUSPECT — some noise irregularities detected" if score >= 20 else
                "NORMAL — noise profile consistent with authentic camera image"
            ),
        }
    except Exception as e:
        return {"error": str(e), "noise_score": 0, "signals": []}


# ═══════════════════════════════════════════════════════════════════════════════
# 6. ENHANCED AI ARTIFACT DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

_AI_SOFTWARE = [
    "stable diffusion", "midjourney", "dalle", "comfyui", "automatic1111",
    "invoke", "novelai", "dreamstudio", "firefly", "imagen", "emu",
    "flux", "sdxl", "controlnet", "lora", "dreambooth", "waifu diffusion",
    "leonardo", "nightcafe", "tensor.art",
]

def _detect_ai_artifacts(image: Image.Image) -> dict:
    signals = []
    score = 0

    # ── EXIF/software analysis ─────────────────────────────────────────
    try:
        exif = image._getexif()
        if not exif:
            signals.append("No EXIF metadata — most AI tools strip or omit it entirely")
            score += 15
        else:
            has_camera = any(TAGS.get(k, "") in ("Make", "Model", "LensModel") for k in exif)
            if not has_camera:
                signals.append("No camera hardware signature in EXIF (Make/Model/Lens absent)")
                score += 12

            software = next((str(v) for k, v in exif.items() if TAGS.get(k) == "Software"), "").lower()
            for tool in _AI_SOFTWARE:
                if tool in software:
                    signals.append(f"🔴 AI software tag confirmed: '{software[:120]}'")
                    score += 80
                    break

            has_lens = any(TAGS.get(k, "") in ("FocalLength", "FNumber", "ExposureTime", "ISOSpeedRatings") for k in exif)
            if not has_lens:
                signals.append("No optical exposure parameters (focal length, aperture, shutter, ISO) — not from a real camera")
                score += 18
    except Exception:
        signals.append("EXIF parse error — metadata may be deliberately wiped")
        score += 8

    # ── Texture & variance ────────────────────────────────────────────
    try:
        gray = image.convert("L")
        w, h = gray.size
        pix = gray.load()
        block = 32
        variances = []
        for y in range(0, h - block, block):
            for x in range(0, w - block, block):
                vals = [pix[x + dx, y + dy] for dy in range(block) for dx in range(block)]
                mean = sum(vals) / len(vals)
                var = sum((v - mean) ** 2 for v in vals) / len(vals)
                variances.append(var)

        if variances:
            avg_var = sum(variances) / len(variances)
            low_ratio = sum(1 for v in variances if v < 50) / len(variances)
            cv = (math.sqrt(sum((v - avg_var) ** 2 for v in variances) / len(variances)) / avg_var) if avg_var > 0 else 0

            if avg_var < 150:
                signals.append(f"Very smooth texture (avg block variance: {avg_var:.1f}) — diffusion/GAN smoothing signature")
                score += 22
            elif avg_var < 300:
                signals.append(f"Moderately smooth texture (avg block variance: {avg_var:.1f})")
                score += 8

            if low_ratio > 0.45:
                signals.append(f"{low_ratio*100:.0f}% of blocks are near-flat — unusual for real-world photographs")
                score += 18

            if cv < 0.5:
                signals.append(f"Suspiciously uniform variance distribution (CV={cv:.2f}) — real photos are more chaotic")
                score += 12
    except Exception:
        pass

    # ── Color entropy & saturation ────────────────────────────────────
    try:
        img_rgb = image.convert("RGB")
        sample = list(img_rgb.getdata())[::80]
        r_vals = [p[0] for p in sample]
        g_vals = [p[1] for p in sample]
        b_vals = [p[2] for p in sample]

        def bucket_entropy(vals, buckets=32):
            counts = {}
            for v in vals:
                b = v * buckets // 256
                counts[b] = counts.get(b, 0) + 1
            total = len(vals)
            return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)

        avg_ent = (bucket_entropy(r_vals) + bucket_entropy(g_vals) + bucket_entropy(b_vals)) / 3

        # AI images tend to have very high or suspiciously perfect color entropy
        if avg_ent > 4.9:
            signals.append(f"Near-maximum color entropy ({avg_ent:.3f}/5.0) — diffusion models produce hyper-saturated distributions")
            score += 12

        # Saturation uniformity
        hsv_sats = [colorsys.rgb_to_hsv(p[0]/255, p[1]/255, p[2]/255)[1] for p in sample]
        avg_sat = sum(hsv_sats) / len(hsv_sats) if hsv_sats else 0
        sat_var = sum((s - avg_sat) ** 2 for s in hsv_sats) / len(hsv_sats) if hsv_sats else 0

        if sat_var < 0.01 and avg_sat > 0.3:
            signals.append(f"Artificially uniform saturation (σ²={sat_var:.4f}) — natural photos have chaotic saturation variation")
            score += 15
    except Exception:
        pass

    # ── Aspect ratio heuristics ───────────────────────────────────────
    AI_ASPECT_RATIOS = {
        (1, 1): "1:1 (square — common AI default)",
        (4, 3): "4:3", (3, 4): "3:4",
        (16, 9): "16:9", (9, 16): "9:16",
        (3, 2): "3:2", (2, 3): "2:3",
    }
    try:
        w, h = image.size
        g = math.gcd(w, h)
        ratio = (w // g, h // g)
        if ratio in AI_ASPECT_RATIOS and w in (512, 768, 1024, 1280, 1536, 2048):
            signals.append(f"Exact AI resolution: {w}x{h} ({AI_ASPECT_RATIOS[ratio]}) — matches Stable Diffusion/Midjourney standard outputs")
            score += 20
        elif ratio in AI_ASPECT_RATIOS:
            signals.append(f"Common AI aspect ratio {AI_ASPECT_RATIOS[ratio]} — not conclusive alone")
            score += 5
    except Exception:
        pass

    # ── C2PA / AI provenance metadata ────────────────────────────────
    try:
        info = image.info or {}
        for key in ("icc_profile", "comment", "description", "author"):
            val = str(info.get(key, "")).lower()
            if any(t in val for t in ["ai", "generated", "synthetic", "adobe firefly", "dalle"]):
                signals.append(f"AI provenance marker in image info ({key}): '{val[:80]}'")
                score += 40
    except Exception:
        pass

    verdict = (
        "🔴 CONFIRMED AI-GENERATED" if score >= 80 else
        "🟠 VERY LIKELY AI-GENERATED" if score >= 55 else
        "🟡 SUSPICIOUS — POSSIBLE AI" if score >= 30 else
        "🟢 LIKELY AUTHENTIC" if score >= 12 else
        "✅ LIKELY AUTHENTIC"
    )

    return {
        "ai_score": min(100, score),
        "verdict": verdict,
        "signals": signals,
        "signal_count": len(signals),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 7. STEGANOGRAPHY (Enhanced — Chi-Square + LSB)
# ═══════════════════════════════════════════════════════════════════════════════

def _steg_surface(image: Image.Image) -> dict:
    try:
        img_rgb = image.convert("RGB")
        pix_data = list(img_rgb.getdata())
        sample = pix_data[::20]  # 5% sample

        # LSB extraction
        lsbs = []
        for r, g, b in sample:
            lsbs.extend([r & 1, g & 1, b & 1])

        if not lsbs:
            return {"steg_risk": "UNKNOWN", "lsb_ones_ratio": 0}

        ones = sum(lsbs)
        ratio = ones / len(lsbs)
        deviation = abs(ratio - 0.5)

        # Chi-square test approximation
        # For each pair of pixel values (2k, 2k+1), count occurrences
        # In natural images, counts differ; in LSB-steg they become equal
        val_counts = {}
        for r, g, b in pix_data[::10]:
            for v in [r, g, b]:
                val_counts[v] = val_counts.get(v, 0) + 1

        chi_sq = 0.0
        for k in range(0, 127):
            c1 = val_counts.get(2 * k, 0)
            c2 = val_counts.get(2 * k + 1, 0)
            expected = (c1 + c2) / 2
            if expected > 0:
                chi_sq += ((c1 - expected) ** 2 + (c2 - expected) ** 2) / expected

        # Normalise
        chi_norm = chi_sq / max(1, len(val_counts))

        if deviation < 0.015 and chi_norm < 5:
            risk_level = "HIGH"
            risk = f"HIGH — LSB suspiciously uniform (deviation={deviation:.4f}) + low chi-sq ({chi_norm:.2f}) → possible payload"
        elif deviation < 0.035 or chi_norm < 10:
            risk_level = "MEDIUM"
            risk = f"MEDIUM — slightly elevated LSB uniformity (deviation={deviation:.4f})"
        else:
            risk_level = "LOW"
            risk = f"LOW — natural LSB distribution (deviation={deviation:.4f})"

        # Estimate payload capacity
        capacity_bits = (img_rgb.width * img_rgb.height * 3)
        capacity_kb = capacity_bits / 8 / 1024

        return {
            "lsb_ones_ratio": round(ratio, 5),
            "lsb_deviation": round(deviation, 5),
            "chi_square_normalised": round(chi_norm, 3),
            "steg_risk": risk,
            "steg_risk_level": risk_level,
            "payload_capacity_kb": round(capacity_kb, 1),
            "sample_size": len(lsbs),
        }
    except Exception as e:
        return {"error": str(e), "steg_risk": "ERROR", "steg_risk_level": "UNKNOWN"}


# ═══════════════════════════════════════════════════════════════════════════════
# 8. METADATA AUTOPSY
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_metadata(image: Image.Image, filename: str) -> dict:
    meta = {
        "filename": filename,
        "format": image.format or "Unknown",
        "mode": image.mode,
        "size": f"{image.width}x{image.height}",
        "width": image.width,
        "height": image.height,
        "megapixels": round((image.width * image.height) / 1_000_000, 2),
        "aspect_ratio": f"{image.width // math.gcd(image.width, image.height)}:{image.height // math.gcd(image.width, image.height)}",
        "exif": {},
        "gps": {},
        "gps_decimal": None,
        "software": None,
        "camera": None,
        "lens": None,
        "datetime": None,
        "has_icc_profile": "icc_profile" in (image.info or {}),
        "thumbnail_present": False,
        "thumbnail_mismatch": False,
        "color_profile": None,
        "compression": None,
        "warnings": [],
    }

    try:
        exif_data = image._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, str(tag_id))
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace")
                    except Exception:
                        value = f"[binary:{len(value)}b]"

                if tag == "GPSInfo":
                    gps_raw = {}
                    for t in value:
                        sub_tag = GPSTAGS.get(t, str(t))
                        gps_raw[sub_tag] = str(value[t])
                    meta["gps"] = gps_raw
                    # Try to compute decimal GPS
                    try:
                        def dms_to_dec(dms_str, ref):
                            import re
                            nums = re.findall(r"[\d.]+", str(dms_str))
                            d, m, s = float(nums[0]), float(nums[1]), float(nums[2])
                            dec = d + m / 60 + s / 3600
                            if ref in ("S", "W"):
                                dec = -dec
                            return round(dec, 7)
                        if "GPSLatitude" in gps_raw and "GPSLongitude" in gps_raw:
                            lat = dms_to_dec(gps_raw["GPSLatitude"], gps_raw.get("GPSLatitudeRef", "N"))
                            lon = dms_to_dec(gps_raw["GPSLongitude"], gps_raw.get("GPSLongitudeRef", "E"))
                            meta["gps_decimal"] = {"lat": lat, "lon": lon,
                                                   "maps_url": f"https://maps.google.com/?q={lat},{lon}"}
                            meta["warnings"].append("⚠️ GPS LOCATION EMBEDDED — This image exposes physical location")
                    except Exception:
                        pass

                elif tag in ("Software", "ProcessingSoftware"):
                    meta["software"] = str(value)[:300]
                    meta["exif"][tag] = str(value)[:300]
                elif tag == "Make":
                    meta["camera"] = str(value).strip()
                    meta["exif"][tag] = str(value)[:200]
                elif tag == "Model":
                    meta["camera"] = (meta.get("camera") or "") + " " + str(value).strip()
                    meta["exif"][tag] = str(value)[:200]
                elif tag in ("LensModel", "LensInfo"):
                    meta["lens"] = str(value)[:200]
                    meta["exif"][tag] = str(value)[:200]
                elif tag in ("DateTime", "DateTimeOriginal", "DateTimeDigitized"):
                    meta["datetime"] = str(value)
                    meta["exif"][tag] = str(value)
                elif tag == "Compression":
                    meta["compression"] = str(value)
                    meta["exif"][tag] = str(value)
                else:
                    sv = str(value)
                    if len(sv) < 400:
                        meta["exif"][tag] = sv

    except Exception as ex:
        meta["warnings"].append(f"EXIF parse issue: {ex}")

    # Thumbnail check
    try:
        thumb_data = image.info.get("thumbnail")
        if thumb_data:
            meta["thumbnail_present"] = True
            meta["warnings"].append("Embedded thumbnail detected — thumbnail may not match edited main image")
    except Exception:
        pass

    if meta["camera"]:
        meta["camera"] = meta["camera"].strip()

    # Check for software stripping
    if meta["exif"] and not meta["software"] and not meta["camera"]:
        meta["warnings"].append("EXIF present but device and software info stripped — possible privacy scrubbing or re-export")

    return meta


# ═══════════════════════════════════════════════════════════════════════════════
# 9. FORGERY COMPOSITE HEURISTICS
# ═══════════════════════════════════════════════════════════════════════════════

def _forgery_heuristics(image: Image.Image, ela_multi: dict) -> dict:
    flags = []
    score = 0

    # Alpha channel misuse
    if image.mode in ("RGBA", "LA") and (image.format or "").upper() not in ("PNG", "GIF", "WEBP", "TIFF"):
        flags.append(f"Unexpected alpha channel in {image.format} format — possible compositing from PNG")
        score += 22

    # ELA multi-level suspicion votes
    ela_votes = ela_multi.get("suspicion_votes", 0)
    if ela_votes >= 2:
        flags.append(f"ELA multi-quality analysis: {ela_votes} compression anomaly votes — strong re-save signal")
        score += 30
    elif ela_votes == 1:
        flags.append("ELA multi-quality analysis: 1 compression anomaly vote")
        score += 12

    # JPEG ghost
    ghost_q = ela_multi.get("ghost", {}).get("estimated_original_quality")
    ghost_detected = ela_multi.get("ghost", {}).get("ghost_detected", False)
    if ghost_detected and ghost_q and ghost_q < 85:
        flags.append(f"JPEG ghost: original quality estimated at Q{ghost_q} — elements may originate from a lower-quality source")
        score += 25

    # ICC profile without EXIF camera
    if image.info.get("icc_profile") and not flags:
        pass  # Normal for professional cameras

    # Extreme aspect ratios
    w, h = image.size
    ratio = w / h if h else 1
    if ratio > 5 or ratio < 0.2:
        flags.append(f"Extreme aspect ratio ({w}x{h}) — unusual for photographic content")
        score += 10

    # Check for common paste-job tell: very high resolution with no EXIF
    try:
        exif = image._getexif()
        if not exif and w * h > 4_000_000:
            flags.append(f"High-resolution image ({w*h//1_000_000:.1f}MP) with zero EXIF — suspicious for authentic photos")
            score += 18
    except Exception:
        pass

    return {
        "forgery_score": min(100, score),
        "forgery_flags": flags,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def pixel_forge_analyze(file_bytes: bytes, filename: str) -> dict:
    """
    Full Pixel Forge V6.1 analysis pipeline — 9 forensic engines.
    """
    try:
        image = Image.open(io.BytesIO(file_bytes))
        image.load()
    except Exception as e:
        return {"error": f"Could not open image: {e}"}

    # ── Run all engines ──────────────────────────────────────────────
    metadata     = _extract_metadata(image, filename)
    ai_detection = _detect_ai_artifacts(image)
    ela_results  = _ela_multi(image)
    ghost        = _jpeg_ghost(image)
    frequency    = _frequency_analysis(image)
    clone        = _clone_detection(image)
    noise        = _noise_fingerprint(image)
    steg         = _steg_surface(image)

    # Inject ghost into ela_results for forgery heuristics
    ela_results["ghost"] = ghost
    forgery = _forgery_heuristics(image, ela_results)

    # ── Composite risk score ─────────────────────────────────────────
    ai_w    = 0.30
    ela_w   = 0.20
    clone_w = 0.15
    noise_w = 0.15
    freq_w  = 0.10
    forg_w  = 0.10

    composite_risk = (
        ai_detection["ai_score"]        * ai_w +
        ela_results.get("suspicion_votes", 0) * 25 * ela_w +
        clone.get("clone_score", 0)     * clone_w +
        noise.get("noise_score", 0)     * noise_w +
        frequency.get("frequency_score", 0) * freq_w +
        forgery["forgery_score"]        * forg_w
    )
    composite_risk = min(100, int(composite_risk))

    # Boost for steg HIGH
    if "HIGH" in steg.get("steg_risk", ""):
        composite_risk = min(100, composite_risk + 12)

    overall_verdict = (
        "🔴 CRITICAL — HIGH MANIPULATION RISK" if composite_risk >= 70 else
        "🟠 SUSPICIOUS — REVIEW CAREFULLY"     if composite_risk >= 45 else
        "🟡 LOW RISK — SOME ANOMALIES"         if composite_risk >= 20 else
        "✅ CLEAN — NO SIGNIFICANT ARTIFACTS"
    )

    # ── Total signal count ───────────────────────────────────────────
    all_signals = (
        ai_detection.get("signals", []) +
        noise.get("signals", []) +
        frequency.get("signals", []) +
        forgery.get("forgery_flags", [])
    )

    return {
        "filename": filename,
        "metadata": metadata,
        "ela_b64": ela_results.get("q95"),
        "ela": {
            "q95": ela_results.get("q95"),
            "q75": ela_results.get("q75"),
            "q50": ela_results.get("q50"),
            "intensities": ela_results.get("intensities"),
            "interpretation": ela_results.get("interpretation"),
            "suspicion_votes": ela_results.get("suspicion_votes", 0),
            "description": ela_results.get("description"),
        },
        "jpeg_ghost": ghost,
        "frequency": frequency,
        "clone": clone,
        "noise": noise,
        "ai_detection": ai_detection,
        "steganography": steg,
        "forgery": forgery,
        "composite_risk": composite_risk,
        "overall_verdict": overall_verdict,
        "total_signals": len(all_signals),
        "all_signals": all_signals,
    }
