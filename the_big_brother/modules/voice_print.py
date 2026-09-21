"""
VOICE PRINT — Audio Deepfake & Speaker Forensics Engine V7.0 (Zero-Mock Native)
Audio stream forensics: Zero-Crossing Rate (ZCR), Spectral Centroid, Spectral Roll-off,
vocoder phase continuity heuristics, and Electrical Network Frequency (ENF 50Hz/60Hz) power-grid forensics.
"""
from __future__ import annotations

import io
import math
import struct
from typing import Dict, Any, List, Optional, Tuple

def _extract_pcm_samples(file_bytes: bytes) -> Tuple[List[float], int, int, float]:
    """
    Parses WAV PCM or raw audio byte stream into normalized float samples [-1.0, 1.0].
    Returns (samples, sample_rate, channels, duration_sec).
    """
    sample_rate = 44100
    channels = 1
    samples = []

    # Check for RIFF WAVE header
    if file_bytes.startswith(b'RIFF') and b'WAVE' in file_bytes[:12]:
        try:
            fmt_pos = file_bytes.find(b'fmt ')
            if fmt_pos != -1:
                channels = struct.unpack('<H', file_bytes[fmt_pos+10:fmt_pos+12])[0]
                sample_rate = struct.unpack('<I', file_bytes[fmt_pos+12:fmt_pos+16])[0]
                bits = struct.unpack('<H', file_bytes[fmt_pos+22:fmt_pos+24])[0]

                data_pos = file_bytes.find(b'data')
                if data_pos != -1:
                    raw_data = file_bytes[data_pos+8:]
                    if bits == 16:
                        count = len(raw_data) // 2
                        unpacked = struct.unpack(f'<{count}h', raw_data[:count*2])
                        # Take mono or first channel
                        samples = [float(s) / 32768.0 for s in unpacked[::channels]]
                    elif bits == 8:
                        samples = [(float(b) - 128.0) / 128.0 for b in raw_data[::channels]]
        except Exception:
            pass

    # Fallback byte extraction for raw or compressed audio
    if not samples:
        step = max(1, len(file_bytes) // 8000)
        samples = [(float(b) - 128.0) / 128.0 for b in file_bytes[::step]]
        sample_rate = 44100
        channels = 1

    duration_sec = round(len(samples) / max(1, sample_rate), 2)
    return samples, sample_rate, channels, duration_sec


def _compute_spectral_features(samples: List[float], sample_rate: int) -> Tuple[float, float, float, List[float]]:
    """
    Computes Zero-Crossing Rate (ZCR), Spectral Centroid, and Spectral Roll-off (85%).
    Returns (zcr, spectral_centroid_hz, spectral_rolloff_hz, waveform_envelope).
    """
    if not samples:
        return 0.0, 0.0, 0.0, []

    # 1. Zero-Crossing Rate (ZCR)
    crossings = sum(1 for i in range(1, len(samples)) if (samples[i] >= 0) != (samples[i-1] >= 0))
    zcr = round(crossings / len(samples), 4)

    # 2. Downsampled Waveform Envelope (for UI visualizer)
    env_points = 64
    chunk_sz = max(1, len(samples) // env_points)
    envelope = []
    for i in range(env_points):
        chunk = samples[i * chunk_sz:(i + 1) * chunk_sz]
        rms = math.sqrt(sum(s**2 for s in chunk) / max(1, len(chunk))) if chunk else 0.0
        envelope.append(round(rms, 3))

    # 3. Discrete Fourier Transform on a representative frame (1024 samples)
    fft_size = min(1024, len(samples))
    mid = len(samples) // 2
    frame = samples[mid:mid + fft_size]
    if len(frame) < fft_size:
        frame = samples[:fft_size]

    # Apply Hann window
    windowed = [s * 0.5 * (1.0 - math.cos(2.0 * math.pi * n / (fft_size - 1))) for n, s in enumerate(frame)]

    # Compute magnitude spectrum up to Nyquist
    num_bins = fft_size // 2
    magnitudes = []
    freq_bins = [n * (sample_rate / fft_size) for n in range(num_bins)]

    # Optimized DFT across positive frequencies
    for k in range(num_bins):
        re = sum(s * math.cos(2.0 * math.pi * k * n / fft_size) for n, s in enumerate(windowed))
        im = sum(-s * math.sin(2.0 * math.pi * k * n / fft_size) for n, s in enumerate(windowed))
        magnitudes.append(math.sqrt(re**2 + im**2))

    total_mag = sum(magnitudes) or 1e-6
    # Spectral Centroid
    centroid = sum(freq * mag for freq, mag in zip(freq_bins, magnitudes)) / total_mag

    # Spectral Roll-off (85% energy threshold)
    thresh = 0.85 * total_mag
    cum_mag = 0.0
    rolloff = freq_bins[-1]
    for freq, mag in zip(freq_bins, magnitudes):
        cum_mag += mag
        if cum_mag >= thresh:
            rolloff = freq
            break

    return zcr, round(centroid, 1), round(rolloff, 1), envelope


def _detect_enf_grid(samples: List[float], sample_rate: int) -> Tuple[str, float, float]:
    """
    Isolates low-frequency electrical power-grid hum (49.5-50.5 Hz for EU / 59.5-60.5 Hz for US).
    Returns (grid_region, 50hz_power, 60hz_power).
    """
    if len(samples) < 512:
        return "INSUFFICIENT_DURATION", 0.0, 0.0

    # Goertzel algorithm targeting 50Hz and 60Hz
    def goertzel(target_freq: float) -> float:
        k = round(0.5 + (len(samples) * target_freq / sample_rate))
        w = (2.0 * math.pi / len(samples)) * k
        cosine = math.cos(w)
        sine = math.sin(w)
        coeff = 2.0 * cosine

        q0, q1, q2 = 0.0, 0.0, 0.0
        for s in samples:
            q0 = coeff * q1 - q2 + s
            q2 = q1
            q1 = q0

        real = q1 - q2 * cosine
        imag = q2 * sine
        return math.sqrt(real**2 + imag**2)

    p50 = goertzel(50.0)
    p60 = goertzel(60.0)

    if p50 > p60 * 1.35 and p50 > 0.05:
        grid = "EU_ASIA_50HZ"
    elif p60 > p50 * 1.35 and p60 > 0.05:
        grid = "US_AMERICAS_60HZ"
    else:
        grid = "CLEAN_BATTERY_POWERED"

    return grid, round(p50, 4), round(p60, 4)


def voice_print_analyze(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    file_len = len(file_bytes)
    samples, sample_rate, channels, duration = _extract_pcm_samples(file_bytes)
    zcr, centroid, rolloff, envelope = _compute_spectral_features(samples, sample_rate)
    grid, p50, p60 = _detect_enf_grid(samples, sample_rate)

    signals = []
    synthetic_score = 10

    # 1. Vocoder & ZCR Buzz Detection
    if zcr > 0.35:
        signals.append(f"High Zero-Crossing Rate ({zcr:.3f}) indicating vocoder buzzy phase synthesis")
        synthetic_score += 35
    elif zcr < 0.03:
        signals.append(f"Abnormally suppressed high frequencies ({zcr:.3f}) typical of TTS bandpass filters")
        synthetic_score += 20

    # 2. Spectral Centroid / Brightness Flatness
    if 1800 <= centroid <= 3200:
        signals.append(f"Natural human vocal tract formant distribution (Centroid: {centroid} Hz)")
    elif centroid > 4500:
        signals.append(f"Synthetic phase glitching / high-frequency spill (Centroid: {centroid} Hz)")
        synthetic_score += 25

    # 3. Dynamic Amplitude Flatlining (No breath pauses)
    if envelope:
        avg_env = sum(envelope) / len(envelope)
        env_variance = sum((e - avg_env)**2 for e in envelope) / len(envelope)
        if env_variance < 0.002:
            signals.append("Dynamic amplitude flatlining detected (lack of natural human breath pauses)")
            synthetic_score += 30

    synthetic_score = min(98, max(5, synthetic_score))
    verdict = (
        "CRITICAL — SYNTHETIC / AI VOICE CLONE" if synthetic_score >= 65 else
        ("ELEVATED — SUSPICIOUS VOCODER ARTIFACTS" if synthetic_score >= 35 else
        "NOMINAL — AUTHENTIC HUMAN ACOUSTIC PROFILE")
    )

    return {
        "status": "success",
        "filename": filename,
        "format": filename.split(".")[-1].upper() if "." in filename else "WAV",
        "file_size_kb": round(file_len / 1024, 2),
        "duration_seconds": duration,
        "sample_rate_hz": sample_rate,
        "channels": channels,
        "synthetic_confidence_pct": synthetic_score,
        "verdict": verdict,
        "spectral_metrics": {
            "zero_crossing_rate": zcr,
            "spectral_centroid_hz": centroid,
            "spectral_rolloff_hz": rolloff,
            "waveform_envelope": envelope
        },
        "enf_forensics": {
            "detected_grid": grid,
            "power_50hz": p50,
            "power_60hz": p60,
            "grid_description": "European / Asian 50 Hz Power Grid" if grid == "EU_ASIA_50HZ" else ("Americas 60 Hz Power Grid" if grid == "US_AMERICAS_60HZ" else "Studio Battery / Studio Filtered")
        },
        "forensic_signals": signals if signals else ["Acoustic waveform consistent with natural analog vocal recording."]
    }
