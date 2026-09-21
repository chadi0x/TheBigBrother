"""
THE BIG BROTHER // V7.0 TACTICAL FORENSIC SYSTEM
COMPANION POWER ENGINE: CROSS-PLATFORM LINGUISTIC STYLOMETRY ANALYZER (v7_stylometry_analyzer)
CLASSIFIED // OSINT & THREAT ACTOR ATTRIBUTION DIVISION

Performs quantitative forensic linguistics across multiple text samples or social bios:
- Lexical Diversity (Type-Token Ratio & Yule's Characteristic K)
- Punctuation & Emoji Distribution Fingerprint
- Capitalization and Grammar Habits
- Hapax Legomena (Uniqueness ratio)
- Cross-Sample Cosine & Jaccard Attribution Similarity
"""

import math
import re
from typing import Dict, Any, List

def analyze_single_sample(text: str) -> Dict[str, Any]:
    if not text or not text.strip():
        return {"words": 0, "chars": 0, "ttr": 0, "yules_k": 0}
        
    chars = len(text)
    # tokenize words
    words = re.findall(r"\b[a-zA-Z0-9_'’]+\b", text.lower())
    total_words = len(words)
    if total_words == 0:
        return {"words": 0, "chars": chars, "ttr": 0, "yules_k": 0}

    # Vocabulary frequency
    freq: Dict[str, int] = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1
        
    vocab_size = len(freq)
    ttr = vocab_size / total_words  # Type-Token Ratio
    
    # Hapax legomena (words occurring exactly once)
    hapax = sum(1 for count in freq.values() if count == 1)
    hapax_ratio = hapax / vocab_size if vocab_size > 0 else 0
    
    # Yule's Characteristic K (measure of vocabulary richness independent of text length)
    # S1 = sum(f_i), S2 = sum(f_i * i^2)
    m1 = total_words
    m2 = sum(count ** 2 for count in freq.values())
    yules_k = 10000 * (m2 - m1) / (m1 ** 2) if m1 > 1 else 0
    
    # Punctuation counts
    punct = {
        "exclamation": text.count("!"),
        "question": text.count("?"),
        "comma": text.count(","),
        "period": text.count("."),
        "semicolon": text.count(";"),
        "colon": text.count(":"),
        "ellipsis": text.count("...") + text.count("…"),
        "quotes": text.count('"') + text.count("'") + text.count("`"),
        "brackets": text.count("(") + text.count("[") + text.count("{")
    }
    
    # Casing stats
    caps = sum(1 for c in text if c.isupper())
    caps_ratio = caps / chars if chars > 0 else 0
    
    # Average sentence length
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if s.strip()]
    avg_sentence_len = total_words / len(sentences) if sentences else total_words

    return {
        "total_chars": chars,
        "total_words": total_words,
        "unique_vocab": vocab_size,
        "type_token_ratio": round(ttr, 4),
        "hapax_legomena": hapax,
        "hapax_ratio": round(hapax_ratio, 4),
        "yules_k": round(yules_k, 2),
        "caps_ratio": round(caps_ratio, 4),
        "avg_sentence_length": round(avg_sentence_len, 2),
        "punctuation_profile": punct,
        "top_frequencies": sorted(freq.items(), key=lambda x: x[1], reverse=True)[:10]
    }

def compare_stylometry(sample_a: str, sample_b: str) -> Dict[str, Any]:
    prof_a = analyze_single_sample(sample_a)
    prof_b = analyze_single_sample(sample_b)
    
    if prof_a["total_words"] == 0 or prof_b["total_words"] == 0:
        return {
            "status": "error",
            "error": "Both text samples must contain valid verbal content for attribution comparison."
        }
        
    words_a = set(w for w, _ in prof_a.get("top_frequencies", []))
    words_b = set(w for w, _ in prof_b.get("top_frequencies", []))
    
    # Jaccard vocab overlap
    intersection = words_a.intersection(words_b)
    union = words_a.union(words_b)
    jaccard = len(intersection) / len(union) if union else 0.0
    
    # Punctuation vector cosine similarity
    pa = prof_a["punctuation_profile"]
    pb = prof_b["punctuation_profile"]
    keys = list(pa.keys())
    dot = sum(pa[k] * pb[k] for k in keys)
    mag_a = math.sqrt(sum(pa[k] ** 2 for k in keys))
    mag_b = math.sqrt(sum(pb[k] ** 2 for k in keys))
    punct_similarity = dot / (mag_a * mag_b) if (mag_a > 0 and mag_b > 0) else 0.5
    
    # Metric proximity (TTR and Casing proximity)
    ttr_diff = abs(prof_a["type_token_ratio"] - prof_b["type_token_ratio"])
    ttr_sim = max(0, 1.0 - ttr_diff)
    
    caps_diff = abs(prof_a["caps_ratio"] - prof_b["caps_ratio"])
    caps_sim = max(0, 1.0 - (caps_diff * 5))
    
    # Weighted Authorship Attribution Confidence
    score = (0.35 * punct_similarity) + (0.25 * jaccard) + (0.20 * ttr_sim) + (0.20 * caps_sim)
    confidence_pct = round(min(100.0, max(5.0, score * 100)), 1)
    
    if confidence_pct >= 80:
        verdict = "HIGH_CONFIDENCE_SAME_AUTHOR"
    elif confidence_pct >= 55:
        verdict = "PROBABLE_SAME_AUTHOR"
    elif confidence_pct >= 35:
        verdict = "INCONCLUSIVE_INDEPENDENT_SAMPLE"
    else:
        verdict = "DISTINCT_AUTHORS_DETECTED"
        
    return {
        "status": "success",
        "attribution_confidence": f"{confidence_pct}%",
        "score_numeric": confidence_pct,
        "verdict": verdict,
        "sample_a_metrics": prof_a,
        "sample_b_metrics": prof_b,
        "cross_vector_analysis": {
            "punctuation_similarity": round(punct_similarity, 3),
            "vocabulary_jaccard_overlap": round(jaccard, 3),
            "lexical_richness_delta": round(ttr_diff, 4),
            "shared_signature_tokens": list(intersection)
        }
    }

async def run_stylometry_analysis(sample_a: str, sample_b: str = "") -> Dict[str, Any]:
    if not sample_b:
        # Single sample profiling
        prof = analyze_single_sample(sample_a)
        return {
            "status": "success",
            "mode": "single_profile",
            "profile": prof
        }
    return compare_stylometry(sample_a, sample_b)
