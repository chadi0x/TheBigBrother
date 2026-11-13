"""
SKY RADAR // VX HARDENED ADS-B INTERCEPT

Upgraded from a flat state dump to a sorted, enriched airspace picture:
latitude-corrected bounding box, airborne filtering, emergency squawk
classification, military/VIP callsign heuristics, distance/bearing, and
per-country statistics. Uses the keyless OpenSky Network API.
"""
from __future__ import annotations

import json
import math
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    requests = None


EMERGENCY_SQUAWKS = {
    "7700": ("MAYDAY", "General emergency"),
    "7600": ("RADIO FAILURE", "Lost radio communication"),
    "7500": ("HIJACK", "Unlawful interference"),
}
MILITARY_PREFIXES = ("RCH", "REACH", "FORTE", "HOMER", "NCHO", "GAF", "IAM", "CFC", "RAAF", "ASY", "MMF", "PLF", "BAF", "NAF", "SUI", "HKY", "PAT", "EVAC", "SPAR", "SAM", "VENUS", "EXEC")
VIP_PREFIXES = ("AF1", "AF2", "EXEC", "SAM", "VENUS", "SPAR", "GOLD", "KING", "CEF", "NIGHTHAWK")


def _bbox(lat: float, lon: float, radius_km: float) -> Dict[str, float]:
    lat_delta = radius_km / 111.32
    cos_lat = max(0.15, math.cos(math.radians(lat)))
    lon_delta = radius_km / (111.32 * cos_lat)
    return {
        "lamin": round(max(-90.0, lat - lat_delta), 5),
        "lamax": round(min(90.0, lat + lat_delta), 5),
        "lomin": round(lon - lon_delta, 5),
        "lomax": round(lon + lon_delta, 5),
    }


def _distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return round(2 * r * math.asin(min(1.0, math.sqrt(a))), 1)


def _bearing(lat1: float, lon1: float, lat2: float, lon2: float) -> int:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    x = math.sin(dl) * math.cos(p2)
    y = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return int((math.degrees(math.atan2(x, y)) + 360) % 360)


def _fetch_opensky(url: str) -> Dict[str, Any]:
    if requests is not None:
        try:
            resp = requests.get(url, timeout=10, headers={"User-Agent": "TheBigBrotherVX-Radar"})
            if resp.status_code == 200:
                return {"data": resp.json(), "status": 200}
            if resp.status_code == 429:
                return {"status": 429, "error": "OpenSky rate limit reached. Try a smaller radius or wait ~60s."}
            return {"status": resp.status_code, "error": f"OpenSky HTTP {resp.status_code}"}
        except Exception:
            pass
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "TheBigBrotherVX-Radar"})
        with urllib.request.urlopen(req, timeout=9) as resp:
            return {"data": json.loads(resp.read().decode("utf-8", errors="replace")), "status": resp.getcode()}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "error": f"OpenSky HTTP {exc.code}: {exc.reason}"}
    except Exception as exc:
        return {"status": 0, "error": f"{type(exc).__name__}: {exc}"}


def get_flight_radar(lat: float, lon: float, radius_km: float = 100) -> Dict[str, Any]:
    radius_km = max(5.0, min(1000.0, float(radius_km or 100)))
    box = _bbox(lat, lon, radius_km)
    url = (
        "https://opensky-network.org/api/states/all"
        f"?lamin={box['lamin']}&lomin={box['lomin']}&lamax={box['lamax']}&lomax={box['lomax']}"
    )
    results: Dict[str, Any] = {
        "status": "success",
        "location": {"lat": lat, "lon": lon, "radius_km": radius_km},
        "bbox": box,
        "flights": [],
        "count": 0,
        "airborne_count": 0,
        "emergency_count": 0,
        "military_count": 0,
        "countries": [],
        "threat_score": 10,
        "threat_level": "NOMINAL",
        "error": None,
    }
    fetched = _fetch_opensky(url)
    if fetched.get("error"):
        results["status"] = "upstream_diagnostic"
        results["error"] = fetched["error"]

    data = fetched.get("data")
    if isinstance(data, dict):
        states = data.get("states") or []
        flights: List[Dict[str, Any]] = []
        countries: Dict[str, int] = {}
        for s in states:
            try:
                if not s or len(s) < 14:
                    continue
                on_ground = bool(s[8])
                if on_ground:
                    continue
                callsign = (s[1] or "").strip()
                f_lat, f_lon = s[6], s[5]
                if f_lat is None or f_lon is None:
                    continue
                squawk = str(s[14]) if len(s) > 14 and s[14] else ""
                emergency = EMERGENCY_SQUAWKS.get(squawk)
                military = callsign.upper().startswith(MILITARY_PREFIXES)
                vip = callsign.upper().startswith(VIP_PREFIXES)
                country = s[2] or "Unknown"
                countries[country] = countries.get(country, 0) + 1
                flights.append({
                    "icao24": s[0],
                    "callsign": callsign or "NO_CALLSIGN",
                    "country": country,
                    "lon": f_lon,
                    "lat": f_lat,
                    "altitude_m": s[13] if s[13] is not None else s[7],
                    "altitude_ft": int((s[13] if s[13] is not None else s[7] or 0) * 3.28084),
                    "velocity_ms": s[9],
                    "velocity_kmh": round((s[9] or 0) * 3.6, 1),
                    "heading_deg": s[10],
                    "vertical_rate_ms": s[11],
                    "squawk": squawk,
                    "on_ground": on_ground,
                    "distance_km": _distance_km(lat, lon, f_lat, f_lon),
                    "bearing_deg": _bearing(lat, lon, f_lat, f_lon),
                    "emergency": bool(emergency),
                    "emergency_label": emergency[0] if emergency else "",
                    "emergency_detail": emergency[1] if emergency else "",
                    "military": military,
                    "vip": vip,
                    "last_contact": s[4],
                })
            except Exception:
                continue

        flights.sort(key=lambda f: f["distance_km"])
        results["flights"] = flights[:120]
        results["count"] = len(flights)
        results["airborne_count"] = len(flights)
        results["emergency_count"] = sum(1 for f in flights if f["emergency"])
        results["military_count"] = sum(1 for f in flights if f["military"])
        results["countries"] = [
            {"country": c, "aircraft": n}
            for c, n in sorted(countries.items(), key=lambda kv: -kv[1])[:15]
        ]
        if not flights:
            results["message"] = "No airborne transponder contacts in this radar sector."

    threat = 10
    threat += min(45, results["count"] * 2)
    threat += results["emergency_count"] * 25
    threat += min(15, results["military_count"] * 3)
    results["threat_score"] = min(100, threat)
    results["threat_level"] = (
        "CRITICAL" if threat >= 70 else "ELEVATED" if threat >= 40 else "NOMINAL"
    )
    return results
