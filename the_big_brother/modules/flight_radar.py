import datetime
import json
import urllib.request
import urllib.error

try:
    import requests
except ImportError:
    requests = None


def get_flight_radar(lat: float, lon: float, radius_km: float = 100):
    """
    Fetches real-time flight data near the target coordinates.
    Uses OpenSky Network API (Free tier). Zero synthetic flights.
    """
    deg_diff = radius_km / 111.0
    
    lamin = lat - deg_diff
    lamax = lat + deg_diff
    lomin = lon - deg_diff
    lomax = lon + deg_diff
    
    url = f"https://opensky-network.org/api/states/all?lamin={lamin}&lomin={lomin}&lamax={lamax}&lomax={lomax}"
    
    results = {
        "status": "success",
        "location": {"lat": lat, "lon": lon},
        "flights": [],
        "count": 0,
        "threat_score": 10,
        "threat_level": "NOMINAL",
        "error": None
    }
    
    data = None
    if requests is not None:
        try:
            resp = requests.get(url, timeout=8, headers={"User-Agent": "TheBigBrotherV7-Radar"})
            if resp.status_code == 200:
                data = resp.json()
            elif resp.status_code == 429:
                results["status"] = "upstream_diagnostic"
                results["error"] = "OpenSky Network rate limit reached. Upstream radar paused."
            else:
                results["status"] = "upstream_diagnostic"
                results["error"] = f"Radar Gateway HTTP {resp.status_code}"
        except Exception as e:
            pass

    if data is None and results.get("status") == "success":
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "TheBigBrotherV7-Radar"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.getcode() == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as he:
            results["status"] = "upstream_diagnostic"
            results["error"] = f"Radar Gateway HTTP {he.code}: {he.reason}"
        except Exception as e:
            results["status"] = "upstream_diagnostic"
            results["error"] = str(e)

    if data and isinstance(data, dict):
        states = data.get("states") or []
        if states:
            for s in states[:25]:
                # OpenSky format: 0=icao24, 1=callsign, 2=country, 5=lon, 6=lat, 7=baro_alt, 9=velocity, 10=true_track, 11=vertical_rate, 13=geo_alt
                results["flights"].append({
                    "icao24": s[0],
                    "callsign": (s[1] or "").strip(),
                    "country": s[2],
                    "lon": s[5],
                    "lat": s[6],
                    "altitude_m": s[13] if s[13] is not None else s[7],
                    "velocity_ms": s[9],
                    "heading_deg": s[10],
                    "vertical_rate_ms": s[11]
                })
            results["count"] = len(results["flights"])
        else:
            results["message"] = "No transponder-active aircraft detected in this radar sector."

    threat = min(80, 10 + (results["count"] * 5))
    results["threat_score"] = threat
    results["threat_level"] = "ELEVATED" if threat >= 40 else "NOMINAL"
        
    return results
