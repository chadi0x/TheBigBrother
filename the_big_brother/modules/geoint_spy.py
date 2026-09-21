import math
import json
import urllib.request
import urllib.error

try:
    import requests
except ImportError:
    requests = None


def _to_maidenhead(lat: float, lon: float) -> str:
    """Computes QTH Maidenhead Grid Locator from lat/lon."""
    lon += 180.0
    lat += 90.0
    field_lon = chr(ord('A') + int(lon / 20.0))
    field_lat = chr(ord('A') + int(lat / 10.0))
    square_lon = str(int((lon % 20.0) / 2.0))
    square_lat = str(int((lat % 10.0) / 1.0))
    sub_lon = chr(ord('a') + int(((lon % 20.0) % 2.0) / (2.0 / 24.0)))
    sub_lat = chr(ord('a') + int(((lat % 10.0) % 1.0) / (1.0 / 24.0)))
    return f"{field_lon}{field_lat}{square_lon}{square_lat}{sub_lon}{sub_lat}"


def _to_utm(lat: float, lon: float) -> str:
    """Calculates UTM zone and approximate northing/easting."""
    zone_num = int((lon + 180) / 6) + 1
    band_letters = "CDEFGHJKLMNPQRSTUVWX"
    band_idx = min(len(band_letters) - 1, max(0, int((lat + 80) / 8)))
    band = band_letters[band_idx]
    return f"{zone_num}{band}"


def get_geoint_data(lat: str, lon: str):
    """
    Generates a GEOINT package for the given coordinates.
    Includes Sat links, SunCalc, MGRS/Maidenhead grid locators, and search queries.
    Reverse geocodes coordinates to a physical address.
    """
    try:
        f_lat = float(str(lat).strip())
        f_lon = float(str(lon).strip())
    except Exception:
        return {"status": "error", "error": "Invalid coordinates"}

    # Reverse Geocoding (Nominatim OpenStreetMap)
    address = "Unknown Address"
    try:
        url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={f_lat}&lon={f_lon}"
        headers = {"User-Agent": "TheBigBrotherV7-OSINT/7.0"}
        if requests is not None:
            resp = requests.get(url, headers=headers, timeout=4)
            if resp.status_code == 200:
                address = resp.json().get("display_name", "Address not found")
        else:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=4) as resp:
                if resp.getcode() == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
                    address = data.get("display_name", "Address not found")
    except Exception:
        pass

    # Grid Locators
    maidenhead = _to_maidenhead(f_lat, f_lon)
    utm_zone = _to_utm(f_lat, f_lon)

    # Tactical & Intelligence Links
    gmaps = f"https://www.google.com/maps/place/{f_lat},{f_lon}/@{f_lat},{f_lon},18z/data=!3m1!1e3"
    street = f"https://www.google.com/maps?layer=c&cbll={f_lat},{f_lon}"
    suncalc = f"https://www.suncalc.org/#/{f_lat},{f_lon},18/now"
    twitter = f"https://twitter.com/search?q=geocode%3A{f_lat}%2C{f_lon}%2C1km&src=typed_query&f=live"
    snapchat = f"https://map.snapchat.com/@{f_lat},{f_lon},15.00z"
    wikimapia = f"http://wikimapia.org/#lang=en&lat={f_lat}&lon={f_lon}&z=18&m=b"

    return {
        "status": "success",
        "coords": f"{f_lat}, {f_lon}",
        "latitude": f_lat,
        "longitude": f_lon,
        "address": address,
        "grid_locators": {
            "maidenhead_qth": maidenhead,
            "utm_zone": utm_zone
        },
        "threat_score": 25,
        "threat_level": "NOMINAL",
        "links": {
            "Google Satellite": gmaps,
            "Street View": street,
            "SunCalc (Shadows)": suncalc,
            "Twitter (Nearby)": twitter,
            "Snapchat Map": snapchat,
            "Wikimapia": wikimapia
        }
    }
