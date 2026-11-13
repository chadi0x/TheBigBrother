"""
GEOINT SPY // VX HARDENED COORDINATE INTELLIGENCE

Upgraded with coordinate validation, accurate 8-character Maidenhead locator,
true UTM easting/northing, structured reverse geocoding (Nominatim + BigDataCloud
fallback), terrain elevation and live solar geometry.
"""
from __future__ import annotations

import datetime
import json
import math
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None


def _fetch_json(url: str, timeout: float = 6.0) -> Optional[Dict[str, Any]]:
    headers = {"User-Agent": "TheBigBrother-VX/1.0 (OSINT research)", "Accept": "application/json"}
    if requests is not None:
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.getcode() == 200:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        pass
    return None


def _to_maidenhead(lat: float, lon: float) -> Dict[str, str]:
    """Accurate Maidenhead (QTH) locator, 6 and 8 character forms."""
    lon = lon + 180.0
    lat = lat + 90.0
    if not (0 <= lon <= 360 and 0 <= lat <= 180):
        return {"grid6": "", "grid8": ""}
    A = ord("A")
    field_lon = int(lon // 20)
    field_lat = int(lat // 10)
    lon_r = lon % 20
    lat_r = lat % 10
    square_lon = int(lon_r // 2)
    square_lat = int(lat_r // 1)
    lon_r = lon_r % 2
    lat_r = lat_r % 1
    sub_lon = int(lon_r / (2 / 24))
    sub_lat = int(lat_r / (1 / 24))
    lon_r = lon_r % (2 / 24)
    lat_r = lat_r % (1 / 24)
    ext_lon = int(lon_r / (2 / 240))
    ext_lat = int(lat_r / (1 / 240))
    grid6 = (
        chr(A + field_lon) + chr(A + field_lat)
        + str(square_lon) + str(square_lat)
        + chr(A + sub_lon) + chr(A + sub_lat)
    )
    grid8 = grid6 + str(ext_lon) + str(ext_lat)
    return {"grid6": grid6, "grid8": grid8}


def _utm_band(lat: float) -> str:
    bands = "CDEFGHJKLMNPQRSTUVWX"
    if lat < -80 or lat > 84:
        return "Z"
    idx = int((lat + 80) / 8)
    return bands[min(len(bands) - 1, max(0, idx))]


def _to_utm(lat: float, lon: float) -> Dict[str, Any]:
    """WGS84 UTM conversion with standard series expansions."""
    if not (-80 <= lat <= 84):
        return {"zone": None, "band": "Z", "easting": None, "northing": None, "hemisphere": "N/A"}
    zone = int((lon + 180.0) / 6.0) + 1
    # Norway / Svalbard exceptions
    if 56 <= lat < 64 and 3 <= lon < 12:
        zone = 32
    if 72 <= lat < 84:
        if 0 <= lon < 9:
            zone = 31
        elif 9 <= lon < 21:
            zone = 33
        elif 21 <= lon < 33:
            zone = 35
        elif 33 <= lon < 42:
            zone = 37
    lon0 = math.radians((zone - 1) * 6 - 180 + 3)
    lat_r = math.radians(lat)
    lon_r = math.radians(lon)
    a = 6378137.0
    f = 1 / 298.257223563
    e2 = f * (2 - f)
    ep2 = e2 / (1 - e2)
    k0 = 0.9996
    N = a / math.sqrt(1 - e2 * math.sin(lat_r) ** 2)
    T = math.tan(lat_r) ** 2
    C = ep2 * math.cos(lat_r) ** 2
    A = math.cos(lat_r) * (lon_r - lon0)
    M = a * (
        (1 - e2 / 4 - 3 * e2 ** 2 / 64 - 5 * e2 ** 3 / 256) * lat_r
        - (3 * e2 / 8 + 3 * e2 ** 2 / 32 + 45 * e2 ** 3 / 1024) * math.sin(2 * lat_r)
        + (15 * e2 ** 2 / 256 + 45 * e2 ** 3 / 1024) * math.sin(4 * lat_r)
        - (35 * e2 ** 3 / 3072) * math.sin(6 * lat_r)
    )
    easting = k0 * N * (
        A + (1 - T + C) * A ** 3 / 6
        + (5 - 18 * T + T ** 2 + 72 * C - 58 * ep2) * A ** 5 / 120
    ) + 500000.0
    northing = k0 * (
        M + N * math.tan(lat_r) * (
            A ** 2 / 2 + (5 - T + 9 * C + 4 * C ** 2) * A ** 4 / 24
            + (61 - 58 * T + T ** 2 + 600 * C - 330 * ep2) * A ** 6 / 720
        )
    )
    if lat < 0:
        northing += 10000000.0
    return {
        "zone": zone,
        "band": _utm_band(lat),
        "easting": round(easting, 2),
        "northing": round(northing, 2),
        "hemisphere": "S" if lat < 0 else "N",
        "notation": f"{zone}{_utm_band(lat)} {round(easting)}E {round(northing)}N",
    }


def _solar_geometry(lat: float, lon: float, when: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """NOAA solar position approximation (elevation/azimuth in degrees)."""
    now = when or datetime.datetime.now(datetime.timezone.utc)
    day = now.timetuple().tm_yday
    hour = now.hour + now.minute / 60 + now.second / 3600
    gamma = 2 * math.pi / 365 * (day - 1 + (hour - 12) / 24)
    eqtime = 229.18 * (
        0.000075 + 0.001868 * math.cos(gamma) - 0.032077 * math.sin(gamma)
        - 0.014615 * math.cos(2 * gamma) - 0.040849 * math.sin(2 * gamma)
    )
    decl = (
        0.006918 - 0.399912 * math.cos(gamma) + 0.070257 * math.sin(gamma)
        - 0.006758 * math.cos(2 * gamma) + 0.000907 * math.sin(2 * gamma)
        - 0.002697 * math.cos(3 * gamma) + 0.00148 * math.sin(3 * gamma)
    )
    time_offset = eqtime + 4 * lon
    true_solar_time = (hour * 60 + time_offset) % 1440
    hour_angle = math.radians(true_solar_time / 4 - 180)
    lat_r = math.radians(lat)
    cos_zenith = (
        math.sin(lat_r) * math.sin(decl)
        + math.cos(lat_r) * math.cos(decl) * math.cos(hour_angle)
    )
    cos_zenith = max(-1.0, min(1.0, cos_zenith))
    zenith = math.acos(cos_zenith)
    elevation = 90 - math.degrees(zenith)
    azimuth = math.degrees(
        math.atan2(
            math.sin(hour_angle),
            math.cos(hour_angle) * math.sin(lat_r) - math.tan(decl) * math.cos(lat_r),
        )
    ) + 180
    return {
        "utc": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "elevation_deg": round(elevation, 2),
        "azimuth_deg": round(azimuth, 2),
        "zenith_deg": round(math.degrees(zenith), 2),
        "declination_deg": round(math.degrees(decl), 3),
        "equation_of_time_min": round(eqtime, 2),
        "true_solar_time_min": round(true_solar_time, 2),
        "is_daylight": elevation > 0,
        "shadow_direction_deg": round((azimuth + 180) % 360, 1) if elevation > 0 else None,
        "shadow_length_ratio": round(1 / math.tan(math.radians(elevation)), 2) if elevation > 0.5 else None,
    }


def _reverse_geocode(lat: float, lon: float) -> Dict[str, Any]:
    url = (
        "https://nominatim.openstreetmap.org/reverse?format=jsonv2"
        f"&lat={lat}&lon={lon}&zoom=18&addressdetails=1"
    )
    data = _fetch_json(url, timeout=6)
    if isinstance(data, dict) and data.get("display_name"):
        addr = data.get("address") or {}
        return {
            "address": data.get("display_name"),
            "source": "Nominatim / OpenStreetMap",
            "country": addr.get("country", ""),
            "country_code": addr.get("country_code", "").upper(),
            "state": addr.get("state", ""),
            "county": addr.get("county", ""),
            "city": addr.get("city") or addr.get("town") or addr.get("village") or addr.get("municipality", ""),
            "suburb": addr.get("suburb") or addr.get("neighbourhood", ""),
            "road": addr.get("road", ""),
            "postcode": addr.get("postcode", ""),
            "osm_type": data.get("osm_type", ""),
            "osm_id": data.get("osm_id", ""),
            "place_rank": data.get("place_rank"),
            "bounding_box": data.get("boundingbox", []),
        }
    fallback = _fetch_json(
        "https://api.bigdatacloud.net/data/reverse-geocode-client"
        f"?latitude={lat}&longitude={lon}&localityLanguage=en",
        timeout=6,
    )
    if isinstance(fallback, dict):
        return {
            "address": ", ".join(
                x for x in [
                    fallback.get("locality"), fallback.get("city"),
                    fallback.get("principalSubdivision"), fallback.get("countryName"),
                ] if x
            ) or "Address not found",
            "source": "BigDataCloud",
            "country": fallback.get("countryName", ""),
            "country_code": fallback.get("countryCode", ""),
            "state": fallback.get("principalSubdivision", ""),
            "city": fallback.get("city", ""),
            "locality": fallback.get("locality", ""),
            "postcode": fallback.get("postcode", ""),
        }
    return {"address": "Unknown Address", "source": "unavailable"}


def _elevation(lat: float, lon: float) -> Optional[float]:
    data = _fetch_json(f"https://api.open-meteo.com/v1/elevation?latitude={lat}&longitude={lon}", timeout=6)
    try:
        return float(data["elevation"][0])
    except Exception:
        return None


def get_geoint_data(lat: str, lon: str) -> Dict[str, Any]:
    try:
        f_lat = float(str(lat).strip())
        f_lon = float(str(lon).strip())
    except Exception:
        return {"status": "error", "error": "Invalid coordinates"}
    if not (-90 <= f_lat <= 90):
        return {"status": "error", "error": "Latitude must be between -90 and 90"}
    if not (-180 <= f_lon <= 180):
        return {"status": "error", "error": "Longitude must be between -180 and 180"}

    geo = _reverse_geocode(f_lat, f_lon)
    maidenhead = _to_maidenhead(f_lat, f_lon)
    utm = _to_utm(f_lat, f_lon)
    solar = _solar_geometry(f_lat, f_lon)
    elevation_m = _elevation(f_lat, f_lon)

    gmaps = f"https://www.google.com/maps/place/{f_lat},{f_lon}/@{f_lat},{f_lon},18z/data=!3m1!1e3"
    street = f"https://www.google.com/maps?layer=c&cbll={f_lat},{f_lon}"
    suncalc = f"https://www.suncalc.org/#/{f_lat},{f_lon},18/now"
    twitter = f"https://twitter.com/search?q=geocode%3A{f_lat}%2C{f_lon}%2C1km&src=typed_query&f=live"
    snapchat = f"https://map.snapchat.com/@{f_lat},{f_lon},15.00z"
    wikimapia = f"http://wikimapia.org/#lang=en&lat={f_lat}&lon={f_lon}&z=18&m=b"
    osm = f"https://www.openstreetmap.org/?mlat={f_lat}&mlon={f_lon}#map=18/{f_lat}/{f_lon}"
    peakvisor = f"https://peakvisor.com/panorama.html?lat={f_lat}&lng={f_lon}&alt={elevation_m or 0}"

    precision = 5 if (len(str(lat).split(".")[-1]) >= 5 and "." in str(lat)) else 3
    threat = min(60, 12 + precision * 3 + (6 if geo.get("road") else 0))

    return {
        "status": "success",
        "coords": f"{f_lat}, {f_lon}",
        "latitude": f_lat,
        "longitude": f_lon,
        "address": geo.get("address", "Unknown Address"),
        "reverse_geocode": geo,
        "elevation_m": elevation_m,
        "grid_locators": {
            "maidenhead_qth": maidenhead.get("grid6", ""),
            "maidenhead_qth8": maidenhead.get("grid8", ""),
            "utm_zone": f"{utm.get('zone')}{utm.get('band')}" if utm.get("zone") else "N/A",
            "utm": utm,
        },
        "solar": solar,
        "local_time_hint": solar.get("utc"),
        "threat_score": threat,
        "threat_level": "ELEVATED" if threat >= 40 else "NOMINAL",
        "links": {
            "Google Satellite": gmaps,
            "Street View": street,
            "OpenStreetMap": osm,
            "SunCalc (Shadows)": suncalc,
            "Twitter (Nearby)": twitter,
            "Snapchat Map": snapchat,
            "Wikimapia": wikimapia,
            "PeakVisor Panorama": peakvisor,
        },
    }
