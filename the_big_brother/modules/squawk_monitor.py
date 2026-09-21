"""
THE BIG BROTHER // V7.0 TACTICAL FORENSIC SYSTEM
COMPANION POWER ENGINE: EMERGENCY SQUAWK MONITOR & MILITARY CALLSIGN RADAR (v7_squawk_monitor)
CLASSIFIED // AIRSPACE DEFENSE & STRATEGIC RECONNAISSANCE RADAR CORTEX

Monitors live global ADS-B airspace feeds for emergency transponder squawk codes
and filters strategic military / VIP callsigns:
- Squawk 7500 (Unlawful Interference / Aircraft Hijacking)
- Squawk 7600 (Radio Communication Loss / Nordo)
- Squawk 7700 (General In-Flight Emergency / Mayday)
- Strategic military callsign filter:
  (FORTE - Northrop Grumman RQ-4 Global Hawk, JAKE/HOMER - RC-135 Rivet Joint,
   RCH - Air Mobility Command C-17/C-5, LAGR - KC-135 Stratotanker, REDEYE - E-8 JSTARS)
"""

import asyncio
import json
import ssl
import urllib.request
import urllib.error
from typing import Dict, Any, List

HIGH_VALUE_CALLSIGNS = {
    "FORTE": "USAF RQ-4B Global Hawk (High-Altitude ISR Drone)",
    "JAKE": "USAF RC-135V/W Rivet Joint (SIGINT / Electronic Recon)",
    "HOMER": "USAF RC-135 Rivet Joint Reconnaissance",
    "LAGR": "USAF KC-135R Stratotanker (Aerial Refueling)",
    "RCH": "Air Mobility Command (Strategic Heavy Airlift C-17 / C-5)",
    "DUKE": "US Army C-12 Huron Reconnaissance",
    "REDEYE": "E-8C Joint STARS (Airborne Battle Management)",
    "VIPER": "Combat Air Patrol / Fast-Jet Escort",
    "AF1": "Air Force One (Presidential Transport)",
    "SAM": "Special Air Mission (Executive / Congressional Transport)"
}

EMERGENCY_SQUAWKS = {
    "7500": {"code": "7500", "meaning": "UNLAWFUL_INTERFERENCE // HIJACKING", "severity": "DEFCON_1_CRITICAL"},
    "7600": {"code": "7600", "meaning": "RADIO_COMMUNICATION_FAILURE // NORDO", "severity": "DEFCON_3_URGENT"},
    "7700": {"code": "7700", "meaning": "GENERAL_EMERGENCY // MAYDAY", "severity": "DEFCON_2_SEVERE"}
}

def _fetch_opensky(url: str):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "BigBrotherADSBSurveillance/7.0"})
    try:
        with urllib.request.urlopen(req, timeout=5.0, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception:
        return {}

async def monitor_squawks_and_military(lat: float = 40.7128, lon: float = -74.0060, radius_km: float = 300.0) -> Dict[str, Any]:
    url = f"https://opensky-network.org/api/states/all?lamin={lat-3.0}&lomin={lon-3.0}&lamax={lat+3.0}&lomax={lon+3.0}"
    
    emergency_flights = []
    military_flights = []
    total_tracked = 0
    
    data = await asyncio.to_thread(_fetch_opensky, url)
    states = data.get("states", []) or []
    total_tracked = len(states)
    
    for s in states:
        if not isinstance(s, list) or len(s) < 15:
            continue
        icao24 = s[0] or "N/A"
        callsign = (s[1] or "").strip().upper()
        country = s[2] or "Unknown"
        flt_lon = s[5]
        flt_lat = s[6]
        altitude_m = s[7]
        speed_mps = s[9]
        squawk = str(s[14]) if s[14] else ""
        
        # Check emergency squawk
        if squawk in EMERGENCY_SQUAWKS:
            emergency_flights.append({
                "icao24": icao24,
                "callsign": callsign or "NO_CALLSIGN",
                "origin_country": country,
                "squawk": squawk,
                "alert": EMERGENCY_SQUAWKS[squawk]["meaning"],
                "severity": EMERGENCY_SQUAWKS[squawk]["severity"],
                "position": {"lat": flt_lat, "lon": flt_lon},
                "altitude_feet": round(altitude_m * 3.28084) if altitude_m else 0,
                "speed_knots": round(speed_mps * 1.94384) if speed_mps else 0
            })

        # Check military callsign prefix
        for prefix, mission in HIGH_VALUE_CALLSIGNS.items():
            if callsign.startswith(prefix):
                military_flights.append({
                    "icao24": icao24,
                    "callsign": callsign,
                    "prefix": prefix,
                    "mission_profile": mission,
                    "origin_country": country,
                    "squawk": squawk or "STANDARD",
                    "position": {"lat": flt_lat, "lon": flt_lon},
                    "altitude_feet": round(altitude_m * 3.28084) if altitude_m else 0,
                    "speed_knots": round(speed_mps * 1.94384) if speed_mps else 0
                })
                break

    return {
        "status": "success",
        "monitoring_sector": {"center_lat": lat, "center_lon": lon, "radius_km": radius_km},
        "total_airborne_contacts": total_tracked,
        "emergency_squawk_alerts": emergency_flights,
        "military_recon_contacts": military_flights,
        "active_emergency_count": len(emergency_flights),
        "active_military_count": len(military_flights),
        "tactical_alert_status": "CRITICAL_AIRSPACE_EMERGENCY" if emergency_flights else ("SPECIAL_AIR_OPERATIONS_ACTIVE" if military_flights else "AIRSPACE_MONOMIAL_NOMINAL")
    }

async def monitor_squawks_async(lat: float = 40.7128, lon: float = -74.0060, radius: float = 300.0) -> Dict[str, Any]:
    return await monitor_squawks_and_military(lat, lon, radius)
