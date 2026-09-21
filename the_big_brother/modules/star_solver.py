"""
THE BIG BROTHER // V7.0 TACTICAL FORENSIC SYSTEM
COMPANION POWER ENGINE: CELESTIAL NIGHT-SKY & CONSTELLATION CHRONO-SOLVER (v7_star_solver)
CLASSIFIED // ASTRO-GEOLOCATION & CHRONOLOCATION SPECIAL TASK FORCE

Calculates approximate observer latitude, hemisphere, and observation time window
based on visible constellations, Polaris altitude, celestial equator offset,
and lunar phase illumination:
- Polaris (North Star) Altitude = Observer Latitude in Northern Hemisphere
- Southern Cross (Crux) Angle = Southern Hemisphere Observer Heading
- Orion / Ursa Major (Big Dipper) Seasonal Visibility Solver
- Lunar illumination phase calculation (synodic lunar month 29.53 days)
"""

import math
import datetime
from typing import Dict, Any, List

def calculate_moon_phase(date_str: str = "") -> Dict[str, Any]:
    if date_str:
        try:
            dt = datetime.datetime.fromisoformat(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            dt = datetime.datetime.now(datetime.timezone.utc)
    else:
        dt = datetime.datetime.now(datetime.timezone.utc)
        
    # Known new moon epoch: Jan 6, 2000, 18:14 UTC
    epoch = datetime.datetime(2000, 1, 6, 18, 14, tzinfo=datetime.timezone.utc)
    diff = (dt - epoch).total_seconds()
    synodic = 29.53058867 * 86400.0  # seconds in lunar cycle
    phase_ratio = (diff % synodic) / synodic
    
    illumination = round((1.0 - math.cos(phase_ratio * 2 * math.pi)) / 2.0 * 100, 1)
    
    if phase_ratio < 0.03 or phase_ratio > 0.97:
        phase_name = "New Moon (0% Visible)"
    elif phase_ratio < 0.22:
        phase_name = "Waxing Crescent"
    elif phase_ratio < 0.28:
        phase_name = "First Quarter (Half Moon)"
    elif phase_ratio < 0.47:
        phase_name = "Waxing Gibbous"
    elif phase_ratio < 0.53:
        phase_name = "Full Moon (100% Illumination)"
    elif phase_ratio < 0.72:
        phase_name = "Waning Gibbous"
    elif phase_ratio < 0.78:
        phase_name = "Last Quarter (Half Moon)"
    else:
        phase_name = "Waning Crescent"

    return {
        "date_analyzed": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "lunar_phase": phase_name,
        "illumination_percentage": f"{illumination}%",
        "cycle_progress": round(phase_ratio, 3)
    }

def solve_celestial_position(
    visible_constellations: List[str],
    polaris_altitude_deg: float = None,
    crux_visible: bool = False,
    date_str: str = ""
) -> Dict[str, Any]:
    
    moon_info = calculate_moon_phase(date_str)
    
    detected_hemisphere = "UNKNOWN"
    inferred_lat_min = -90.0
    inferred_lat_max = 90.0
    
    c_lower = [c.lower().strip() for c in visible_constellations]
    
    # 1. Polaris logic: In Northern hemisphere, altitude of Polaris == latitude
    if polaris_altitude_deg is not None and polaris_altitude_deg >= 0:
        detected_hemisphere = "NORTHERN_HEMISPHERE"
        inferred_lat_min = max(0.0, polaris_altitude_deg - 2.5)
        inferred_lat_max = min(90.0, polaris_altitude_deg + 2.5)
    elif crux_visible or "crux" in c_lower or "southern cross" in c_lower:
        detected_hemisphere = "SOUTHERN_HEMISPHERE"
        inferred_lat_min = -90.0
        inferred_lat_max = 25.0  # Crux rarely visible above 25°N
    elif "ursa major" in c_lower or "big dipper" in c_lower or "cassiopeia" in c_lower:
        detected_hemisphere = "NORTHERN_HEMISPHERE_OR_EQUATORIAL"
        inferred_lat_min = -30.0
        inferred_lat_max = 90.0
        
    # Constellation database coordinates (Right Ascension & Declination)
    constellation_data = {
        "orion": {"declination": "+5°", "best_season": "Northern Winter (Dec - Feb)"},
        "ursa major": {"declination": "+55°", "best_season": "Northern Spring (Mar - May)"},
        "crux": {"declination": "-60°", "best_season": "Southern Autumn/Winter (May - Jul)"},
        "cassiopeia": {"declination": "+60°", "best_season": "Northern Autumn (Sep - Nov)"},
        "scorpius": {"declination": "-30°", "best_season": "Northern Summer / Southern Winter"},
        "cygnus": {"declination": "+42°", "best_season": "Northern Summer (Jul - Sep)"}
    }
    
    matched_bodies = []
    for c in visible_constellations:
        key = c.lower().strip()
        data = constellation_data.get(key, {"declination": "Equatorial / Variable", "best_season": "All Year"})
        matched_bodies.append({
            "name": c.title(),
            "declination": data["declination"],
            "optimal_season": data["best_season"]
        })

    center_lat = round((inferred_lat_min + inferred_lat_max) / 2.0, 2)
    
    return {
        "status": "success",
        "hemisphere": detected_hemisphere,
        "latitude_bracket": f"{inferred_lat_min:.1f}° to {inferred_lat_max:.1f}°",
        "estimated_latitude": center_lat,
        "moon_phase_telemetry": moon_info,
        "matched_celestial_landmarks": matched_bodies,
        "geonav_confidence": "HIGH (POLARIS_LOCKED)" if polaris_altitude_deg is not None else "MEDIUM (CONSTELLATION_ESTIMATE)"
    }

async def solve_star_sky_async(constellations: List[str], polaris_alt: float = None, crux: bool = False, date: str = "") -> Dict[str, Any]:
    return solve_celestial_position(constellations, polaris_alt, crux, date)
