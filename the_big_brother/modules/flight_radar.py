import requests
import datetime

def get_flight_radar(lat: float, lon: float, radius_km: float = 100):
    """
    Fetches real-time flight data near the target coordinates.
    Uses OpenSky Network API (Free tier).
    """
    # 1 degree lat ~ 111km. 
    deg_diff = radius_km / 111.0
    
    lamin = lat - deg_diff
    lamax = lat + deg_diff
    lomin = lon - deg_diff
    lomax = lon + deg_diff
    
    url = f"https://opensky-network.org/api/states/all?lamin={lamin}&lomin={lomin}&lamax={lamax}&lomax={lomax}"
    
    results = {
        "location": {"lat": lat, "lon": lon},
        "flights": [],
        "count": 0,
        "error": None
    }
    
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            states = data.get("states", [])
            
            if states:
                for s in states[:20]: # Limit to 20 closest/first
                    # s indexes: 0=icao24, 1=callsign, 2=origin_country, 5=lon, 6=lat, 13=geo_altitude
                    results["flights"].append({
                        "icao": s[0],
                        "callsign": s[1].strip(),
                        "country": s[2],
                        "lat": s[6],
                        "lon": s[5],
                        "alt": s[13],
                        "velocity": s[9]
                    })
                results["count"] = len(results["flights"])
            else:
                 results["message"] = "No aircraft found in this sector."
        else:
             results["error"] = f"Radar Offline: {resp.status_code}"
             
    except Exception as e:
        results["error"] = str(e)
        
    return results
