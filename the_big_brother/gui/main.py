from fastapi import FastAPI, BackgroundTasks, Response, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from uuid import uuid4
import os
import sys
import io
import csv
from typing import List, Optional

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from the_big_brother.scanner import scan, SitesInformation, QueryNotify, QueryStatus
from the_big_brother.image_grabber import fetch_images
from the_big_brother.reverse_search import ReverseImageSearcher
from the_big_brother.validators.headless_validator import HeadlessValidator
from the_big_brother.modules.digital_footprint import get_phone_info, run_holehe
from the_big_brother.modules.network_mapper import scan_target, generate_network_map
from the_big_brother.modules.dark_watch import search_dark_web
from the_big_brother.modules.crypto_analyzer import analyze_crypto
from the_big_brother.modules.ssl_sentinel import get_ssl_info
from the_big_brother.modules.exif_analyzer import get_exif_data
from the_big_brother.modules.dork_studio import generate_dorks
from the_big_brother.modules.geoint_spy import get_geoint_data
from the_big_brother.modules.flight_radar import get_flight_radar

# New V4 modules
from the_big_brother.modules.phantom_id import phantom_id_search
from the_big_brother.modules.breach_vault import breach_vault_search
from the_big_brother.modules.sigint_sweep import sigint_sweep
from the_big_brother.modules.shadow_map import shadow_map_analyze

class FootprintRequest(BaseModel):
    query: str
    type: str # "email" or "phone"

class NetworkRequest(BaseModel):
    domain: str

class DarkRequest(BaseModel):
    query: str

class CryptoRequest(BaseModel):
    address: str
    coin: str

class SSLRequest(BaseModel):
    domain: str

class ExifRequest(BaseModel):
    url: str

class DorkRequest(BaseModel):
    target: str
    domain: str = ""

class DeepSearchRequest(BaseModel):
    image_url: str

class GeointRequest(BaseModel):
    lat: str
    lon: str

class FlightRequest(BaseModel):
    lat: float
    lon: float
    radius: float = 100

class PhantomRequest(BaseModel):
    username: str

class BreachRequest(BaseModel):
    query: str
    type: str = "email"

class SigintRequest(BaseModel):
    query: str

class ShadowMapRequest(BaseModel):
    target: str

app = FastAPI(title="The Big Brother V4 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage
class JobState:
    def __init__(self):
        self.status = "running"
        self.results = []
        self.images = []
        self.stop_requested = False

jobs: dict[str, JobState] = {}

class ScanRequest(BaseModel):
    username: str

class NotifyQueue(QueryNotify):
    def __init__(self, job_id, jobs_dict):
        self.job_id = job_id
        self.jobs = jobs_dict
        super().__init__()

    def update(self, result):
        if self.jobs[self.job_id].stop_requested:
            raise InterruptedError("Stopped by user")

        if result.status == QueryStatus.CLAIMED:
            self.jobs[self.job_id].results.append({
                "site": result.site_name,
                "url": result.site_url_user,
                "status": "Found",
                "validation": "Pending",
                "context": result.context
            })
        elif result.status == QueryStatus.WAF:
             self.jobs[self.job_id].results.append({
                "site": result.site_name,
                "url": result.site_url_user,
                "status": "WAF Blocked",
                "validation": "Pending",
                "context": result.context
            })

    def start(self, message=None):
        pass
    
    def finish(self, message=None):
        pass

def run_scan_job(job_id: str, username: str):
    try:
        # Handle spaces: Check "John Doe" and "JohnDoe" (or replace space with nothing)
        usernames_to_check = [username]
        if " " in username:
            usernames_to_check.append(username.replace(" ", ""))

        # 1. Fetch Images (only for the primary username)
        try:
            images = fetch_images(username, limit=3)
            jobs[job_id].images = images
        except Exception as e:
            print(f"Image fetch error: {e}")

        # 2. Run Scan
        # Use local data.json file to ensure all sites are loaded
        # Get the path to the local data.json file
        data_file_path = os.path.join(os.path.dirname(__file__), "..", "resources", "data.json")
        sites_info = SitesInformation(data_file_path=data_file_path, honor_exclusions=False)
        site_data = {site.name: site.information for site in sites_info}
        
        notify = NotifyQueue(job_id, jobs)
        
        try:
            for u in usernames_to_check:
                if jobs[job_id].stop_requested: break
                scan(u, site_data, notify)
        except InterruptedError:
            jobs[job_id].status = "stopped"
            return

        if jobs[job_id].stop_requested:
             jobs[job_id].status = "stopped"
             return

        # 3. Validate
        jobs[job_id].status = "validating"
        validate_results(job_id)
        
        if jobs[job_id].stop_requested:
            jobs[job_id].status = "stopped"
        else:
            jobs[job_id].status = "completed"

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error in scan job: {e}")
        jobs[job_id].status = "error"

def validate_results(job_id: str):
    results = jobs[job_id].results
    if not results:
        return

    to_validate = [r for r in results if r["status"] == "Found"]
    
    if not to_validate:
        return

    try:
        with HeadlessValidator(headless=True) as validator:
            for res in to_validate:
                if jobs[job_id].stop_requested:
                    break
                
                res["validation"] = "Checking..."
                val_res = validator.validate(res["url"])
                
                if val_res.is_profile:
                    res["validation"] = "Verified"
                    res["page_title"] = val_res.title
                    res["snippet"] = val_res.visible_text[:200] if val_res.visible_text else ""
                else:
                    res["validation"] = "False Positive"
                    res["reason"] = val_res.reason
    except Exception as e:
        print(f"Validation error: {e}")

@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid4())
    jobs[job_id] = JobState()
    background_tasks.add_task(run_scan_job, job_id, request.username)
    return {"job_id": job_id}

@app.post("/api/stop/{job_id}")
async def stop_scan(job_id: str):
    if job_id in jobs:
        jobs[job_id].stop_requested = True
        return {"status": "stopping"}
    return {"error": "Job not found"}

@app.get("/api/results/{job_id}")
async def get_results(job_id: str):
    if job_id not in jobs:
        return {"error": "Job not found"}
    return {
        "status": jobs[job_id].status,
        "results": jobs[job_id].results,
        "images": jobs[job_id].images
    }

@app.get("/api/download/{job_id}")
async def download_report(job_id: str):
    if job_id not in jobs:
        return {"error": "Job not found"}
    
    results = jobs[job_id].results
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Site", "URL", "Status", "Validation", "Page Title"])
    
    for r in results:
        writer.writerow([
            r.get("site"), 
            r.get("url"), 
            r.get("status"), 
            r.get("validation"), 
            r.get("page_title", "")
        ])
    
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=report_{job_id}.csv"}
    )

@app.post("/api/deep-search")
async def deep_search(request: DeepSearchRequest):
    searcher = ReverseImageSearcher(headless=True)
    results = await searcher.search(request.image_url)
    return results

@app.post("/api/footprint")
async def footprint_scan(request: FootprintRequest):
    if request.type == "phone":
        return get_phone_info(request.query)
    elif request.type == "email":
        return await run_holehe(request.query)
    elif request.type == "breach":
        # Redirect to new breach vault
        return await breach_vault_search(request.query, "email")
    return {"error": "Invalid type"}

@app.post("/api/phantom")
async def phantom_scan(request: PhantomRequest):
    return await phantom_id_search(request.username)

@app.post("/api/breach")
async def breach_scan(request: BreachRequest):
    return await breach_vault_search(request.query, request.type)

@app.post("/api/sigint")
async def sigint_scan(request: SigintRequest):
    return await sigint_sweep(request.query)

@app.post("/api/shadowmap")
async def shadowmap_scan(request: ShadowMapRequest):
    return await shadow_map_analyze(request.target)

@app.post("/api/network/scan")
async def network_scan(request: NetworkRequest):
    data = await scan_target(request.domain)
    # Generate map HTML
    if "error" not in data:
         graph_html = generate_network_map(data)
         data["map_html"] = graph_html
    return data

@app.post("/api/dark/search")
async def dark_search(request: DarkRequest):
    return await search_dark_web(request.query)

@app.post("/api/crypto/analyze")
async def crypto_analyze(request: CryptoRequest):
    return analyze_crypto(request.address, request.coin)

@app.post("/api/ssl/scan")
async def ssl_scan(request: SSLRequest):
    return get_ssl_info(request.domain)

@app.post("/api/tools/exif")
async def tool_exif(request: ExifRequest):
    return get_exif_data(request.url)

# FILE UPLOAD for EXIF
@app.post("/api/tools/exif/upload")
async def tool_exif_upload(file: UploadFile = File(...)):
    # Read bytes
    content = await file.read()
    # Modify get_exif_data to accept bytes. 
    # Since we can't easily modify the module function signature without breaking it elsewhere or refactoring,
    # let's duplicate the logic here or update the module.
    # Actually, let's update the module logic in-place via a helper if possible.
    # But for now, let's pass a byte stream if the module supports it or just use PIL directly here.
    
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    from io import BytesIO
    
    results = {"source": file.filename, "basic": {}, "gps": {}, "error": None}
    try:
        image = Image.open(BytesIO(content))
        results["basic"]["format"] = image.format
        results["basic"]["mode"] = image.mode
        results["basic"]["size"] = f"{image.width}x{image.height}"
        
        exif_data = image._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                if isinstance(value, bytes):
                    try: value = value.decode()
                    except: value = str(value)

                if tag == "GPSInfo":
                    gps_data = {}
                    for t in value:
                        sub_tag = GPSTAGS.get(t, t)
                        gps_data[sub_tag] = str(value[t])
                    results["gps"] = gps_data
                else:
                    if len(str(value)) < 500:
                        results["basic"][tag] = value
    except Exception as e:
        results["error"] = str(e)
    return results

@app.post("/api/tools/dork")
async def tool_dork(request: DorkRequest):
    return generate_dorks(request.target, request.domain)

@app.post("/api/tools/geoint")
async def tool_geoint(request: GeointRequest):
    return get_geoint_data(request.lat, request.lon)

@app.post("/api/tools/flight")
async def tool_flight(request: FlightRequest):
    return get_flight_radar(request.lat, request.lon, request.radius)


# Serve static files for frontend
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
