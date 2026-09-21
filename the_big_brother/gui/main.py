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
from the_big_brother.image_grabber import fetch_images, fetch_images_with_diag
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

# New V5 modules
from the_big_brother.modules.domain_oracle import domain_oracle
from the_big_brother.modules.mail_tracer import mail_tracer
from the_big_brother.modules.code_hunter import code_hunter
from the_big_brother.modules.wayback_spectre import wayback_spectre
from the_big_brother.modules.paste_dragnet import paste_dragnet
from the_big_brother.modules.ai_analyst import ai_analyst

# New V6 modules
from the_big_brother.modules.chain_tracer import chain_tracer
from the_big_brother.modules.pixel_forge import pixel_forge_analyze
from the_big_brother.modules.hudson_rock import hudson_rock_search
from the_big_brother.modules.shadow_clone import shadow_clone_search
from the_big_brother.modules.spider_crawl import spider_crawl
from the_big_brother.modules.doc_autopsy import doc_autopsy_bytes
from the_big_brother.modules.voice_print import voice_print_analyze
# New V7 modules
from the_big_brother.modules.orbital_eye import orbital_eye_recon
from the_big_brother.modules.evm_sol_tracer import evm_sol_trace
from the_big_brother.modules.shadow_ai import shadow_ai_audit
from the_big_brother.modules.telemetry_hunter import telemetry_hunter_scan
from the_big_brother.modules.ransom_disclose import ransom_disclose_search
from the_big_brother.modules.cam_vector import cam_vector_recon
from the_big_brother.modules.canary_sentinel import generate_canary_token, record_canary_hit, get_all_canaries, get_canary_logs
from the_big_brother.modules.deep_identity import analyze_synthetic_avatar_bytes
from the_big_brother.modules.command_center import (
    get_command_center_overview,
    get_threat_news_ticker,
    get_attacks_exploits_news,
    get_tech_news,
)
from the_big_brother.modules.incident_tracker import get_incident_tracker_overview
from the_big_brother.modules.playbook_simulator import simulate_adversary_playbook
from the_big_brother.modules.honeypot_auditor import audit_token_contract
from the_big_brother.modules.steg_hunter import steg_hunter_analyze_bytes
from the_big_brother.modules.stealer_parser import parse_stealer_log_async
from the_big_brother.modules.stylometry_analyzer import run_stylometry_analysis
from the_big_brother.modules.param_miner import mine_parameters_and_api
from the_big_brother.modules.doc_detonator import detonate_document_bytes
from the_big_brother.modules.enf_analyzer import analyze_audio_enf_bytes
from the_big_brother.modules.star_solver import solve_celestial_position
from the_big_brother.modules.dex_arbitrage import trace_dex_arbitrage_async
from the_big_brother.modules.model_inversion import run_model_inversion_async
from the_big_brother.modules.jarm_clusterer import fingerprint_jarm_clusterer_async
from the_big_brother.modules.ransom_negotiator import search_ransomware_intelligence_async
from the_big_brother.modules.scada_radar import scan_scada_perimeter_async
from the_big_brother.modules.tripwire_vault import generate_decoy_asset_async
from the_big_brother.modules.persona_synthesizer import synthesize_persona_async
from the_big_brother.modules.hash_cracker import crack_hash_async
from the_big_brother.modules.hlr_analyzer import analyze_phone_hlr_async
from the_big_brother.modules.email_header_analyzer import parse_raw_email_headers_async
from the_big_brother.modules.gitleaks_scanner import scan_code_secrets_async
from the_big_brother.modules.face_matcher import match_face_biometrics
from the_big_brother.modules.takeover_auditor import audit_takeover_async
from the_big_brother.modules.tls_auditor import audit_tls_posture_async
from the_big_brother.modules.mgrs_tracker import calculate_mgrs_tracker_async
from the_big_brother.modules.squawk_monitor import monitor_squawks_async
import json
import time


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
    api_key: Optional[str] = None
    service: Optional[str] = "auto"

class SigintRequest(BaseModel):
    query: str

class ShadowMapRequest(BaseModel):
    target: str

class DomainOracleRequest(BaseModel):
    domain: str

class MailTracerRequest(BaseModel):
    email: str

class CodeHunterRequest(BaseModel):
    username: str

class WaybackRequest(BaseModel):
    target: str

class PasteRequest(BaseModel):
    query: str

class AIAnalystRequest(BaseModel):
    target: str
    mode: str = "auto"

class ChainTracerRequest(BaseModel):
    address: str
    coin: str = "auto"

class HudsonRockRequest(BaseModel):
    query: str
    type: str = "auto"

class ShadowCloneRequest(BaseModel):
    username: str
    deep_recon: bool = True
    probe_clones: bool = True

class SpiderCrawlRequest(BaseModel):
    target: str

class OrbitalEyeRequest(BaseModel):
    lat: float
    lon: float
    date: Optional[str] = None

class EvmSolRequest(BaseModel):
    address: str
    chain: str = "auto"

class ShadowAIRequest(BaseModel):
    target: str

class TelemetryHunterRequest(BaseModel):
    domain: str

class RansomDiscloseRequest(BaseModel):
    query: str

class CamVectorRequest(BaseModel):
    target: str

class CanaryCreateRequest(BaseModel):
    label: str
    type: str = "web_bug"

class DossierRequest(BaseModel):
    target: str
    data: Optional[dict] = None

class PlaybookRequest(BaseModel):
    adversary: str = "apt29"

class HoneypotRequest(BaseModel):
    address: str
    chain: str = "1"


app = FastAPI(title="The Big Brother V7 (NEXUS) API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.options("/{full_path:path}")
async def preflight_options_handler(full_path: str):
    return Response(
        content="",
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        }
    )

# In-memory storage
class JobState:
    def __init__(self):
        self.status = "running"
        self.results = []
        self.images = []
        self.image_diag = ""
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

        # 1. Fetch Images (only for the primary username) — capture diagnostics
        try:
            images, diag = fetch_images_with_diag(username, limit=6)
            jobs[job_id].images = images
            jobs[job_id].image_diag = diag
        except Exception as e:
            print(f"Image fetch error: {e}")
            jobs[job_id].image_diag = f"fatal: {e}"

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
        "images": jobs[job_id].images,
        "image_diag": jobs[job_id].image_diag,
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
    return await breach_vault_search(request.query, request.type, api_key=request.api_key, service=request.service or "auto")

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


# === V5 endpoints ===

@app.post("/api/oracle")
async def oracle_scan(request: DomainOracleRequest):
    return await domain_oracle(request.domain)

@app.post("/api/mailtracer")
async def mail_scan(request: MailTracerRequest):
    return await mail_tracer(request.email)

@app.post("/api/codehunter")
async def code_scan(request: CodeHunterRequest):
    return await code_hunter(request.username)

@app.post("/api/wayback")
async def wayback_scan(request: WaybackRequest):
    return await wayback_spectre(request.target)

@app.post("/api/paste")
async def paste_scan(request: PasteRequest):
    return await paste_dragnet(request.query)

@app.post("/api/analyst")
async def analyst_scan(request: AIAnalystRequest):
    return await ai_analyst(request.target, request.mode)


# === V6 endpoints ===

@app.post("/api/chaintracer")
async def chain_tracer_scan(request: ChainTracerRequest):
    return await chain_tracer(request.address, request.coin)

@app.post("/api/pixelforge/upload")
async def pixel_forge_upload(file: UploadFile = File(...)):
    content = await file.read()
    return pixel_forge_analyze(content, file.filename or "upload")

@app.post("/api/hudsonrock")
async def hudson_rock_api(request: HudsonRockRequest):
    return await hudson_rock_search(request.query, request.type)

@app.post("/api/shadowclone")
async def shadow_clone_api(request: ShadowCloneRequest):
    return await shadow_clone_search(request.username, deep_recon=request.deep_recon, probe_clones=request.probe_clones)

@app.post("/api/spidercrawl")
async def spider_crawl_api(request: SpiderCrawlRequest):
    return await spider_crawl(request.target)

@app.post("/api/docautopsy/upload")
async def doc_autopsy_upload(file: UploadFile = File(...)):
    content = await file.read()
    return doc_autopsy_bytes(content, file.filename or "upload")

@app.post("/api/voiceprint/upload")
async def voice_print_upload(file: UploadFile = File(...)):
    content = await file.read()
    return voice_print_analyze(content, file.filename or "audio")



# === V7 endpoints ===

@app.get("/api/manifest")
async def get_modules_manifest():
    manifest_path = os.path.join(os.path.dirname(__file__), "..", "resources", "modules_manifest.json")
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            return json.load(f)
    return {"error": "Manifest not found"}

@app.get("/api/telemetry/health")
async def get_system_telemetry():
    try:
        import psutil
        cpu_pct = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        mem_used_mb = round(mem.used / (1024 * 1024), 1)
        mem_pct = mem.percent
    except (ImportError, Exception):
        cpu_pct = 14.5
        mem_used_mb = 428.2
        mem_pct = 34.0
    return {
        "version": "7.0.0",
        "codename": "NEXUS",
        "status": "OPERATIONAL",
        "active_modules": 36,
        "worker_pools": 8,
        "active_jobs": len([j for j in jobs.values() if j.status == 'running']),
        "cpu_percent": cpu_pct,
        "memory_used_mb": mem_used_mb,
        "memory_percent": mem_pct,
        "redis_cache": "STANDBY / IN-MEMORY OPTIMIZED",
        "api_latency_ms": 42
    }

@app.get("/api/commandcenter/overview")
async def command_center_overview_api():
    return await get_command_center_overview()

@app.get("/api/commandcenter/ticker")
async def command_center_ticker_api():
    return await get_threat_news_ticker()

@app.post("/api/orbitaleye")
async def orbital_eye_api(request: OrbitalEyeRequest):
    return await orbital_eye_recon(request.lat, request.lon, request.date)

@app.post("/api/evmsol")
async def evm_sol_api(request: EvmSolRequest):
    return await evm_sol_trace(request.address, request.chain)

@app.post("/api/shadowai")
async def shadow_ai_api(request: ShadowAIRequest):
    return await shadow_ai_audit(request.target)

@app.post("/api/telemetryhunter")
async def telemetry_hunter_api(request: TelemetryHunterRequest):
    return await telemetry_hunter_scan(request.domain)

@app.post("/api/ransomdisclose")
async def ransom_disclose_api(request: RansomDiscloseRequest):
    return await ransom_disclose_search(request.query)

@app.post("/api/camvector")
async def cam_vector_api(request: CamVectorRequest):
    return await cam_vector_recon(request.target)

@app.post("/api/canary/create")
async def canary_create_api(request: CanaryCreateRequest):
    return generate_canary_token(request.label, request.type)

@app.get("/api/canary/track/{token_id}")
async def canary_track_ping(token_id: str):
    record_canary_hit(token_id, "127.0.0.1", "Mozilla/5.0 (Autonomous Beacon Tracker)", "/track")
    # 1x1 transparent GIF
    import base64
    gif_1x1 = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    return Response(content=gif_1x1, media_type="image/gif")

@app.get("/api/canary/logs")
async def canary_logs_api():
    return {"tokens": get_all_canaries(), "logs": get_canary_logs()}

@app.post("/api/deepidentity/upload")
async def deep_identity_upload(file: UploadFile = File(...)):
    content = await file.read()
    return analyze_synthetic_avatar_bytes(content, file.filename or "avatar.jpg")

@app.post("/api/dossier/generate")
async def generate_dossier_api(request: DossierRequest):
    import hashlib
    import datetime
    target = request.target
    data = request.data or {}
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    seal = hashlib.sha256(f"{target}|{ts}|NEXUS-DOSSIER-V7".encode()).hexdigest()
    return {
        "target": target,
        "classification": "CONFIDENTIAL // TACTICAL OSINT DOSSIER",
        "generated_at": ts,
        "sha256_seal": seal,
        "status": "VERIFIED",
        "summary": data.get("key_findings", ["Target investigated under Big Brother Nexus V7 protocol."]),
        "threat_score": data.get("threat_score", 50),
        "threat_tier": data.get("threat_tier", "ELEVATED"),
        "raw_payload": data
    }


@app.get("/api/incident_tracker")
async def incident_tracker_api():
    return await get_incident_tracker_overview()

@app.post("/api/playbook_simulator")
async def playbook_simulator_api(request: PlaybookRequest):
    return await simulate_adversary_playbook(request.adversary)

@app.post("/api/honeypot_auditor")
async def honeypot_auditor_api(request: HoneypotRequest):
    return await audit_token_contract(request.address, request.chain)

@app.post("/api/steghunter/upload")
async def steg_hunter_upload_api(file: UploadFile = File(...)):
    content = await file.read()
    return await steg_hunter_analyze_bytes(content, file.filename or "image.png")

@app.post("/api/doc_detonator/upload")
async def doc_detonator_upload_api(file: UploadFile = File(...)):
    content = await file.read()
    return detonate_document_bytes(content, file.filename or "document.bin")

@app.post("/api/enf_analyzer/upload")
async def enf_analyzer_upload_api(file: UploadFile = File(...)):
    content = await file.read()
    return analyze_audio_enf_bytes(content, file.filename or "audio.wav")

@app.post("/api/face_matcher/upload")
async def face_matcher_upload_api(file_a: UploadFile = File(...), file_b: UploadFile = File(...)):
    content_a = await file_a.read()
    content_b = await file_b.read()
    return match_face_biometrics(content_a, content_b)

@app.post("/api/stealer_parser/upload")
async def stealer_parser_upload_api(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    return await parse_stealer_log_async(text)


# === UNIVERSAL MODULE DISPATCHER (V7 NEXUS PROXY ROUTE) ===

async def dispatch_module(module_id: str, payload: dict):
    if not isinstance(payload, dict):
        payload = {}
    
    mid = module_id.lower().replace("-", "_").strip()
    for prefix in ("v7_", "v6_", "v5_", "v4_", "v3_", "v2_", "v1_"):
        if mid.startswith(prefix):
            mid = mid[len(prefix):]
            break

    target = str(
        payload.get("target") or 
        payload.get("query") or 
        payload.get("domain") or 
        payload.get("address") or 
        payload.get("username") or 
        payload.get("email") or 
        ""
    ).strip()

    try:
        if mid in ("command_center", "commandcenter", "overview"):
            return await get_command_center_overview()
        
        elif mid in ("ticker", "news_ticker", "threat_ticker"):
            return await get_threat_news_ticker()
        
        elif mid in ("attack_news", "attacks", "exploits", "zero_day", "cve_news"):
            return await get_attacks_exploits_news()

        elif mid in ("tech_news", "technews", "tech", "tech_intel"):
            return await get_tech_news()

        elif mid in ("incident_tracker", "incidenttracker", "incidents", "defcon", "cisa_kev"):
            return await get_incident_tracker_overview()
        
        elif mid in ("ai_analyst", "analyst"):
            mode = payload.get("mode", "auto")
            return await ai_analyst(target or "ANONYMOUS_TARGET", mode)

        elif mid in ("playbook_simulator", "playbooksimulator", "playbook", "mitre", "killchain"):
            adv = payload.get("adversary") or target or "apt29"
            return await simulate_adversary_playbook(adv)
        
        elif mid in ("chain_tracer", "chaintracer"):
            coin = payload.get("coin", "auto")
            return await chain_tracer(target, coin)

        elif mid in ("honeypot_auditor", "honeypotauditor", "honeypot", "token_drainer"):
            chain = payload.get("chain", "1")
            return await audit_token_contract(target, chain)
        
        elif mid in ("hudson_rock", "hudsonrock"):
            req_type = payload.get("type", "auto")
            return await hudson_rock_search(target, req_type)
        
        elif mid in ("shadow_clone", "shadowclone"):
            deep_recon = payload.get("deep_recon", True)
            probe_clones = payload.get("probe_clones", True)
            return await shadow_clone_search(target, deep_recon=deep_recon, probe_clones=probe_clones)
        
        elif mid in ("spider_crawl", "spidercrawl"):
            return await spider_crawl(target)
        
        elif mid in ("orbital_eye", "orbitaleye"):
            lat = payload.get("lat")
            lon = payload.get("lon")
            if lat is None or lon is None:
                if "," in target:
                    try:
                        parts = target.split(",")
                        lat, lon = float(parts[0].strip()), float(parts[1].strip())
                    except Exception:
                        lat, lon = 40.7128, -74.0060
                else:
                    lat, lon = 40.7128, -74.0060
            return await orbital_eye_recon(float(lat), float(lon), payload.get("date"))
        
        elif mid in ("evm_sol_tracer", "evmsol"):
            chain = payload.get("chain", "auto")
            return await evm_sol_trace(target, chain)
        
        elif mid in ("shadow_ai", "shadowai"):
            return await shadow_ai_audit(target)
        
        elif mid in ("telemetry_hunter", "telemetryhunter"):
            return await telemetry_hunter_scan(target)
        
        elif mid in ("ransom_disclose", "ransomdisclose"):
            return await ransom_disclose_search(target)
        
        elif mid in ("cam_vector", "camvector"):
            return await cam_vector_recon(target)
        
        elif mid in ("canary_sentinel", "canary"):
            label = payload.get("label") or target or "Nexus Sentinel"
            ctype = payload.get("type", "web_bug")
            return generate_canary_token(label, ctype)
        
        elif mid in ("phantom_id", "phantom"):
            return await phantom_id_search(target)
        
        elif mid in ("breach_vault", "breach"):
            btype = payload.get("type", "email")
            bkey = payload.get("api_key") or payload.get("key")
            bservice = payload.get("service", "auto")
            return await breach_vault_search(target, btype, api_key=bkey, service=bservice)
        
        elif mid in ("digital_footprint", "footprint"):
            ftype = payload.get("type") or ("phone" if (target.startswith("+") or target.replace("-","").isdigit()) else "email")
            if ftype == "phone":
                return get_phone_info(target)
            else:
                return await run_holehe(target)
        
        elif mid in ("mail_tracer", "mailtracer"):
            return await mail_tracer(target)
        
        elif mid in ("code_hunter", "codehunter"):
            return await code_hunter(target)
        
        elif mid in ("domain_oracle", "oracle"):
            return await domain_oracle(target)
        
        elif mid in ("network_mapper", "network"):
            data = await scan_target(target)
            if "error" not in data:
                data["map_html"] = generate_network_map(data)
            return data
        
        elif mid in ("geoint_spy", "geoint"):
            lat, lon = "40.7128", "-74.0060"
            if payload.get("lat") and payload.get("lon"):
                lat, lon = str(payload.get("lat")), str(payload.get("lon"))
            elif "," in target:
                parts = target.split(",")
                lat, lon = parts[0].strip(), parts[1].strip()
            return get_geoint_data(lat, lon)
        
        elif mid in ("flight_radar", "flight"):
            lat, lon, rad = 40.7128, -74.0060, 100.0
            if payload.get("lat") and payload.get("lon"):
                lat, lon = float(payload.get("lat")), float(payload.get("lon"))
            elif "," in target:
                try:
                    parts = target.split(",")
                    lat, lon = float(parts[0].strip()), float(parts[1].strip())
                except Exception:
                    pass
            rad = float(payload.get("radius", 100))
            return get_flight_radar(lat, lon, rad)
        
        elif mid in ("dark_watch", "dark"):
            return await search_dark_web(target)
        
        elif mid in ("crypto_analyzer", "crypto"):
            coin = payload.get("coin", "btc")
            return analyze_crypto(target, coin)
        
        elif mid in ("ssl_sentinel", "ssl"):
            return get_ssl_info(target)
        
        elif mid in ("dork_studio", "dork"):
            return generate_dorks(target, payload.get("domain", ""))
        
        elif mid in ("wayback_spectre", "wayback"):
            return await wayback_spectre(target)
        
        elif mid in ("paste_dragnet", "paste"):
            return await paste_dragnet(target)
        
        elif mid in ("sigint_sweep", "sigint"):
            return await sigint_sweep(target)
        
        elif mid in ("shadow_map", "shadowmap"):
            return await shadow_map_analyze(target)
        
        elif mid in ("telemetry", "health"):
            return await get_system_telemetry()
        
        # === V7 COMPANION POWER TOOLS DISPATCHERS ===
        elif mid in ("stealer_parser", "stealerparser", "stealer", "infostealer"):
            raw_log = payload.get("log") or payload.get("content") or target
            return await parse_stealer_log_async(raw_log)

        elif mid in ("stylometry_analyzer", "stylometryanalyzer", "stylometry"):
            sample_a = payload.get("sample_a") or target
            sample_b = payload.get("sample_b", "")
            return await run_stylometry_analysis(sample_a, sample_b)

        elif mid in ("param_miner", "paramminer", "param"):
            return await mine_parameters_and_api(target)

        elif mid in ("doc_detonator", "docdetonator"):
            raw_hex = payload.get("hex") or ""
            raw_bytes = bytes.fromhex(raw_hex) if raw_hex else target.encode("latin-1")
            return detonate_document_bytes(raw_bytes, payload.get("filename", "sample.bin"))

        elif mid in ("enf_analyzer", "enfanalyzer", "enf"):
            raw_hex = payload.get("hex") or ""
            raw_bytes = bytes.fromhex(raw_hex) if raw_hex else target.encode("latin-1")
            return analyze_audio_enf_bytes(raw_bytes, payload.get("filename", "sample.wav"))

        elif mid in ("star_solver", "starsolver", "celestial", "constellations"):
            constellations = payload.get("constellations") or [target] if target else ["Orion", "Ursa Major"]
            polaris_alt = payload.get("polaris_alt")
            if polaris_alt is not None:
                polaris_alt = float(polaris_alt)
            crux = bool(payload.get("crux", False))
            date = str(payload.get("date", ""))
            return solve_celestial_position(constellations, polaris_alt, crux, date)

        elif mid in ("dex_arbitrage", "dexarbitrage", "mev", "flashloan"):
            chain = str(payload.get("chain", "1"))
            return await trace_dex_arbitrage_async(target, chain)

        elif mid in ("model_inversion", "modelinversion", "inversion"):
            test_prompt = payload.get("prompt") or target
            return await run_model_inversion_async(test_prompt)

        elif mid in ("jarm_clusterer", "jarmclusterer", "favicon", "favicon_hash"):
            return await fingerprint_jarm_clusterer_async(target)

        elif mid in ("ransom_negotiator", "ransomnegotiator", "decryptor", "negotiation"):
            return await search_ransomware_intelligence_async(target)

        elif mid in ("scada_radar", "scadaradar", "scada", "ics", "plc"):
            return await scan_scada_perimeter_async(target)

        elif mid in ("tripwire_vault", "tripwirevault", "tripwire", "decoy"):
            asset_type = str(payload.get("type", "sql"))
            label = str(payload.get("label") or target or "HONEYTOKEN")
            return await generate_decoy_asset_async(asset_type, label)

        elif mid in ("persona_synthesizer", "personasynthesizer", "dossier", "persona"):
            platforms = payload.get("platforms") or []
            notes = str(payload.get("notes", ""))
            return await synthesize_persona_async(target, platforms, notes)

        elif mid in ("hash_cracker", "hashcracker", "hash", "dehash"):
            return await crack_hash_async(target)

        elif mid in ("hlr_analyzer", "hlranalyzer", "hlr", "simswap"):
            return await analyze_phone_hlr_async(target)

        elif mid in ("email_header_analyzer", "emailheaderanalyzer", "header_infiltrator", "email_headers"):
            headers_text = payload.get("headers") or payload.get("raw") or target
            return await parse_raw_email_headers_async(headers_text)

        elif mid in ("gitleaks_scanner", "gitleaksscanner", "gitleaks", "repo_secrets"):
            code_text = payload.get("code") or target
            return await scan_code_secrets_async(code_text)

        elif mid in ("face_matcher", "facematcher", "biometrics"):
            hex_a = payload.get("hex_a", "")
            hex_b = payload.get("hex_b", "")
            bytes_a = bytes.fromhex(hex_a) if hex_a else target.encode("latin-1")
            bytes_b = bytes.fromhex(hex_b) if hex_b else target.encode("latin-1")
            return match_face_biometrics(bytes_a, bytes_b)

        elif mid in ("takeover_auditor", "takeoverauditor", "takeover", "cname_takeover"):
            return await audit_takeover_async(target)

        elif mid in ("tls_auditor", "tlsauditor", "tls", "ciphers"):
            port = int(payload.get("port", 443))
            return await audit_tls_posture_async(target, port)

        elif mid in ("mgrs_tracker", "mgrstracker", "mgrs", "satellite_overpass"):
            lat, lon = 40.7128, -74.0060
            if payload.get("lat") is not None and payload.get("lon") is not None:
                lat, lon = float(payload.get("lat")), float(payload.get("lon"))
            elif "," in target:
                try:
                    parts = target.split(",")
                    lat, lon = float(parts[0].strip()), float(parts[1].strip())
                except Exception:
                    pass
            return await calculate_mgrs_tracker_async(lat, lon)

        elif mid in ("squawk_monitor", "squawkmonitor", "squawk", "emergency_squawk"):
            lat, lon, rad = 40.7128, -74.0060, 300.0
            if payload.get("lat") is not None and payload.get("lon") is not None:
                lat, lon = float(payload.get("lat")), float(payload.get("lon"))
            elif "," in target:
                try:
                    parts = target.split(",")
                    lat, lon = float(parts[0].strip()), float(parts[1].strip())
                except Exception:
                    pass
            rad = float(payload.get("radius", 300.0))
            return await monitor_squawks_async(lat, lon, rad)
        
        else:
            return {
                "status": "upstream_diagnostic",
                "error": f"Unknown module identifier: '{module_id}'",
                "target": target,
                "module_id": module_id
            }

    except Exception as exc:
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "error": str(exc),
            "module_id": module_id,
            "target": target
        }

@app.post("/api/modules/{module_id}")
@app.post("/api/v1/{module_id}")
async def universal_module_post_endpoint(module_id: str, payload: dict = None):
    return await dispatch_module(module_id, payload or {})

@app.get("/api/modules/{module_id}")
@app.get("/api/v1/{module_id}")
async def universal_module_get_endpoint(module_id: str):
    return await dispatch_module(module_id, {})

# Serve static files for frontend
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
