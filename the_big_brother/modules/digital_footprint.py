import phonenumbers
from phonenumbers import geocoder, carrier, timezone

import asyncio
import subprocess
import json
import dns.resolver

async def check_email_osint(email: str):
    """
    Checks email against holehe's list of sites.
    """
    out = []
    
    # Holehe allows checking specific modules or all.
    # For speed in this demo, we might want to limit or just run the standard set.
    # Using the importable check_email function from holehe
    
    # Note: holehe is primarily CLI based but has core functions.
    # We will wrap it. 
    
    # Since holehe might be slow, it's best run in a background task or thread.
    # Here is a simplified synchronous wrapper that we'll call asynchronously.
    
    from holehe.core import import_submodules
    modules = import_submodules("holehe.modules")
    
    results = []
    
    for module in modules:
        try:
            # Each module has a [module_name] class or function
            # This is a simplified integration based on holehe structure
             if hasattr(module, str(module.__name__).split(".")[-1]):
                check_func = getattr(module, str(module.__name__).split(".")[-1])
                # most holehe modules take email, client, out
                # We need to inspect holehe source for exact internal API or use CLI wrapper
                # For safety and stability, maybe shelling out is safer if internal API is unstable
                pass
        except Exception:
            pass

    # Alternative: Shell out to holehe CLI for stability if library use is complex
    # But let's try a direct approach if possible or fallback to a simulated "quick check" 
    # using known patterns if holehe is too heavy.
    
    # REVISION: To ensure this works without deep diving into holehe's internal non-public API,
    # let's use a subprocess to call 'holehe' if it's installed as a binary, 
    # OR better, since we installed it via pip, we can try to use its published entry points.
    
    # Let's implement a robust phone checker first as it is pure library call.
    return {"status": "scan_started", "email": email}

def get_phone_info(number_str: str):
    try:
        parsed_number = phonenumbers.parse(number_str, None)
        if not phonenumbers.is_valid_number(parsed_number):
            return {"error": "Invalid number"}
            
        # Get line type
        line_type_code = phonenumbers.number_type(parsed_number)
        line_type_map = {0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_OR_MOBILE", 3: "TOLL_FREE", 4: "PREMIUM_RATE", 
                         5: "SHARED_COST", 6: "VOIP", 7: "PERSONAL_NUMBER", 8: "PAGER", 9: "UAN", 10: "VOICEMAIL"}
        line_type = line_type_map.get(line_type_code, "UNKNOWN")

        # Get Timezones
        tzs = timezone.time_zones_for_number(parsed_number)
        
        return {
            "valid": True,
            "number": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "country": geocoder.description_for_number(parsed_number, "en"),
            "carrier": carrier.name_for_number(parsed_number, "en"),
            "line_type": line_type,
            "timezones": list(tzs)
        }
    except Exception as e:
        return {"error": str(e)}

# Re-implementing email check to be robust
import subprocess
import json

async def run_holehe(email: str):
    """
    Runs holehe as a subprocess. Also checks MX records.
    """
    results = {"email": email, "found_on": [], "mx_records": [], "valid_mx": False}

    # 1. MX Record Check
    try:
        domain = email.split('@')[-1]
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            results["mx_records"].append(str(mx.exchange))
        if results["mx_records"]:
            results["valid_mx"] = True
    except:
        pass

    # 2. Holehe Scan
    cmd = ["holehe", email, "--only-used", "--no-color"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        output = stdout.decode()
        
        sites = []
        for line in output.splitlines():
            if "[+]" in line:
                parts = line.split(" ")
                site = parts[-1]
                if site not in sites:
                    sites.append(site)
        results["found_on"] = sites
    except Exception as e:
        print(f"Holehe error: {e}")
        
    return results
