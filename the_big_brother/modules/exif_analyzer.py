from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import requests
from io import BytesIO

def get_exif_data(image_source: str, is_url: bool = True):
    """
    Extracts EXIF data from an image URL or local file (simulated via bytes).
    """
    results = {
        "source": image_source,
        "basic": {},
        "gps": {},
        "error": None
    }
    
    try:
        image = None
        if is_url:
            resp = requests.get(image_source, timeout=10)
            if resp.status_code == 200:
                image = Image.open(BytesIO(resp.content))
            else:
                 return {"error": f"Failed to download image: {resp.status_code}"}
        else:
             # For now we only support URL in this quick implementation
             return {"error": "Local file upload not implemented in this version"}

        if not image:
             return {"error": "Could not open image"}

        # Basic Info
        results["basic"]["format"] = image.format
        results["basic"]["mode"] = image.mode
        results["basic"]["size"] = f"{image.width}x{image.height}"
        
        exif_data = image._getexif()
        if not exif_data:
            return results # No exif

        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            
            # Decode bytes if needed
            if isinstance(value, bytes):
                try:
                    value = value.decode()
                except:
                    value = str(value)

            if tag == "GPSInfo":
                gps_data = {}
                for t in value:
                    sub_tag = GPSTAGS.get(t, t)
                    gps_data[sub_tag] = str(value[t])
                results["gps"] = gps_data
            else:
                # Filter out very long binary data (like maker notes)
                if len(str(value)) < 500:
                    results["basic"][tag] = value

    except Exception as e:
        results["error"] = str(e)
        
    return results
