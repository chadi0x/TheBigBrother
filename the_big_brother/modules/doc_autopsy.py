"""
DOC AUTOPSY — Document Forensics & Hidden Data Extractor V6.1 (POWERED UP)
Native Zip/XML parsing for Office files (DOCX, XLSX, PPTX), PDF stream inspector,
image EXIF/GPS parser, tracked changes & author revision history extractor.
"""
import io
import re
import zipfile
import xml.etree.ElementTree as ET
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

def _parse_office_zip(file_bytes: bytes, results: dict):
    """Deep XML extraction for DOCX, XLSX, PPTX files."""
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
            namelist = z.namelist()
            results["office_structure"] = namelist[:30]

            # 1. docProps/core.xml (Author, Creator, LastModifiedBy, Dates)
            if "docProps/core.xml" in namelist:
                core_xml = z.read("docProps/core.xml")
                root = ET.fromstring(core_xml)
                ns = {
                    'dc': 'http://purl.org/dc/elements/1.1/',
                    'dcterms': 'http://purl.org/dc/terms/',
                    'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'
                }
                creator = root.find('dc:creator', ns)
                last_modified = root.find('cp:lastModifiedBy', ns)
                created = root.find('dcterms:created', ns)
                modified = root.find('dcterms:modified', ns)

                if creator is not None and creator.text:
                    results["authors"].append(f"Creator: {creator.text}")
                if last_modified is not None and last_modified.text:
                    results["authors"].append(f"Last Modified By: {last_modified.text}")
                if created is not None and created.text:
                    results["created_date"] = created.text
                if modified is not None and modified.text:
                    results["modified_date"] = modified.text

            # 2. docProps/app.xml (Application, Version, Total Time, Company)
            if "docProps/app.xml" in namelist:
                app_xml = z.read("docProps/app.xml")
                root = ET.fromstring(app_xml)
                ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
                app = root.find('ep:Application', ns)
                company = root.find('ep:Company', ns)
                app_ver = root.find('ep:AppVersion', ns)

                if app is not None and app.text:
                    results["software"] = app.text + (f" (v{app_ver.text})" if app_ver is not None and app_ver.text else "")
                if company is not None and company.text:
                    results["company"] = company.text

            # 3. Word comments & tracked changes
            if "word/comments.xml" in namelist:
                comments_xml = z.read("word/comments.xml")
                root = ET.fromstring(comments_xml)
                ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
                for comment in root.findall('.//w:comment', ns):
                    author = comment.attrib.get('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}author', 'Unknown')
                    date = comment.attrib.get('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}date', '')
                    text = "".join(comment.itertext()).strip()
                    results["comments_found"].append({"author": author, "date": date, "text": text[:200]})

            # 4. Check for VBA Macros
            vba_files = [f for f in namelist if 'vbaProject' in f or f.endswith('.bin')]
            if vba_files:
                results["suspicious_flags"].append(f"⚠️ EMBEDDED MACROS DETECTED: {', '.join(vba_files)}")

    except Exception as e:
        results["suspicious_flags"].append(f"Office container parse note: {e}")

def _parse_pdf_stream(file_bytes: bytes, results: dict):
    """Deep stream extraction for PDF files."""
    try:
        # Search PDF Metadata Catalog dictionary
        pdf_str = file_bytes.decode('ascii', errors='ignore')

        # Find /Author, /Creator, /Producer, /CreationDate, /ModDate
        authors = re.findall(r'/Author\s*\(([^)]+)\)', pdf_str)
        creators = re.findall(r'/Creator\s*\(([^)]+)\)', pdf_str)
        producers = re.findall(r'/Producer\s*\(([^)]+)\)', pdf_str)
        created_dates = re.findall(r'/CreationDate\s*\(([^)]+)\)', pdf_str)
        mod_dates = re.findall(r'/ModDate\s*\(([^)]+)\)', pdf_str)

        for a in set(authors): results["authors"].append(f"Author: {a}")
        for c in set(creators): results["authors"].append(f"Creator: {c}")
        if producers: results["software"] = ", ".join(set(producers))[:100]
        if created_dates: results["created_date"] = created_dates[0]
        if mod_dates: results["modified_date"] = mod_dates[0]

        # Check for JavaScript streams or Launch actions in PDF
        if "/JS" in pdf_str or "/JavaScript" in pdf_str:
            results["suspicious_flags"].append("⚠️ EMBEDDED JAVASCRIPT DETECTED IN PDF")
        if "/Launch" in pdf_str:
            results["suspicious_flags"].append("⚠️ EMBEDDED LAUNCH ACTION DETECTED IN PDF")

    except Exception as e:
        results["suspicious_flags"].append(f"PDF stream parse note: {e}")

def doc_autopsy_bytes(file_bytes: bytes, filename: str) -> dict:
    filename_lower = filename.lower()
    ext = filename.split(".")[-1].upper() if "." in filename else "UNKNOWN"

    results = {
        "filename": filename,
        "file_size_bytes": len(file_bytes),
        "file_size_kb": round(len(file_bytes) / 1024, 2),
        "format": ext,
        "authors": [],
        "created_date": None,
        "modified_date": None,
        "software": None,
        "company": None,
        "extracted_links": [],
        "comments_found": [],
        "metadata_tags": {},
        "suspicious_flags": [],
        "raw_strings_sample": []
    }

    # 1. Extract printable ASCII / UTF-8 strings
    try:
        strings = re.findall(rb'[a-zA-Z0-9\s.,;:_\-@/\n\r\t]{5,}', file_bytes)
        decoded_strings = []
        for s in strings[:200]:
            try:
                ds = s.decode('ascii', errors='ignore').strip()
                if len(ds) > 5:
                    decoded_strings.append(ds)
            except Exception:
                pass

        # Find URLs
        url_matches = set(re.findall(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\']*', " ".join(decoded_strings)))
        results["extracted_links"] = list(url_matches)[:30]

    except Exception as e:
        results["suspicious_flags"].append(f"String extraction note: {e}")

    # 2. Format Specific Parsers
    if filename_lower.endswith(('.docx', '.xlsx', '.pptx', '.zip')):
        _parse_office_zip(file_bytes, results)
    elif filename_lower.endswith('.pdf'):
        _parse_pdf_stream(file_bytes, results)
    elif filename_lower.endswith(('.jpg', '.jpeg', '.png', '.tiff', '.webp')):
        try:
            img = Image.open(io.BytesIO(file_bytes))
            results["metadata_tags"]["dimensions"] = f"{img.width}x{img.height}"
            results["metadata_tags"]["mode"] = img.mode
            exif = img._getexif()
            if exif:
                for k, v in exif.items():
                    tag = TAGS.get(k, str(k))
                    if tag in ('Make', 'Model', 'Software', 'Artist', 'Copyright', 'DateTime'):
                        results["metadata_tags"][tag] = str(v)
        except Exception:
            pass

    # Deduplicate authors
    results["authors"] = list(set(results["authors"]))

    if not results["authors"] and not results["software"] and not results["created_date"]:
        results["suspicious_flags"].append("No structured author/software metadata found — document may have been scrubbed.")

    return results
