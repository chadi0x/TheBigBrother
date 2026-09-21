"""
DOC AUTOPSY — Document Provenance & Hidden Data Extractor V7.0 (Zero-Mock Native)
Native OOXML/ZIP stream forensics (DOCX, XLSX, PPTX), deep PDF trailer/catalog parsing,
incremental update analysis, embedded VBA macro detection, and malicious /Launch or /JavaScript stream detection.
"""
from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional

def _parse_ooxml_container(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    provenance = {
        "authors": [],
        "last_modified_by": None,
        "created_date": None,
        "modified_date": None,
        "software": "Microsoft Office / OOXML",
        "company": None,
        "total_editing_time_minutes": 0,
        "revision_count": 1,
        "comments": [],
        "custom_properties": {},
        "vba_macros_detected": False,
        "suspicious_payloads": []
    }

    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
            names = z.namelist()

            # 1. docProps/core.xml
            if "docProps/core.xml" in names:
                core_xml = z.read("docProps/core.xml")
                root = ET.fromstring(core_xml)
                ns = {
                    'dc': 'http://purl.org/dc/elements/1.1/',
                    'dcterms': 'http://purl.org/dc/terms/',
                    'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'
                }
                creator = root.find('dc:creator', ns)
                last_mod = root.find('cp:lastModifiedBy', ns)
                created = root.find('dcterms:created', ns)
                modified = root.find('dcterms:modified', ns)
                revision = root.find('cp:revision', ns)

                if creator is not None and creator.text:
                    provenance["authors"].append(f"Creator: {creator.text.strip()}")
                if last_mod is not None and last_mod.text:
                    provenance["last_modified_by"] = last_mod.text.strip()
                    provenance["authors"].append(f"Last Modified By: {last_mod.text.strip()}")
                if created is not None and created.text:
                    provenance["created_date"] = created.text.strip()
                if modified is not None and modified.text:
                    provenance["modified_date"] = modified.text.strip()
                if revision is not None and revision.text:
                    try: provenance["revision_count"] = int(revision.text.strip())
                    except ValueError: pass

            # 2. docProps/app.xml
            if "docProps/app.xml" in names:
                app_xml = z.read("docProps/app.xml")
                root = ET.fromstring(app_xml)
                ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
                app = root.find('ep:Application', ns)
                app_ver = root.find('ep:AppVersion', ns)
                company = root.find('ep:Company', ns)
                total_time = root.find('ep:TotalTime', ns)

                if app is not None and app.text:
                    v_str = f" v{app_ver.text.strip()}" if app_ver is not None and app_ver.text else ""
                    provenance["software"] = f"{app.text.strip()}{v_str}"
                if company is not None and company.text:
                    provenance["company"] = company.text.strip()
                if total_time is not None and total_time.text:
                    try: provenance["total_editing_time_minutes"] = int(total_time.text.strip())
                    except ValueError: pass

            # 3. docProps/custom.xml
            if "docProps/custom.xml" in names:
                cust_xml = z.read("docProps/custom.xml")
                root = ET.fromstring(cust_xml)
                for prop in root:
                    p_name = prop.attrib.get("name")
                    p_val = "".join(prop.itertext()).strip()
                    if p_name:
                        provenance["custom_properties"][p_name] = p_val

            # 4. word/comments.xml
            if "word/comments.xml" in names:
                comm_xml = z.read("word/comments.xml")
                root = ET.fromstring(comm_xml)
                for comment in root.findall('.//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}comment'):
                    c_author = comment.attrib.get('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}author', 'Unknown')
                    c_date = comment.attrib.get('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}date', '')
                    c_text = "".join(comment.itertext()).strip()
                    provenance["comments"].append({"author": c_author, "date": c_date, "text": c_text[:160]})

            # 5. Check VBA Macros
            vba_items = [f for f in names if 'vbaProject' in f or f.endswith('.bin')]
            if vba_items:
                provenance["vba_macros_detected"] = True
                provenance["suspicious_payloads"].append(f"Embedded VBA Macro Container: {', '.join(vba_items)}")

    except Exception as e:
        provenance["suspicious_payloads"].append(f"OOXML stream parse note: {str(e)}")

    return provenance


def _parse_pdf_container(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    raw_str = file_bytes.decode('latin-1', errors='ignore')

    authors = re.findall(r'/Author\s*(?:\(([^)]*)\)|<([0-9a-fA-F]+)>)', raw_str)
    creators = re.findall(r'/Creator\s*(?:\(([^)]*)\)|<([0-9a-fA-F]+)>)', raw_str)
    producers = re.findall(r'/Producer\s*(?:\(([^)]*)\)|<([0-9a-fA-F]+)>)', raw_str)
    created_dates = re.findall(r'/CreationDate\s*\(([^)]*)\)', raw_str)
    mod_dates = re.findall(r'/ModDate\s*\(([^)]*)\)', raw_str)

    clean_authors = set()
    for a in authors:
        val = a[0] or a[1]
        if val and len(val.strip()) > 1:
            clean_authors.add(f"Author: {val.strip()}")
    for c in creators:
        val = c[0] or c[1]
        if val and len(val.strip()) > 1:
            clean_authors.add(f"Creator Tool: {val.strip()}")

    # Incremental update counts
    eof_count = raw_str.count('%%EOF')

    # Malicious Action inspection
    suspicious = []
    has_js = bool(re.search(r'/JavaScript|/JS\b', raw_str))
    if has_js:
        suspicious.append("Embedded JavaScript Stream (/JavaScript) detected inside PDF catalog")
    has_launch = bool(re.search(r'/Launch\b', raw_str))
    if has_launch:
        suspicious.append("Process Execution Action (/Launch) detected inside PDF dictionary")
    has_embedded = bool(re.search(r'/EmbeddedFiles\b', raw_str))
    if has_embedded:
        suspicious.append("Attached File Stream (/EmbeddedFiles) detected inside PDF payload")

    software_name = producers[0][0] if producers and producers[0][0] else "PDF Reference Toolchain"

    return {
        "authors": list(clean_authors),
        "last_modified_by": None,
        "created_date": created_dates[0] if created_dates else None,
        "modified_date": mod_dates[0] if mod_dates else None,
        "software": software_name,
        "company": None,
        "total_editing_time_minutes": 0,
        "revision_count": eof_count,
        "comments": [],
        "custom_properties": {"Incremental_Updates_EOF": eof_count},
        "vba_macros_detected": False,
        "suspicious_payloads": suspicious
    }


def doc_autopsy_analyze(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    file_size = len(file_bytes)
    fn_lower = filename.lower()

    if fn_lower.endswith((".docx", ".xlsx", ".pptx", ".odt")):
        doc_type = "OOXML / ZIP"
        provenance = _parse_ooxml_container(file_bytes, filename)
    elif fn_lower.endswith(".pdf") or file_bytes.startswith(b'%PDF'):
        doc_type = "Adobe PDF Stream"
        provenance = _parse_pdf_container(file_bytes, filename)
    else:
        doc_type = "Binary Archive / Generic"
        provenance = {
            "authors": [],
            "last_modified_by": None,
            "created_date": None,
            "modified_date": None,
            "software": "Generic Binary",
            "company": None,
            "total_editing_time_minutes": 0,
            "revision_count": 1,
            "comments": [],
            "custom_properties": {},
            "vba_macros_detected": False,
            "suspicious_payloads": []
        }

    threat_score = 10
    if provenance["vba_macros_detected"]:
        threat_score += 50
    if provenance["suspicious_payloads"]:
        threat_score += 35
    threat_score = min(100, threat_score)

    risk_tier = "CRITICAL_MALICIOUS_PAYLOAD" if threat_score >= 70 else ("ELEVATED_METADATA_DISCLOSURE" if threat_score >= 35 else "NOMINAL")

    return {
        "status": "success",
        "filename": filename,
        "file_size_bytes": file_size,
        "document_type": doc_type,
        "threat_score": threat_score,
        "risk_tier": risk_tier,
        "metadata_provenance": provenance,
        "summary": (
            f"Extracted provenance for {filename}: {len(provenance['authors'])} authors, "
            f"Software: {provenance['software']}. "
            f"{'CRITICAL: Embedded active macros/payloads flagged.' if provenance['suspicious_payloads'] else 'No malicious payload streams detected.'}"
        )
    }

# Backward compatibility alias for main.py route
doc_autopsy_bytes = doc_autopsy_analyze
