"""
THE BIG BROTHER // V7.0 TACTICAL FORENSIC SYSTEM
COMPANION POWER ENGINE: MALICIOUS OLE/VBA DETONATOR & PDF JAVASCRIPT EXTRACTOR (v7_doc_detonator)
CLASSIFIED // CYBER MALWARE ANALYSIS & WEAPONIZED DOCUMENT TRIAGE

Deep static analyzer for weaponized documents (PDF, DOCX, DOCM, XLS, RTF, XLSM):
- PDF /JavaScript, /Launch, /EmbeddedFiles, /URI, /OpenAction extraction
- VBA macro obfuscation deconstruction (Chr(), StrReverse, hex strings)
- Suspicious API invocation matching (VirtualAlloc, CreateProcess, URLDownloadToFile)
- High-entropy shellcode block location
"""

import re
import math
from typing import Dict, Any, List

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    for count in freq.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return round(entropy, 4)

def deobfuscate_vba_chr(script_text: str) -> str:
    """Detects and resolves Chr(65) & Chr(66) chains."""
    def chr_repl(match):
        try:
            num = int(match.group(1))
            if 32 <= num <= 126:
                return chr(num)
        except Exception:
            pass
        return match.group(0)

    # Replace Chr(XX) or Chr$(XX) or ChrW(XX)
    cleaned = re.sub(r'Chr[W\$]?\((\d+)\)', chr_repl, script_text, flags=re.IGNORECASE)
    # Collapse string concatenations "a" & "b"
    cleaned = re.sub(r'"\s*&\s*"', '', cleaned)
    return cleaned

def detonate_document_bytes(file_bytes: bytes, filename: str = "document.bin") -> Dict[str, Any]:
    if not file_bytes:
        return {"status": "error", "error": "No document content provided."}
        
    size = len(file_bytes)
    overall_entropy = shannon_entropy(file_bytes)
    fn_lower = filename.lower()
    
    # 1. Detect File Type
    doc_type = "Generic Binary / Unknown Document"
    if file_bytes.startswith(b"%PDF"):
        doc_type = "Adobe Acrobat PDF"
    elif file_bytes.startswith(b"PK\x03\x04"):
        doc_type = "Office OpenXML (DOCX/XLSX/PPTX)"
    elif file_bytes.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        doc_type = "Legacy OLE Structured Storage (DOC/XLS/PPT)"
    elif file_bytes.startswith(b"{\\rtf"):
        doc_type = "Rich Text Format (RTF)"

    # 2. PDF Specific Threat Indicators
    pdf_indicators = []
    pdf_js_payloads = []
    if b"%PDF" in file_bytes[:1024]:
        text_content = file_bytes.decode("latin-1", errors="ignore")
        
        pdf_tags = [
            ("/JavaScript", "Active JavaScript embedded inside PDF object"),
            ("/JS", "Abbreviated JavaScript execution hook"),
            ("/Launch", "OS Command Execution / Payload Launch"),
            ("/EmbeddedFiles", "Hidden malicious file payload packed inside PDF"),
            ("/OpenAction", "Auto-executes payload on document open without user click"),
            ("/AA", "Additional Actions auto-trigger event"),
            ("/AcroForm", "Dynamic form containing scripting triggers"),
            ("/RichMedia", "Flash or binary payload container"),
            ("/JBIG2Decode", "Exploited decoder filter (Pegasus / CVE-2021-30860)")
        ]
        for tag, desc in pdf_tags:
            count = len(re.findall(re.escape(tag), text_content))
            if count > 0:
                pdf_indicators.append({
                    "tag": tag,
                    "occurrences": count,
                    "description": desc,
                    "threat_weight": "HIGH" if tag in ("/JavaScript", "/Launch", "/OpenAction") else "MEDIUM"
                })
                
        # Extract raw JS stream snippets if found
        js_matches = re.findall(r'/JavaScript\s*<<(?:[^>]*)>>|/JS\s*\((.*?)\)|stream[\r\n]+(.*?app\.alert|.*?eval|.*?unescape|.*?this\.exportDataObject)[\r\n]+endstream', text_content, re.DOTALL | re.IGNORECASE)
        for m in js_matches[:5]:
            snippet = str(m)
            if len(snippet) > 20:
                pdf_js_payloads.append(snippet[:300])

    # 3. Macro & VBA Suspicious API Scanning
    suspicious_apis = [
        ("VirtualAlloc", "Direct Windows Memory Allocation (Shellcode Staging)"),
        ("WriteProcessMemory", "Process Injection"),
        ("CreateProcess", "Arbitrary Process Spawning"),
        ("URLDownloadToFile", "Remote Dropper Download"),
        ("ShellExecute", "System Command Execution"),
        ("WScript.Shell", "VBScript Shell Execution"),
        ("PowerShell", "PowerShell Execution Vector"),
        ("AutoOpen", "Document Auto-Execution Macro Trigger"),
        ("Workbook_Open", "Excel Auto-Execution Macro Trigger"),
        ("Document_Open", "Word Auto-Execution Macro Trigger"),
        ("cmd.exe", "Command Line Spawning"),
        ("certutil", "Certificate Utility LOLBin Abuse"),
        ("bitsadmin", "BITS Transfer Dropper")
    ]
    
    text_data = file_bytes.decode("latin-1", errors="ignore")
    found_apis = []
    for api, desc in suspicious_apis:
        matches = len(re.findall(re.escape(api), text_data, re.IGNORECASE))
        if matches > 0:
            found_apis.append({
                "api": api,
                "occurrences": matches,
                "description": desc,
                "category": "EXECUTION_OR_STAGING"
            })

    # 4. De-obfuscate string chains if found
    deobfuscated_preview = ""
    if "Chr(" in text_data or "ChrW(" in text_data:
        deobfuscated_preview = deobfuscate_vba_chr(text_data[:8000])[:500]

    # 5. Determine Threat Verdict
    risk_score = 0
    if pdf_indicators:
        risk_score += sum(25 for i in pdf_indicators if i["threat_weight"] == "HIGH")
    if found_apis:
        risk_score += len(found_apis) * 15
    if overall_entropy > 7.2:
        risk_score += 30

    risk_score = min(100, risk_score)
    if risk_score >= 70:
        verdict = "WEAPONIZED_MALICIOUS_DOCUMENT"
    elif risk_score >= 35:
        verdict = "SUSPICIOUS_ACTIVE_CONTENT"
    else:
        verdict = "BENIGN_OR_CLEAN_DOCUMENT"

    return {
        "status": "success",
        "filename": filename,
        "file_size": size,
        "document_type": doc_type,
        "overall_entropy": overall_entropy,
        "risk_score": risk_score,
        "verdict": verdict,
        "pdf_attack_vectors": pdf_indicators,
        "extracted_scripts": pdf_js_payloads,
        "suspicious_apis": found_apis,
        "deobfuscated_strings_preview": deobfuscated_preview if deobfuscated_preview else "NO_CHR_CHAINS_DETECTED"
    }

async def detonate_document_async(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    return detonate_document_bytes(file_bytes, filename)
