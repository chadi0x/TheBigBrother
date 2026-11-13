"""
DORK STUDIO // VX EXPANDED SEARCH-OPERATOR FOUNDRY

Generates high-signal, platform-specific dorks with severity, category and a
ready-to-click URL. Kept backwards-compatible with the legacy shape:
    {platform: [{title, query}, ...]}
while adding severity/category/rationale/url fields to every item.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List


def _item(title: str, query: str, category: str, severity: str, url: str = "", rationale: str = "") -> Dict[str, str]:
    out = {
        "title": title,
        "query": query,
        "category": category,
        "severity": severity,
        "url": url,
    }
    if rationale:
        out["rationale"] = rationale
    return out


def _g(query: str) -> str:
    return "https://www.google.com/search?q=" + urllib.parse.quote(query)


def _gh(query: str) -> str:
    return "https://github.com/search?q=" + urllib.parse.quote(query) + "&type=code"


def generate_dorks(target: str, domain: str = "") -> Dict[str, Any]:
    """
    Build an operator matrix for a brand/person/domain. No network calls.
    `target` is the organization/person; `domain` narrows site: queries.
    """
    target = (target or "").strip()
    domain = re.sub(r"^[a-z]+://", "", (domain or "").strip(), flags=re.I).split("/")[0].split(":")[0]
    site = f"site:{domain} " if domain else ""
    dorks: Dict[str, List[Dict[str, str]]] = {
        "google": [],
        "github": [],
        "shodan": [],
        "censys": [],
        "fofa": [],
        "virustotal": [],
        "pastebin": [],
        "linkedin": [],
    }

    def G(title, q, cat, sev, why=""):
        dorks["google"].append(_item(title, q, cat, sev, _g(q), why))

    # --- Exposure / secrets ---
    G("Exposed .git directories", f'{site}intitle:"index of" ".git"', "source-control", "critical", "Browsable Git metadata can expose full source history and secrets.")
    G("Environment / config files", f"{site}ext:env | ext:ini | ext:conf | ext:cfg | ext:yml | ext:yaml", "secrets", "critical", "Configuration files frequently carry credentials and internal hostnames.")
    G("Backup / database dumps", f"{site}ext:sql | ext:bak | ext:backup | ext:dump | ext:old | ext:zip | ext:tar.gz", "backup", "critical", "Dumps and archives are high-value exfiltration targets.")
    G("Private keys and certificates", f'{site}(ext:pem | ext:key | ext:p12 | ext:pfx | ext:jks) "BEGIN"', "secrets", "critical", "Private key material must never be web-accessible.")
    G("Cloud credential strings", f'{site}("AKIA" | "aws_secret_access_key" | "xoxb-" | "ghp_" | "AIza")', "secrets", "critical", "Provider-specific token prefixes indicate leaked credentials.")
    G("Log files", f"{site}ext:log | ext:txt intext:error intext:stack", "diagnostics", "high", "Logs reveal paths, versions and sometimes session tokens.")

    # --- Application surfaces ---
    G("Exposed admin / login panels", f'{site}(inurl:admin | inurl:login | inurl:portal | inurl:dashboard) intitle:"login"', "admin-panel", "high", "Internet-facing admin portals increase credential-stuffing risk.")
    G("Directory listings", f'{site}intitle:"index of" "Parent Directory"', "directory-listing", "medium", "Open indexes leak file inventories and backups.")
    G("Install / setup pages", f"{site}(inurl:install | inurl:setup | inurl:readme | inurl:license) ext:php", "misconfiguration", "medium", "Unfinished setup flows can allow reconfiguration or admin creation.")
    G("Debug / diagnostics", f"{site}(inurl:debug | inurl:test | inurl:trace | inurl:phpinfo) ", "diagnostics", "medium", "Debug endpoints disclose environment details.")
    G("API documentation", f"{site}(inurl:swagger | inurl:openapi | inurl:api-docs | inurl:graphql)", "api", "medium", "Public API schemas reveal hidden operations and parameters.")
    G("Error pages with stack traces", f'{site}("Fatal error" | "Warning: mysql" | "Traceback (most recent call last)")', "information-disclosure", "high", "Stack traces disclose framework, paths and query structure.")

    # --- Injection / parameter hunting ---
    G("SQL injection candidates", f"{site}inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir=", "injection", "high", "Parameterized endpoints are the first place to test for SQLi.")
    G("LFI / path traversal candidates", f"{site}(inurl:include= | inurl:page= | inurl:file= | inurl:path= | inurl:doc=) (ext:php | ext:asp | ext:jsp)", "injection", "high", "File-inclusion parameters can expose arbitrary files.")
    G("Open redirect candidates", f'{site}(inurl:redirect= | inurl:url= | inurl:next= | inurl:return= | inurl:continue=)', "open-redirect", "medium", "Unvalidated redirect targets enable phishing and OAuth token theft.")
    G("Reflected parameter candidates", f'{site}inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword=', "xss", "medium", "Reflection points are prime XSS/HTML-injection candidates.")

    # --- Brand / infrastructure footprint ---
    G("Third-party code repositories", f'site:github.com "{target}"', "code-leak", "medium", "Employee repositories often contain internal references and keys.")
    G("Pastebin mentions", f'site:pastebin.com "{target}"', "leak", "high", "Pastes frequently contain dumped credentials and internal documents.")
    G("Document leaks", f'{site}ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx "{target}"', "document-leak", "medium", "Indexed documents can expose internal data and metadata.")
    G("Subdomains via Google", f"{site}", "asset-discovery", "low", "Enumerate indexed hosts outside the primary domain.")
    G("Employee emails", f'{site}("@' + (domain or "target.com") + '")', "identity", "low", "Harvest public employee addresses for phishing simulations.")

    # --- GitHub ---
    def GH(title, q, cat, sev, why=""):
        dorks["github"].append(_item(title, q, cat, sev, _gh(q), why))

    GH("Cloud keys", f'"{target}" ("AKIA" OR "aws_secret" OR "AZURE_CLIENT_SECRET")', "secrets", "critical", "Search code and commit history for cloud credentials.")
    GH("Private key blocks", f'"{target}" "BEGIN RSA PRIVATE KEY"', "secrets", "critical")
    GH("Generic API keys", f'"{target}" ("api_key" OR "apikey" OR "secret_key")', "secrets", "high")
    GH("Tokens", f'"{target}" ("ghp_" OR "xoxb-" OR "glpat-" OR "sk_live_")', "secrets", "critical")
    GH("Database URLs", f'"{target}" ("postgres://" OR "mysql://" OR "mongodb+srv://")', "secrets", "critical")
    GH("Internal hostnames", f'"{target}" ("internal" AND "http")', "infrastructure", "medium")
    GH("CI/CD secrets", f'"{target}" (".github/workflows" AND "secrets.")', "ci-cd", "high")
    GH("Terraform state", f'"{target}" (path:terraform.tfstate OR path:*.tfvars)', "cloud", "critical")

    # --- Shodan ---
    def SH(title, q, cat, sev, url, why=""):
        dorks["shodan"].append(_item(title, q, cat, sev, url, why))

    SH("Organization footprint", f'org:"{target}"', "infrastructure", "info", "https://www.shodan.io/search?query=" + urllib.parse.quote(f'org:"{target}"'))
    SH("TLS certificate search", f'ssl:"{domain or target}"', "infrastructure", "info", "https://www.shodan.io/search?query=" + urllib.parse.quote(f'ssl:"{domain or target}"'))
    SH("Exposed databases", f'org:"{target}" (port:3306 OR port:5432 OR port:27017 OR port:6379 OR port:9200)', "exposure", "critical", "https://www.shodan.io/search?query=" + urllib.parse.quote(f'org:"{target}" (port:3306 OR port:5432 OR port:27017 OR port:6379 OR port:9200)'))
    SH("Remote access", f'org:"{target}" (port:3389 OR port:5900 OR port:22)', "exposure", "high", "https://www.shodan.io/search?query=" + urllib.parse.quote(f'org:"{target}" (port:3389 OR port:5900 OR port:22)'))
    SH("ICS / SCADA", f'org:"{target}" (port:502 OR port:102 OR port:44818 OR port:47808)', "ics", "critical", "https://www.shodan.io/search?query=" + urllib.parse.quote(f'org:"{target}" (port:502 OR port:102 OR port:44818 OR port:47808)'))
    SH("Default credentials", f'org:"{target}" "default password"', "misconfiguration", "high", "https://www.shodan.io/search?query=" + urllib.parse.quote(f'org:"{target}" "default password"'))

    # --- Censys / FOFA / VirusTotal ---
    dorks["censys"].extend([
        _item("Certificate SANs", f'services.tls.certificates.leaf_data.names: "{domain or target}"', "infrastructure", "info", "https://search.censys.io/search?resource=hosts&q=" + urllib.parse.quote(f'services.tls.certificates.leaf_data.names: "{domain or target}"')),
        _item("Organization ASN", f'autonomous_system.name: "{target}"', "infrastructure", "info", "https://search.censys.io/search?resource=hosts&q=" + urllib.parse.quote(f'autonomous_system.name: "{target}"')),
        _item("Exposed services", f'services.service_name: (HTTP OR SSH OR RDP) and autonomous_system.name: "{target}"', "exposure", "medium", "https://search.censys.io/search?resource=hosts&q=" + urllib.parse.quote(f'autonomous_system.name: "{target}"')),
    ])
    dorks["fofa"].extend([
        _item("Domain assets", f'domain="{domain or target}"', "asset-discovery", "info", "https://fofa.info/result?qbase64=" + urllib.parse.quote(f'domain="{domain or target}"')),
        _item("Certificate assets", f'cert="{domain or target}"', "asset-discovery", "info"),
        _item("Title match", f'title="{target}"', "asset-discovery", "low"),
        _item("Exposed admin", f'domain="{domain or target}" && title="admin"', "admin-panel", "high"),
    ])
    dorks["virustotal"].extend([
        _item("Domain relations", f'domain:{domain or target}', "infrastructure", "info", "https://www.virustotal.com/gui/domain/" + urllib.parse.quote(domain or target)),
        _item("URLs for domain", f'url:{domain or target}', "infrastructure", "info", "https://www.virustotal.com/gui/domain/" + urllib.parse.quote(domain or target) + "/urls"),
    ])
    dorks["pastebin"].extend([
        _item("Credential paste", f'"{domain or target}" (password OR passwd OR credential)', "leak", "high", "https://www.google.com/search?q=" + urllib.parse.quote(f'site:pastebin.com "{domain or target}"')),
    ])
    dorks["linkedin"].extend([
        _item("Employee enumeration", f'site:linkedin.com/in "{target}"', "identity", "low", "https://www.google.com/search?q=" + urllib.parse.quote(f'site:linkedin.com/in "{target}"')),
        _item("Org page", f'site:linkedin.com/company "{target}"', "identity", "info"),
    ])

    total = sum(len(v) for v in dorks.values())
    dorks["_meta"] = {
        "target": target,
        "domain": domain,
        "total": total,
        "platforms": {k: len(v) for k, v in dorks.items() if not k.startswith("_")},
        "note": "Dork generation is passive. Only run these queries against assets you are authorized to assess.",
    }
    return dorks
