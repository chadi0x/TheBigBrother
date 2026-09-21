def generate_dorks(target: str, domain: str = ""):
    """
    Generates a list of advanced dorks for various platforms.
    """
    dorks = {
        "google": [],
        "shodan": [],
        "github": [],
        "censys": [],
        "fofa": []
    }
    
    # ---------------- GOOGLE (AGGRESSIVE) ----------------
    # SQL Injection
    dorks["google"].append({"title": "SQL Injection Vectors", "query": f"site:{domain} inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= intext:warning intext:mysql"})
    # LFI / Directory Traversal
    dorks["google"].append({"title": "Directory Traversal", "query": f"site:{domain} inurl:include= | inurl:page= | inurl:file= | inurl:cfg= ext:inc | ext:php"})
    # Exposed Git
    dorks["google"].append({"title": "Exposed .git", "query": f"site:{domain} intitle:\"index of\" \"/.git\""})
    # Public Cameras
    dorks["google"].append({"title": "Public Cameras", "query": f"inurl:top.htm inurl:currenttime inurl:pixel"})
    # Log Files
    dorks["google"].append({"title": "Exposed Log Files", "query": f"site:{domain} ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh"})
    # Install/Setup Pages
    dorks["google"].append({"title": "Install/Setup Pages", "query": f"site:{domain} inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config"})
    # S3 Buckets
    dorks["google"].append({"title": "S3 Buckets", "query": f"site:s3.amazonaws.com \"{target}\""})
    # Pastebin Data
    dorks["google"].append({"title": "Pastebin Leaks", "query": f"site:pastebin.com \"{target}\""})

    # ---------------- SHODAN (INFRASTRUCTURE) ----------------
    dorks["shodan"].append({"title": "Organization Infra", "query": f"org:\"{target}\""})
    dorks["shodan"].append({"title": "SSL Certificates", "query": f"ssl:\"{target}\""})
    dorks["shodan"].append({"title": "Vulnerable SMB", "query": f"net:\"{target}\" port:445 has_vuln:true"})
    dorks["shodan"].append({"title": "Open Webcams", "query": "has_screenshot:true port:80,81,8080 title:\"webcam\""})
    dorks["shodan"].append({"title": "Industrial Control Systems", "query": "port:502,102,44818 tag:ics"})
    dorks["shodan"].append({"title": "Default Passwords", "query": "\"default password\" \"admin\""})
    
    if domain:
        dorks["shodan"].append({"title": "Hostname Search", "query": f"hostname:\"{domain}\""})
        
    # ---------------- GITHUB (SECRETS) ----------------
    dorks["github"].append({"title": "AWS Keys", "query": f"\"{target}\" AWS_ACCESS_KEY_ID"})
    dorks["github"].append({"title": "API Keys", "query": f"\"{target}\" API_KEY OR SECRET_KEY"})
    if domain:
        dorks["github"].append({"title": "Internal Passwords", "query": f"\"{domain}\" password OR secret OR key"})

    # ---------------- CENSYS ----------------
    dorks["censys"].append({"title": "Search by Domain", "query": f"services.tls.certificates.leaf_data.names: {domain}"})
    dorks["censys"].append({"title": "Search by Org", "query": f"autonomous_system.name: \"{target}\""})

    # ---------------- FOFA ----------------
    dorks["fofa"].append({"title": "Domain Search", "query": f"domain=\"{domain}\""})
    dorks["fofa"].append({"title": "Title Search", "query": f"title=\"{target}\""})
    dorks["fofa"].append({"title": "Cert Search", "query": f"cert=\"{domain}\""})

    return dorks
