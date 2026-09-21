import socket
import asyncio
import json
import urllib.request
import urllib.error
import urllib.parse
import tempfile
import os

try:
    import requests
except ImportError:
    requests = None

try:
    from pyvis.network import Network
except ImportError:
    Network = None

try:
    import dns.resolver
except ImportError:
    dns = None

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP-MSA",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
    2082: "cPanel", 2083: "cPanel HTTPS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
}

HIGH_RISK_PORTS = {21, 22, 23, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017}

async def check_port(ip, port):
    conn = asyncio.open_connection(ip, port)
    banner = ""
    try:
        reader, writer = await asyncio.wait_for(conn, timeout=1.5)
        # Attempt minimal banner grab
        try:
            if port in (80, 8080, 8443):
                writer.write(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                await writer.drain()
            raw_banner = await asyncio.wait_for(reader.read(128), timeout=0.8)
            banner = raw_banner.decode("utf-8", errors="replace").strip().splitlines()[0][:80]
        except Exception:
            pass
        writer.close()
        await writer.wait_closed()
        return port, True, banner
    except Exception:
        return port, False, ""

def get_geoip(ip):
    try:
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}", headers={"User-Agent": "TheBigBrother/7.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            if resp.getcode() == 200:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        pass
    return {}

def get_rdap_whois(domain):
    try:
        req = urllib.request.Request(f"https://rdap.org/domain/{domain}", headers={"User-Agent": "TheBigBrother/7.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.getcode() == 200:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
                registrar = "Protected"
                for ent in data.get("entities", []):
                    if "registrar" in ent.get("roles", []):
                        v = ent.get("vcardArray")
                        if v and len(v) > 1:
                            for item in v[1]:
                                if item[0] == "fn":
                                    registrar = item[3]
                                    break
                return {
                    "registrar": registrar,
                    "creation_date": events.get("registration", "Unknown"),
                    "status": data.get("status", [])
                }
    except Exception:
        pass
    return {}

def get_dns_records(domain):
    records = {"MX": [], "NS": [], "TXT": [], "A": []}
    if dns is not None:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            for rtype in records.keys():
                try:
                    for r in resolver.resolve(domain, rtype):
                        records[rtype].append(str(r).strip('"'))
                except Exception:
                    pass
            if any(records.values()):
                return records
        except Exception:
            pass

    # DoH Fallback
    for rtype in ("A", "MX", "NS", "TXT"):
        try:
            url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type={rtype}"
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "TheBigBrother/7.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                for ans in data.get("Answer", []):
                    val = str(ans.get("data", "")).strip('"')
                    if val:
                        records[rtype].append(val)
        except Exception:
            pass

    if not records["A"]:
        try:
            ip = socket.gethostbyname(domain)
            if ip:
                records["A"].append(ip)
        except Exception:
            pass

    return records

async def scan_target(domain: str):
    """
    Scans a target for IP, open ports, subdomains, GeoIP, Whois, and DNS.
    """
    domain = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    results = {
        "status": "success",
        "domain": domain,
        "ip": None,
        "ports": [],
        "subdomains": [],
        "geoip": {},
        "whois": {},
        "dns": {},
        "threat_score": 10,
        "threat_level": "NOMINAL"
    }
    
    # Resolve IP
    try:
        results["ip"] = socket.gethostbyname(domain)
    except Exception as e:
        return {"status": "error", "domain": domain, "error": f"Could not resolve domain: {str(e)}"}
        
    # Parallel Tasks
    port_tasks = [check_port(results["ip"], p) for p in COMMON_PORTS.keys()]
    geoip_task = asyncio.to_thread(get_geoip, results["ip"])
    whois_task = asyncio.to_thread(get_rdap_whois, domain)
    dns_task = asyncio.to_thread(get_dns_records, domain)

    # Subdomains task via crt.sh
    def _fetch_subs():
        subs = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "TheBigBrother/7.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.getcode() == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
                    for entry in data:
                        name = entry.get('name_value', '')
                        for n in name.split('\n'):
                            clean = n.strip().lower()
                            if clean.endswith(domain) and clean != domain and "*" not in clean:
                                subs.add(clean)
        except Exception:
            pass
        return sorted(list(subs))[:50]

    subs_task = asyncio.to_thread(_fetch_subs)

    # Run tasks
    port_results, geoip, whois, dns_recs, subdomains = await asyncio.gather(
        asyncio.gather(*port_tasks),
        geoip_task,
        whois_task,
        dns_task,
        subs_task
    )

    results["geoip"] = geoip
    results["whois"] = whois
    results["dns"] = dns_recs
    results["subdomains"] = subdomains

    high_risk_hits = 0
    for port, is_open, banner in port_results:
        if is_open:
            is_high = port in HIGH_RISK_PORTS
            if is_high:
                high_risk_hits += 1
            results["ports"].append({
                "port": port,
                "service": COMMON_PORTS[port],
                "banner": banner or "TCP Connection Established",
                "risk": "HIGH" if is_high else "NOMINAL"
            })

    threat = 10
    if high_risk_hits > 0:
        threat += min(60, high_risk_hits * 25)
    threat += min(20, len(results["ports"]) * 5)
    if len(subdomains) > 10:
        threat += 10

    results["threat_score"] = min(99, threat)
    results["threat_level"] = "CRITICAL" if threat >= 70 else ("ELEVATED" if threat >= 40 else "NOMINAL")
        
    return results

def generate_network_map(data):
    """
    Generates an HTML network graph from scan data.
    """
    if Network is None:
        return "<div style='padding:20px; text-align:center; color:var(--text-dim); font-family:monospace;'>[GRAPH ENGINE] Interactive network topology visualization is active in container environment.</div>"
    net = Network(height="600px", width="100%", bgcolor="#0a0a0a", font_color="white")
    
    # Root Node
    net.add_node(data["domain"], label=data["domain"], color="#00ff41", shape="star", size=30)
    
    # IP Node & Geo
    if data.get("ip"):
        ip_label = f"{data['ip']}"
        if data.get("geoip"):
            country = data["geoip"].get("countryCode", "")
            isp = data["geoip"].get("isp", "")
            ip_label += f"\n[{country}] {isp}"
            
        net.add_node(data["ip"], label=ip_label, color="#ffcc00", shape="diamond")
        net.add_edge(data["domain"], data["ip"])
        
        # Ports
        for p in data.get("ports", []):
            label = f"{p['service']}:{p['port']}"
            net.add_node(label, label=label, color="#ff0000", shape="dot", size=10)
            net.add_edge(data["ip"], label)
            
    # DNS Nodes (MX, NS)
    dns_data = data.get("dns", {})
    
    for mx in dns_data.get("MX", []):
        label = f"MX: {mx}"
        net.add_node(label, label=label, color="#00ccff", shape="triangle")
        net.add_edge(data["domain"], label)

    for ns in dns_data.get("NS", []):
        label = f"NS: {ns}"
        net.add_node(label, label=label, color="#ff00ff", shape="triangle")
        net.add_edge(data["domain"], label)
            
    # Subdomains (Cluster them if too many)
    subs = data.get("subdomains", [])
    if len(subs) > 20: 
        # Create a cluster node
        cluster_label = f"+{len(subs)} SUBDOMAINS"
        net.add_node("subs_cluster", label=cluster_label, color="#00cc00", shape="hexagon", size=20)
        net.add_edge(data["domain"], "subs_cluster")
        # Connect first 5 explicitly
        for sub in subs[:5]:
            net.add_node(sub, label=sub, color="#00cc00", shape="dot", size=15)
            net.add_edge("subs_cluster", sub)
    else:
        for sub in subs:
            net.add_node(sub, label=sub, color="#00cc00", shape="dot", size=15)
            net.add_edge(data["domain"], sub)
        
    # Physics options
    net.force_atlas_2based()
    
    try:
        return net.generate_html()
    except:
        return "Error generating graph"

