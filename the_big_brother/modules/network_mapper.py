import socket
import asyncio
import requests
from pyvis.network import Network
import tempfile
import os
import dns.resolver

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP-MSA",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
    2082: "cPanel", 2083: "cPanel HTTPS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
}

async def check_port(ip, port):
    conn = asyncio.open_connection(ip, port)
    try:
        reader, writer = await asyncio.wait_for(conn, timeout=1)
        writer.close()
        await writer.wait_closed()
        return port, True
    except:
        return port, False

def get_geoip(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

def get_rdap_whois(domain):
    try:
        # RDAP is the new JSON standard for WHOIS
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            # Extract key info safely
            return {
                "registrar": data.get("entities", [{}])[0].get("vcardArray", [[],[]])[1][1][3] if "entities" in data else "Unknown",
                "creation_date":  next((e["date"] for e in data.get("events", []) if e["eventAction"] == "registration"), "Unknown"),
                "status": data.get("status", [])
            }
    except:
        pass
    return {}

def get_dns_records(domain):
    records = {"MX": [], "NS": [], "TXT": [], "A": []}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        try:
            for r in resolver.resolve(domain, 'MX'):
                records["MX"].append(str(r.exchange))
        except: pass
        
        try:
            for r in resolver.resolve(domain, 'NS'):
                records["NS"].append(str(r.target))
        except: pass
        
        try:
            for r in resolver.resolve(domain, 'TXT'):
                records["TXT"].append(str(r))
        except: pass

        try:
            for r in resolver.resolve(domain, 'A'):
                records["A"].append(str(r.address))
        except: pass
        
    except Exception as e:
        print(f"DNS Error: {e}")
    return records

async def scan_target(domain: str):
    """
    Scans a target for IP, open ports, subdomains, GeoIP, Whois, and DNS.
    """
    results = {
        "domain": domain,
        "ip": None,
        "ports": [],
        "subdomains": [],
        "geoip": {},
        "whois": {},
        "dns": {}
    }
    
    # Resolve IP
    try:
        results["ip"] = socket.gethostbyname(domain)
    except:
        return {"error": "Could not resolve domain"}
        
    # Parallel Tasks
    # 1. Port Scan
    port_tasks = [check_port(results["ip"], p) for p in COMMON_PORTS.keys()]
    
    # 2. GeoIP (Sync but fast enough, or thread it)
    results["geoip"] = await asyncio.to_thread(get_geoip, results["ip"])
    
    # 3. Whois
    results["whois"] = await asyncio.to_thread(get_rdap_whois, domain)
    
    # 4. DNS
    results["dns"] = await asyncio.to_thread(get_dns_records, domain)

    # 5. Execute Port Scan
    port_results = await asyncio.gather(*port_tasks)
    
    for port, is_open in port_results:
        if is_open:
            results["ports"].append({"port": port, "service": COMMON_PORTS[port]})
            
    # 6. Subdomains (crt.sh)
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = await asyncio.to_thread(requests.get, url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data:
                name = entry['name_value']
                for n in name.split('\n'):
                    if n.endswith(domain) and n != domain and "*" not in n:
                        subs.add(n)
            results["subdomains"] = list(subs)
    except Exception as e:
        print(f"Subdomain Error: {e}")
        
    return results

def generate_network_map(data):
    """
    Generates an HTML network graph from scan data.
    """
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

