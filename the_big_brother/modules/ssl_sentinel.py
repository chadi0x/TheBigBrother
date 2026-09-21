import ssl
import socket
import datetime

def get_ssl_info(domain: str):
    """
    Connects to a domain and retrieves SSL certificate details.
    """
    ctx = ssl.create_default_context()
    results = {
        "domain": domain,
        "issuer": {},
        "subject": {},
        "sans": [],
        "not_before": "",
        "not_after": "",
        "expired": False,
        "error": None
    }
    
    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extract Issuer
                for item in cert.get('issuer', []):
                    key, val = item[0]
                    results['issuer'][key] = val
                    
                # Extract Subject
                for item in cert.get('subject', []):
                    key, val = item[0]
                    results['subject'][key] = val
                
                # Extract SANs (Subject Alternative Names)
                # These are gold mines for subdomains
                sans = cert.get('subjectAltName', [])
                results['sans'] = [val for key, val in sans if key == 'DNS']
                
                # Dates
                results['not_before'] = cert.get('notBefore', '')
                results['not_after'] = cert.get('notAfter', '')
                
                # Check Expiry
                if results['not_after']:
                    # Format: May 25 12:00:00 2026 GMT
                    # Python ssl usually returns this format
                    try:
                        expire_date = datetime.datetime.strptime(results['not_after'], "%b %d %H:%M:%S %Y %Z")
                        if expire_date < datetime.datetime.utcnow():
                            results['expired'] = True
                    except:
                        pass
                        
    except Exception as e:
        results['error'] = str(e)
        
    return results
