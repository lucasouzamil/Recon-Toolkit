from .portscan import scan as portscan
from .dns_lookup import scan as dnslookup
from .whois_lookup import scan as whoislookup
from .subdomain_scanner import scan as subscan
from .tech_fingerprint import scan as techfinger

TOOLS = {
    "portscan":    ("Port Scan TCP/UDP básico",       portscan),
    "dnslookup":   ("DNS Lookup (A,MX,NS,TXT...)",    dnslookup),
    "whois":       ("WHOIS Lookup",                   whoislookup),
    "subdomains":  ("Força‑bruta de subdomínios",     subscan),
    "fingerprint": ("Fingerprint de tecnologias Web", techfinger),
}