# Recon Toolkit

CLI modular em Python que agrega scripts de reconhecimento típicos na fase **Information Gathering** de pentests.

## Funcionalidades
| Sub‑comando   | Descrição                                   | Módulo          |
|---------------|---------------------------------------------|-----------------|
| portscan      | Scan TCP/UDP com top‑1000 ou range custom   | recon/portscan  |
| dnslookup     | Resolve registros A/AAAA/MX/NS/TXT          | recon/dns_lookup|
| whois         | WHOIS lookup simplificado                   | recon/whois_lookup|
| subdomains    | Força‑bruta de subdomínios                  | recon/subdomain_scanner |
| fingerprint   | Identifica tecnologias Web (heurístico)     | recon/tech_fingerprint |

## Instalação
```bash
git clone https://github.com/seu‑usuario/recon_toolkit.git
cd recon_toolkit
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Uso
```bash
python cli.py --help                
python cli.py portscan target.com -o '{"top1000":true,"udp":false}'
python cli.py dnslookup target.com
```

## Como adicionar novas ferramentas

1. Crie recon/nova_ferramenta.py implementando scan(target, **opts).

2. Importe‑a e registre‑a no dict TOOLS em recon/__init__.py.