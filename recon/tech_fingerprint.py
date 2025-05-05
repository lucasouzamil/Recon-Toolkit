import requests, re
from bs4 import BeautifulSoup

_SIGS = {
  "nginx":      re.compile(r"server:.*nginx", re.I),
  "apache":     re.compile(r"server:.*apache", re.I),
  "cloudflare": re.compile(r"cloudflare", re.I),
  "wordpress":  re.compile(r"wp-content", re.I),
  "react":      re.compile(r"__react", re.I)
}

def scan(url: str) -> list[str]:
  """
  Faz um GET e retorna lista de tecnologias sugeridas.
  (Heurística simples baseada em cabeçalhos e HTML.)
  """
  resp = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
  found = []
  # cabeçalhos
  hdrs = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
  html = resp.text
  for tech, sig in _SIGS.items():
    if sig.search(hdrs) or sig.search(html):
      found.append(tech)
  return found
