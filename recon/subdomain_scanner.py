from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

_DEFAULT_WORDLIST = ["www", "mail", "ftp", "api", "dev", "test"]

def _check(sub, timeout):
  try:
    r = requests.get(f"http://{sub}", timeout=timeout)
    return r.status_code < 500
  except requests.RequestException:
    return False

def scan(domain: str, wordlist=None, threads=30, timeout=2.5):
  """
  Brute-force simples: testa {word}.{domain}
  Retorna lista de subdomínios descobertos.
  """
  wl = wordlist or _DEFAULT_WORDLIST
  encontrados = []
  with ThreadPoolExecutor(max_workers=threads) as exe:
    futs = {exe.submit(_check, f"{w}.{domain}", timeout): w for w in wl}
    for f in as_completed(futs):
      if f.result():
        encontrados.append(f"{futs[f]}.{domain}")
  return encontrados
