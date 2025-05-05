from pathlib import Path
import csv, socket, ipaddress
from tqdm import tqdm


DATA_DIR = Path(__file__).resolve().parent / "data"
TOP1000_FILE = DATA_DIR / "top-1000-most-popular-tcp-ports-nmap-sorted.csv"

def _service_name(port, proto):
  try:
    return socket.getservbyport(port, proto)
  except OSError:
    return "desconhecido"

def _scan_tcp(host, ports, timeout=0.5):
  resultados = []
  with tqdm(total=len(ports), desc="TCP", unit="port") as bar:
    for p in ports:
      estado = "closed"
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(timeout)
      try:
        if sock.connect_ex((host, p)) == 0:
          estado = "open"
      except socket.timeout:
        estado = "filtered"
      finally:
        sock.close()
      resultados.append((p, "tcp", estado, _service_name(p, "tcp")))
      bar.update()
  return resultados

def _scan_udp(host, ports, timeout=0.5):
  resultados = []
  with tqdm(total=len(ports), desc="UDP", unit="port") as bar:
    for p in ports:
      estado = "filtered"
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.settimeout(timeout)
      try:
        sock.sendto(b"", (host, p))
        sock.recvfrom(1024)
        estado = "open"
      except socket.timeout:
        pass
      except socket.error as e:
        if e.errno in (socket.errno.ECONNREFUSED, 111):
            estado = "closed"
      finally:
        sock.close()
      resultados.append((p, "udp", estado, _service_name(p, "udp")))
      bar.update()
  return resultados

def scan(target: str, tcp=True, udp=False, top1000=False, port_range=None):
  """
  target        IP ou hostname
  tcp/udp       habilita cada protocolo
  top1000       se True carrega top-1000 portas do Nmap
  port_range    tupla (inicio, fim) se quiser intervalo manual
  Retorna lista de tuplas (porta, proto, estado, serviço)
  """
  try:
    ipaddress.ip_address(target)
    host_ip = target
  except ValueError:
    host_ip = socket.gethostbyname(target)

  if top1000:
    try:
      with TOP1000_FILE.open() as f:
        ports = sorted(int(p) for p in next(csv.reader(f)))
    except FileNotFoundError:
      raise FileNotFoundError(
        f"Lista Nmap Top‑1000 não encontrada em {TOP1000_FILE}. "
        "Verifique se o arquivo existe ou use --range."
      )
  elif port_range:
    ports = list(range(port_range[0], port_range[1] + 1))
  else:
    raise ValueError("Defina top1000=True ou port_range=(ini,fim)")
  results = []
  if tcp:
    results.extend(_scan_tcp(host_ip, ports))
  if udp:
    results.extend(_scan_udp(host_ip, ports))
  return results
