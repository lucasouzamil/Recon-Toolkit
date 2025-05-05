import dns.resolver, itertools

_FALLBACK_NS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]   # Cloudflare, Google, Quad9

def _resolve_once(resolver, target, rtype):
    try:
        answer = resolver.resolve(target, rtype)
        return [str(r.to_text()) for r in answer]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return ["NXDOMAIN"]
    except Exception as e:
        return [f"erro: {e}"]

def scan(target: str, record_types=("A", "AAAA", "MX", "NS", "TXT"), nameservers=None, timeout=3.0):
  """
  • target        domínio ou host
  • record_types  tupla/iterável de tipos a consultar
  • nameservers   lista opcional de servidores (ex.: ["8.8.8.8","1.1.1.1"])
  • timeout       tempo máximo (seg) para cada consulta
  """
  saida = {}

  ns_lists = ([nameservers] if nameservers else []) + [_FALLBACK_NS, None]

  for rtype in record_types:
    for ns in ns_lists:
      resolver = dns.resolver.Resolver()
      resolver.lifetime = timeout
      if ns:
        resolver.nameservers = ns

      resp = _resolve_once(resolver, target, rtype)

      if resp and not resp[0].startswith("erro:"):
        saida[rtype] = resp
        break
      else:
        saida[rtype] = resp

  return saida
