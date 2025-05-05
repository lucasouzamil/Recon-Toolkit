import whois

def scan(target: str) -> dict:
  """
  Faz WHOIS e devolve dict com campos importantes.
  """
  w = whois.whois(target)
  campos = ["domain_name", "registrar", "creation_date",
            "expiration_date", "name_servers", "emails"]
  return {c: w.get(c) for c in campos}
