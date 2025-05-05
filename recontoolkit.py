import json, click

@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
def cli():
  """
  RECON TOOL KIT: Framework modular para reconhecimento de alvo em pentests.
  
  Execute `python cli.py <comando> -h` para detalhes de cada módulo."""
  pass

@cli.command(
"portscan",
short_help="Varredura TCP/UDP - top-1000 ou intervalo personalizado",
help="""\
Realiza varredura de portas TCP e/ou UDP.

\b
EXEMPLOS
  ▸ Top-1000 portas TCP      : python recontoolkit.py portscan alvo.com --top1000
  ▸ Intervalo TCP 20-1024    : python recontoolkit.py portscan 10.0.0.1 --range 20 1024
  ▸ TCP + UDP (top-1000)     : python recontoolkit.py portscan alvo.com --udp --top1000
""")
@click.argument("alvo")
@click.option("--tcp/--no-tcp", default=True,  show_default=True, help="Habilita/desabilita varredura TCP.")
@click.option("--udp/--no-udp", default=False, show_default=True, help="Habilita/desabilita varredura UDP.")
@click.option("--top1000", is_flag=True, help="Usa lista Nmap Top-1000 (ignora --range).")
@click.option("--range", "porta_intervalo", nargs=2, type=int, metavar="INI FIM", help="Define intervalo de portas (ex.: --range 1 65535).")
def cmd_portscan(alvo, tcp, udp, top1000, porta_intervalo):
  from recon import portscan
  results = portscan(
    alvo,
    tcp=tcp,
    udp=udp,
    top1000=top1000,
    port_range=tuple(porta_intervalo) if porta_intervalo else None,
  )

  if not results:
    click.echo("Nenhuma porta retornada.")
    return

  header = f"{'PORT':<7}{'PROTO':<6}{'STATE':<10}SERVICE"
  click.echo(header)
  click.echo("-" * len(header))

  for port, proto, state, service in results:
    line = f"{port:<7}{proto:<6}{state:<10}{service}"
    if state == "open":
      click.secho(line, fg="green")
    elif state == "filtered":
      click.secho(line, fg="yellow")
    else:
      click.echo(line)

@cli.command(
"dnslookup",
short_help="Consulta DNS A/AAAA/MX/NS/TXT",
help="""\
Resolve registros DNS de um domínio ou host.

\b
EXEMPLOS
  ▸ Padrão (A, MX, NS, TXT)  : python recontoolkit.py dnslookup exemplo.com
  ▸ Apenas A e AAAA          : python recontoolkit.py dnslookup exemplo.com -t A -t AAAA
""")
@click.argument("alvo")
@click.option("-t", "--types", multiple=True, metavar="TIPO", help="Tipos de registro (ex.: A MX TXT). Vazio = padrão.")
@click.option("--ns", "nameservers", multiple=True, metavar="IP", help="Lista de servidores DNS (pode repetir a opção). Ex.: --ns 8.8.8.8 --ns 1.1.1.1")
def cmd_dns(alvo, types, nameservers):
  from recon import dnslookup
  tipos = types or ("A", "AAAA", "MX", "NS", "TXT")
  res = dnslookup(alvo, record_types=tipos, nameservers=list(nameservers) or None)

  for rtype in tipos:
    valores = res.get(rtype, [])
    if not valores:
      click.secho(f"{rtype:<5} nenhuma resposta", fg="yellow")
      continue
    click.secho(f"{rtype}:", fg="cyan")
    for val in valores:
      if val.startswith("erro:"):
        click.secho(f"  {val}", fg="red")
      else:
        click.echo(f"  {val}")


@cli.command(
    "whois",
    short_help="Consulta WHOIS simplificada",
    help="""\
Retorna informações de registro do domínio.

\b
Exemplos
  ▸ Saída tabular           : python recontoolkit.py.py whois exemplo.com
  ▸ Saída JSON              : python recontoolkit.py.py whois exemplo.com --json
""")
@click.argument("alvo")
def cmd_whois(alvo):
  from recon import whoislookup
  info = whoislookup(alvo)

  campos_humanos = {
    "domain_name":    "Domínio",
    "registrar":      "Registrador",
    "creation_date":  "Criado em",
    "expiration_date":"Expira em",
    "name_servers":   "Name-servers",
    "emails":         "E-mails"
  }

  col_w = max(len(v) for v in campos_humanos.values()) + 2
  click.secho(f"{'CAMPO'.ljust(col_w)}VALOR", fg="cyan", bold=True)
  click.secho("-" * (col_w + 40), fg="cyan")

  def _fmt(val):
    if val is None:
      return "-"
    if isinstance(val, (list, tuple, set)):
      return ", ".join(str(v) for v in val)
    return str(val)

  for chave, label in campos_humanos.items():
    click.echo(f"{label.ljust(col_w)}{_fmt(info.get(chave))}")


@cli.command(
    "subdomains",
    short_help="Força-bruta simples de subdomínios",
    help="""\
Tenta descobrir subdomínios usando wordlist.

\b
Exemplos
  ▸ Wordlist default            : python recontoolkit.py subdomains alvo.com
  ▸ Wordlist custom + 50 threads: python recontoolkit.py subdomains alvo.com -w lista.txt -t 50
  ▸ Saída JSON                  : python recontoolkit.py subdomains alvo.com --json
""")
@click.argument("dominio")
@click.option("-w", "--wordlist", type=click.Path(exists=True), help="Arquivo com palavras, uma por linha.")
@click.option("-t", "--threads", default=30, show_default=True, help="Máximo de threads simultâneas.")
@click.option("--timeout", default=2.5, show_default=True, help="Timeout HTTP em segundos.")
def cmd_subdomains(dominio, wordlist, threads, timeout):
  from recon import subscan
  wl = None
  if wordlist:
    with open(wordlist, encoding="utf-8") as f:
      wl = [l.strip() for l in f if l.strip()]

  encontrados = subscan(dominio, wordlist=wl, threads=threads, timeout=timeout)

  if not encontrados:
    click.secho("Nenhum subdomínio encontrado.", fg="yellow")
    return

  largura = max(len(s) for s in encontrados)
  header  = f"{'#':<3} SUBDOMÍNIO".ljust(largura + 4, " ")
  click.secho(header, fg="cyan", bold=True)
  click.secho("-" * len(header), fg="cyan")

  for idx, sub in enumerate(encontrados, 1):
    click.echo(f"{idx:<3} {sub}")


@cli.command("fingerprint", short_help="Identifica tecnologias Web (heurístico)", help="""\
Faz uma requisição HTTP/HTTPS e tenta inferir servidor e frameworks.

\b
Exemplos
  ▸ Saída tabular           : python recontoolkit.py fingerprint https://exemplo.com
  ▸ Saída JSON              : python recontoolkit.py fingerprint https://exemplo.com --json
""")
@click.argument("url")
@click.option("--json", "json_out", is_flag=True, help="Exibe saída em JSON bruto.")
def cmd_fingerprint(url):
  from recon import techfinger
  res = techfinger(url)

  if not res:
    click.secho("Nenhuma tecnologia detectada.")
    return

  largura = max(len(t) for t in res)
  header  = f"{'#':<3} TECNOLOGIA".ljust(largura + 5, " ")
  click.secho(header, fg="cyan", bold=True)
  click.secho("-" * len(header))

  for idx, tech in enumerate(res, 1):
    click.echo(f"{idx:<3} {tech}")

if __name__ == "__main__":
  cli()
