**Autor:** [Lucas Lima](https://github.com/lucasouzamil)

# Recon Tool Kit

Framework modular de reconhecimento para pentests, escrito em Python e baseado em **click**, que reúne em um único binário funções essenciais de footprinting (levantamento de informações públicas) sobre alvos Web.

> **Aviso legal**: utilize esta ferramenta exclusivamente em ambientes de teste ou contra sistemas que você tenha autorização explícita para avaliar. O uso indevido pode infringir legislações locais e internacionais.

## Instalação

```bash
# 1. Clone o repositório
$ git clone https://github.com/lucasouzamil/Recon-Toolkit.git
$ cd Recon-Toolkit

# 2. (Opcional) Crie um ambiente virtual
$ python -m venv venv && source venv/bin/activate  # Linux/macOS
$ python -m venv venv && venv\Scripts\activate    # Windows

# 3. Instale as dependências
$ pip install -r requirements.txt

# 4. Execute
$ python recontoolkit.py -h
```

Requisitos mínimos:

* Python ≥ 3.9
* Sistema operacional: Windows, Linux ou macOS

## Uso

O uso geral do Recon Tool Kit segue o formato:

```bash
python recontoolkit.py <comando> [opções]
```

Use `-h` ou `--help` para obter ajuda detalhada sobre cada comando:

```bash
python recontoolkit.py -h
```

## Comandos Disponíveis

### Portscan

Realiza varreduras de portas TCP/UDP, permitindo customização por intervalo ou utilizando a lista Top-1000 do Nmap.

**Exemplos:**

```bash
python recontoolkit.py portscan alvo.com --top1000
python recontoolkit.py portscan 10.0.0.1 --range 20 1024
python recontoolkit.py portscan alvo.com --udp --top1000
```

### DNS Lookup

Resolve registros DNS como A, AAAA, MX, NS, e TXT.

**Exemplos:**

```bash
python recontoolkit.py dnslookup exemplo.com
python recontoolkit.py dnslookup exemplo.com -t A -t AAAA
```

### WHOIS

Realiza consultas WHOIS simplificadas.

**Exemplo:**

```bash
python recontoolkit.py whois exemplo.com
```

### Subdomains

Realiza uma varredura por força-bruta para identificar subdomínios.

**Exemplos:**

```bash
python recontoolkit.py subdomains alvo.com
python recontoolkit.py subdomains alvo.com -w lista.txt -t 50
```

### Fingerprint

Identifica tecnologias utilizadas em um servidor web por heurística.

**Exemplo:**

```bash
python recontoolkit.py fingerprint https://exemplo.com
```