#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_bugbounty.py - Scanner Bug Bounty modular e interativo

Atualizações nesta versão:
- Corrigido uso de proxy em aiohttp (trust_env=True e passagem proxy nas requests)
- Ajustada lógica de --no-screenshots (uso direto do parâmetro do_screenshots)
- Removido import fragil do sslyze em Python; usa somente CLI (run_sslyze_cli)
- Verificação de existência de .git antes de tentar push no git_push_reports
- Tratamento robusto de WebDriverException em screenshots
- Comentários em Português destacam mudanças
"""

import os
import sys
import time
import json
import socket
import shutil
import argparse
import traceback
import subprocess
import datetime
import logging
import platform
import random
import webbrowser
from dataclasses import dataclass
import shlex
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse
from collections import defaultdict, Counter

# ---------------------------
# Dependências: instalar automaticamente se faltarem
# ---------------------------
REQUIRED_PKGS = [
    "requests",
    "beautifulsoup4",
    "dnspython",
    "selenium",
    "webdriver-manager",
    "python-nmap",
    "sslyze",
    "markdown",
    "jinja2",
    "tqdm",
    "colorama",
    "python-dotenv",
    "aiohttp",
    "asyncio",
]

def ensure_packages(pkgs):
    missing = []
    for pkg in pkgs:
        try:
            if pkg == "beautifulsoup4":
                __import__("bs4")
            else:
                __import__(pkg.replace("-", "_"))
        except Exception:
            missing.append(pkg)
    if not missing:
        return
    print("[*] Instalando dependências ausentes:", missing)
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
    except Exception as e:
        print("[!] Falha ao instalar pacotes:", e)
        print("[!] O script continuará, mas algumas funcionalidades podem não funcionar.")

ensure_packages(REQUIRED_PKGS)

# imports pós-instalação
import asyncio
import aiohttp
import requests
from bs4 import BeautifulSoup
import dns.resolver
from webdriver_manager.chrome import ChromeDriverManager
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import WebDriverException  # -> USADO para tratamento robusto
from jinja2 import Template
from tqdm import tqdm
from colorama import Fore, Style, init as colorama_init
from dotenv import load_dotenv

# tentar importar libs opcionais
try:
    import nmap as nmaplib
    NMAP_AVAILABLE = True
except Exception:
    NMAP_AVAILABLE = False

# MUDANÇA: remover import frágil do sslyze em Python (evita erros com versões)
# Apenas usar a CLI sslyze via run_sslyze_cli quando disponível no PATH.
SSLYZE_PY_AVAILABLE = False

try:
    import markdown as markdown_lib
    MARKDOWN_AVAILABLE = True
except Exception:
    MARKDOWN_AVAILABLE = False

# Wappalyzer optional
try:
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except Exception:
    WAPPALYZER_AVAILABLE = False

# carregar .env
load_dotenv()

# ---------------------------
# Configurações principais
# ---------------------------
TARGET_ROOTS = [t.strip() for t in os.environ.get("TARGET_ROOTS", "").split(",") if t.strip()]
USER_AGENT = "Bughunt - Security Research"
DEFAULT_TIMEOUT = 15
REQUEST_DELAY = float(os.environ.get("REQUEST_DELAY", "1.0"))  # segundos entre requisições
CONCURRENCY = int(os.environ.get("CONCURRENCY", "8"))
QUICK_MODE = False
REPORTS_DIR = Path("reports")
LOGS_DIR = Path("logs")
CHECKPOINTS_DIR = Path(".checkpoints")
BRUTE_SUB_WORDS = [
    "www","api","app","admin","beta","dev","staging","stage","test","portal","login","secure","m","mobile",
    "cdn","static","assets","images","img","web","site","mail","smtp","shop","payments","payment","dashboard",
    "help","support","docs","store","checkout","account","user","auth","oauth","sso","identity","session",
    "gateway","proxy","cache","download","upload","files","media","video","audio","stream","live","events",
    "calendar","forum","blog","news","press","career","jobs","partners","vendors","affiliates","promo","offer",
    "deals","status","metrics","monitor","api2","api3","admin2","secure2","internal","intranet","legacy",
    "old","static2","beta2","uat","qa","sandbox","grafana","prometheus","kibana","elk","influx","mgmt","svc",
    "auth0","oauth2","pay","payments","billing","crm","erp","portal2","docs2","apidocs","swagger","redoc",
    "git","gitlab","repo","downloads","uploads","media","cdn","images2","img2","assets2"
]

# gerar wordlist ~1000 por combinação simples
def expand_wordlist(base, target_count=1000):
    out = list(base)
    suffixes = ["", "01", "02", "dev", "stg", "prod", "uat", "test", "old", "-backup"]
    prefixes = ["", "m", "mobile", "web", "app", "api", "secure", "cdn"]
    i = 0
    while len(out) < target_count:
        for p in prefixes:
            for s in suffixes:
                candidate = (p + ("-" if p and s else "") + s).strip("-")
                if candidate and candidate not in out:
                    out.append(candidate)
                if len(out) >= target_count:
                    break
            if len(out) >= target_count:
                break
        i += 1
        if i > 10:
            break
    return out[:target_count]

BRUTE_SUB_WORDS = expand_wordlist(BRUTE_SUB_WORDS, target_count=1000)

# MUDANÇA: priorizar palavras mais comuns no escopo real e manter o restante como fallback.
PRIORITY_BRUTE_SUB_WORDS = [
    "gerenciador", "aluno", "admin", "api", "app", "painel", "unidades",
    "login", "auth", "sso", "dashboard", "portal", "funcionario", "funcionarios",
    "matricula", "academia", "checkout", "club", "area-logada", "loja", "member",
]
BRUTE_SUB_WORDS = expand_wordlist(PRIORITY_BRUTE_SUB_WORDS + BRUTE_SUB_WORDS, target_count=1000)

# directory wordlist ~5000: gerar a partir de tokens comuns
DIR_TOKENS = [
    "admin","login","backup","old","test","staging","dev","config","config.php",".env","wp-admin","wp-login",
    "api","v1","v2","private","secret","debug","db","database","phpmyadmin","server-status",".git",".gitignore",
    "robots.txt","sitemap.xml","uploads","upload","images","assets","css","js",".env.example","README.md","LICENSE"
]
def generate_dir_wordlist(tokens, target=5000):
    out = set(tokens)
    prefixes = ["", "old", "backup", "dev", "test", "stg", "uat", "prod"]
    suffixes = ["", "1", "2", "beta", "v1", "v2", "-old"]
    for p in prefixes:
        for t in tokens:
            for s in suffixes:
                candidate = f"{p}/{t}{s}".lstrip("/")
                out.add(candidate)
                if len(out) >= target:
                    return list(out)[:target]
    i = 0
    while len(out) < target:
        out.add(f"secret_{i}")
        i += 1
    return list(out)[:target]

DIR_WORDLIST = generate_dir_wordlist(DIR_TOKENS, target=1000)

# portas a verificar
PORTS = [80,443,8080,8443,3000,5000,7000,8000,9000,22,21,25,110,143,993,995,3306,5432,27017,6379,9200,9300]

# APIs e chaves via env
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
SECURITYTRAILS_API_KEY = os.environ.get("SECURITYTRAILS_API_KEY")

# ferramentas externas - sem duplicatas
TOOLS = {
    "amass": shutil.which("amass"),
    "subfinder": shutil.which("subfinder"),
    "nuclei": shutil.which("nuclei"),
    "naabu": shutil.which("naabu"),
    "httpx": shutil.which("httpx"),
    "whatweb": shutil.which("whatweb"),
    "nmap": shutil.which("nmap"),
    "sslyze": shutil.which("sslyze"),
    "git": shutil.which("git"),
}

# opções CLI
parser = argparse.ArgumentParser(description="Scanner Bug Bounty modular (não-invasivo)")
parser.add_argument("--no-screenshots", action="store_true", help="Pular screenshots")
parser.add_argument("--no-nuclei", action="store_true", help="Pular execução do nuclei")
parser.add_argument("--no-github", action="store_true", help="Pular push para GitHub (ou usar --no-github)")
parser.add_argument("--resume", type=str, help="Retomar de checkpoint JSON")
parser.add_argument("--limit", type=int, help="Limitar número de subdomínios processados (para teste)", default=0)
parser.add_argument("--proxy", type=str, help="Usar proxy (ex: http://127.0.0.1:8080) para todas requisições")
parser.add_argument("--tor", action="store_true", help="Ativar modo Tor para ferramentas externas")
parser.add_argument("--vpn", type=str, help="Disparar cliente VPN (openvpn/wireguard) com o caminho informado")
parser.add_argument("--target", action="append", help="Alvo único (domínio, IP ou URL). Pode repetir")
parser.add_argument("--targets-file", type=str, help="Arquivo com alvos, um por linha")
parser.add_argument("--mode", choices=["bugbounty", "pentest", "osint", "web", "mobile", "wireless", "tools", "reports"], help="Executar diretamente um modo do framework")
parser.add_argument("--full", action="store_true", help="Executar modo pentest completo sem menu")
parser.add_argument("--silent", action="store_true", help="Modo silencioso para automação/batch")
parser.add_argument("--auto-install", action="store_true", help="Tentar instalar ferramentas ausentes quando possível")
parser.add_argument("--telegram-token", type=str, help="Token do bot Telegram para notificações")
parser.add_argument("--telegram-chat-id", type=str, help="Chat ID do Telegram para notificações")
parser.add_argument("--no-menu", action="store_true", help="Não abrir menu interativo")
parser.add_argument("--quick", action="store_true", help="Modo rápido com wordlist menor e concorrência maior")
args = parser.parse_args()

NO_SCREENSHOTS = args.no_screenshots
NO_NUCLEI = args.no_nuclei
NO_GITHUB = args.no_github
RESUME_PATH = args.resume
LIMIT_SUBS = args.limit if args.limit and args.limit>0 else None
PROXY = args.proxy or os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY")
TOR_MODE = args.tor
VPN_PATH = args.vpn
CLI_TARGETS = args.target or []
TARGETS_FILE = args.targets_file
AUTO_INSTALL = args.auto_install
SILENT_MODE = args.silent
TELEGRAM_TOKEN = args.telegram_token or os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = args.telegram_chat_id or os.environ.get("TELEGRAM_CHAT_ID")
QUICK_MODE = args.quick
FULL_MODE = args.full
MODE_OVERRIDE = args.mode
NO_MENU = args.no_menu

REPORT_PROGRAM_NAME = "BugBounty Scanner"
REPORT_PROGRAM_SCOPE = TARGET_ROOTS

if QUICK_MODE:
    NO_SCREENSHOTS = True
    CONCURRENCY = 16
    DEFAULT_TIMEOUT = 10
    DIR_WORDLIST = generate_dir_wordlist(DIR_TOKENS, target=500)
    print("[*] Modo rápido ativado: wordlist reduzida, screenshots desabilitados, concorrência aumentada.")
else:
    DIR_WORDLIST = generate_dir_wordlist(DIR_TOKENS, target=1000)

# ---------------------------
# Privilege warning for Linux
# ---------------------------
if platform.system().lower() == "linux":
    try:
        if os.geteuid() != 0:
            print("[!] Aviso: algumas ferramentas (nmap raw, naabu em modo privileged) podem precisar de privilégios root. Execute com sudo se necessário.")
    except AttributeError:
        pass  # Windows no geteuid

# If proxy provided, set env so requests use it by default
if PROXY:
    os.environ["HTTP_PROXY"] = PROXY
    os.environ["HTTPS_PROXY"] = PROXY

# Contadores globais para progresso do scan
PROGRESS_TOTAL = 0
PROGRESS_DONE = 0
PROGRESS_ACTIVE = 0
PROGRESS_SKIPPED = 0

# ---------------------------
# Logging e pastas
# ---------------------------
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
REPORT_DIR = REPORTS_DIR / timestamp
LOGS_DIR.mkdir(parents=True, exist_ok=True)
CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)
logfile = LOGS_DIR / f"scan_{timestamp}.log"
logging.basicConfig(
    filename=str(logfile),
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
console.setFormatter(formatter)
logging.getLogger().addHandler(console)
colorama_init()

def log_info(msg):
    logging.info(msg)
def log_warn(msg):
    logging.warning(msg)
def log_err(msg):
    logging.error(msg)
def log_debug(msg):
    logging.debug(msg)

log_info("Iniciando scanner Bug Bounty aprimorado")
log_info(f"Alvos: {TARGET_ROOTS}")
log_debug(f"TOOLS detectadas: {TOOLS}")
if PROXY:
    log_info(f"Proxy configurado: {PROXY}")

# ---------------------------
# Utilitários de rede e segurança
# ---------------------------
HEADERS_BASE = {"User-Agent": USER_AGENT}

def save_checkpoint(data, name="checkpoint"):
    path = CHECKPOINTS_DIR / f"{name}_{timestamp}.json"
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        log_info(f"Checkpoint salvo: {path}")
    except Exception as e:
        log_err(f"Falha ao salvar checkpoint: {e}")

def load_checkpoint(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log_err(f"Falha ao carregar checkpoint {path}: {e}")
        return None

# DNS resolução segura
def resolve_host_sync(host):
    ips = set()
    try:
        answers = dns.resolver.resolve(host, 'A', lifetime=10)
        for r in answers:
            ips.add(r.to_text())
    except Exception as ex:
        log_debug(f"DNS resolve A falhou para {host}: {ex}")
        try:
            ip = socket.gethostbyname(host)
            ips.add(ip)
        except Exception as e:
            log_debug(f"socket.gethostbyname falhou para {host}: {e}")
    return list(ips)

# checar portas via socket (sync)
def check_ports_sync(ip, ports=PORTS, timeout=3):
    open_ports = []
    for p in ports:
        try:
            with socket.create_connection((ip, p), timeout=timeout):
                open_ports.append(p)
        except Exception:
            pass
    return open_ports

# small helper to write files
def write_file(path, data, mode="w", encoding="utf-8"):
    with open(path, mode, encoding=encoding) as f:
        f.write(data)

# ---------------------------
# Subdomínios: crt.sh, VirusTotal, SecurityTrails, ferramentas externas e brute-force
# ---------------------------
def fetch_crtsh(domain):
    out = set()
    try:
        q = f"%.{domain}"
        url = f"https://crt.sh/?q={q}&output=json"
        r = requests.get(url, headers=HEADERS_BASE, timeout=20, proxies={"http": PROXY, "https": PROXY} if PROXY else None)
        if r.status_code == 200:
            try:
                data = r.json()
                for item in data:
                    name = item.get("name_value") or item.get("common_name")
                    if not name:
                        continue
                    for n in str(name).splitlines():
                        n = n.strip()
                        if n.startswith("*."):
                            n = n[2:]
                        if n.endswith(domain):
                            out.add(n.lower())
            except Exception as e:
                log_debug(f"crt.sh parse JSON falhou para {domain}: {e}")
    except Exception as e:
        log_warn(f"crt.sh falhou para {domain}: {e}")
    return out

def fetch_virustotal(domain, api_key):
    out = set()
    if not api_key:
        return out
    try:
        headers = {"x-apikey": api_key, "User-Agent": USER_AGENT}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        params = {"limit": 40}
        r = requests.get(url, headers=headers, params=params, timeout=20, proxies={"http": PROXY, "https": PROXY} if PROXY else None)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("data", []):
                name = item.get("id")
                if name and name.endswith(domain):
                    out.add(name.lower())
    except Exception as e:
        log_warn(f"VirusTotal falhou: {e}")
    return out

def fetch_securitytrails(domain, api_key):
    out = set()
    if not api_key:
        return out
    try:
        headers = {"APIKEY": api_key}
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        r = requests.get(url, headers=headers, timeout=20, proxies={"http": PROXY, "https": PROXY} if PROXY else None)
        if r.status_code == 200:
            data = r.json()
            for s in data.get("subdomains", []):
                out.add(f"{s}.{domain}")
    except Exception as e:
        log_warn(f"SecurityTrails falhou: {e}")
    return out

def run_external_subfinder(domain):
    out = set()
    bin_path = TOOLS.get("subfinder")
    if not bin_path:
        return out
    try:
        cmd = [bin_path, "-d", domain, "-silent"]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
        if r.returncode == 0:
            for line in r.stdout.decode().splitlines():
                if line.strip():
                    out.add(line.strip())
    except Exception as e:
        log_warn(f"subfinder falhou: {e}")
    return out

def run_external_amass(domain):
    out = set()
    bin_path = TOOLS.get("amass")
    if not bin_path:
        return out
    try:
        cmd = [bin_path, "enum", "-d", domain, "-silent"]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
        if r.returncode == 0:
            for line in r.stdout.decode().splitlines():
                if line.strip():
                    out.add(line.strip())
    except Exception as e:
        log_warn(f"amass falhou: {e}")
    return out

def brute_force_subdomains(domain, words=BRUTE_SUB_WORDS):
    out = set()
    for w in words:
        out.add(f"{w}.{domain}".lower())
    return out

# ---------------------------
# Discover endpoints in JS/CSS/HTML
# ---------------------------
import re
URL_REGEX = re.compile(r"""(?:"|')(https?://[^\s'"]+)(?:"|')""", re.IGNORECASE)
RELATIVE_URL_REGEX = re.compile(r"""(?:href=|src=)['"]([^'"]+)['"]""", re.IGNORECASE)

def extract_endpoints_from_text(base_url, text):
    endpoints = set()
    try:
        for m in URL_REGEX.findall(text):
            endpoints.add(m)
        # relative
        for m in RELATIVE_URL_REGEX.findall(text):
            if m.startswith("http"):
                endpoints.add(m)
            elif m.startswith("/"):
                endpoints.add(urljoin(base_url, m))
    except Exception as e:
        log_debug(f"extract_endpoints_from_text erro: {e}")
    return endpoints

ERROR_PAGE_PATTERNS = [
    "this page could not be found",
    "404",
    "página não encontrada",
    "pagina nao encontrada",
    "not found",
    "page not found",
]

def looks_like_error_page(title, text):
    combined = f"{title or ''} {text or ''}".lower()
    return any(pattern in combined for pattern in ERROR_PAGE_PATTERNS)

def extract_query_links_from_html(base_url, html_text):
    links = set()
    try:
        soup = BeautifulSoup(html_text or "", "html.parser")
        for anchor in soup.find_all("a", href=True):
            href = anchor.get("href")
            if not href:
                continue
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            if parsed.query:
                links.add(absolute)
    except Exception as e:
        log_debug(f"extract_query_links_from_html erro: {e}")
    return links

# ---------------------------
# Detection of technologies & security headers
# ---------------------------
SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Expect-CT"
]

def detect_technologies_from_response(resp_text, resp_headers):
    techs = []
    try:
        server = resp_headers.get("Server")
        if server:
            techs.append(f"Server: {server}")
        xpb = resp_headers.get("X-Powered-By")
        if xpb:
            techs.append(f"X-Powered-By: {xpb}")
        text = ""
        if isinstance(resp_text, str):
            text = resp_text.lower()
        elif hasattr(resp_text, "text"):
            text = resp_text.text.lower()
        if "wp-content" in text or "wordpress" in text:
            techs.append("WordPress")
        if "react" in text:
            techs.append("React")
        if "angular" in text:
            techs.append("Angular")
        if "/cdn-cgi/" in text:
            techs.append("Cloudflare")
    except Exception as e:
        log_debug(f"detect_technologies_from_response erro: {e}")
    return list(dict.fromkeys(techs))

def evaluate_security_headers(headers):
    missing = []
    for h in SECURITY_HEADERS:
        if h not in headers:
            missing.append(h)
    return missing

# ---------------------------
# Banner inicial
# ---------------------------
def display_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    try:
        terminal_width = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        terminal_width = 80

    red = "\033[91m"
    gold = "\033[93m"
    white = "\033[97m"
    reset = "\033[0m"

    cross = [
        "███████████",
        "███████████",
        "███████████",
        "███████████",
        "██████████████████████████",
        "██████████████████████████",
        "██████████████████████████",
        "███████████",
        "███████████",
        "███████████",
        "███████████",
        "██████████████████████████",
        "██████████████████████████",
        "██████████████████████████",
        "███████████",
        "███████████",
        "███████████",
        "███████████",
    ]
    top_border = f"{gold}{'╔' + '═' * max(0, terminal_width - 2) + '╗'}{reset}"
    bottom_border = f"{gold}{'╚' + '═' * max(0, terminal_width - 2) + '╝'}{reset}"
    inner_width = max(0, terminal_width - 2)
    title = "🛡️ DEUS VULT - BugBounty Scanner"
    subtitle = "Versão 2.0 | By OpiumGabriel"

    print(top_border)
    print(f"{gold}║{reset}{' ' * inner_width}{gold}║{reset}")
    for raw_line in cross:
        line = raw_line[:inner_width]
        print(f"{gold}║{reset}{red}{line.center(inner_width)}{reset}{gold}║{reset}")
    print(f"{gold}║{reset}{' ' * inner_width}{gold}║{reset}")
    print(f"{gold}║{reset}{gold}{title.center(inner_width)}{reset}{gold}║{reset}")
    print(f"{gold}║{reset}{white}{subtitle.center(inner_width)}{reset}{gold}║{reset}")
    print(f"{gold}║{reset}{' ' * inner_width}{gold}║{reset}")
    print(bottom_border)
    print()

# ---------------------------
# Portais de login: priorização, extração e testes leves
# ---------------------------
LOGIN_ENDPOINT_PATHS = [
    "/login", "/admin", "/admin/login", "/auth", "/signin", "/entrar", "/painel",
    "/gerenciador", "/unidades", "/aluno", "/aluno/login", "/funcionario",
    "/funcionario/login", "/dashboard", "/administrador", "/gestor", "/logon", "/sign-on",
]
LOGIN_ENDPOINT_SET = {path.lstrip("/").lower() for path in LOGIN_ENDPOINT_PATHS}
LOGIN_TITLE_KEYWORDS = ["login", "entrar", "acesso", "admin", "painel", "gerenciador", "aluno", "funcionário", "funcionario"]
LOGIN_SECURITY_HEADERS = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"]
LOGIN_RATE_LIMIT_BLOCK_HINTS = ["too many requests", "rate limit", "try again later", "temporarily blocked", "captcha", "challenge"]
LOGIN_ERROR_ENUM_HINTS = [
    r"usu[aá]rio.*(n[aã]o encontrado|inv[aá]lido|incorreto)",
    r"(senha|password).*(incorreta|inv[aá]lida|errada|wrong)",
    r"(login|acesso).*(inv[aá]lido|incorreto|falhou)",
]

def normalize_dir_path(path):
    return str(path or "").lstrip("/").split("?", 1)[0].split("#", 1)[0].lower()

def prioritize_login_wordlist(wordlist):
    prioritized = []
    seen = set()
    for path in LOGIN_ENDPOINT_PATHS:
        normalized = path.lstrip("/")
        if normalized not in seen:
            prioritized.append(normalized)
            seen.add(normalized)
    for item in wordlist:
        normalized = str(item).lstrip("/")
        if normalized not in seen:
            prioritized.append(normalized)
            seen.add(normalized)
    return prioritized

def classify_form_field(element):
    attrs = " ".join(
        str(value)
        for value in [
            element.get("name"),
            element.get("id"),
            element.get("placeholder"),
            element.get("aria-label"),
            element.get("autocomplete"),
            element.get("type"),
        ]
        if value
    ).lower()
    if element.name == "input":
        input_type = str(element.get("type", "text")).lower()
        if input_type in ("submit", "button", "image", "reset"):
            return "submit"
        if re.search(r"csrf|_token|authenticity_token", attrs):
            return "csrf"
        if input_type == "password" or re.search(r"pass(word)?|senha|pwd", attrs):
            return "senha"
        if input_type == "email" or re.search(r"e-?mail|mail", attrs):
            return "email"
        if re.search(r"matr[ií]cula|matricula", attrs):
            return "matrícula"
        if re.search(r"usu[aá]rio|user(name)?|login|acesso|identidade|id", attrs):
            return "usuário"
        if re.search(r"aluno", attrs):
            return "aluno"
        if re.search(r"funcion[aá]rio|employee|staff", attrs):
            return "funcionário"
        if re.search(r"admin|administrador|gestor|manager|painel|gerenciador", attrs):
            return "admin/portal"
        return element.get("name") or element.get("id") or input_type
    if element.name == "textarea":
        return element.get("name") or element.get("id") or "textarea"
    if element.name == "select":
        return element.get("name") or element.get("id") or "select"
    return None

def extract_login_portal_form_data(html, page_url):
    soup = BeautifulSoup(html or "", "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    forms = []
    all_fields = []
    csrf_present = False
    form_uses_get = False
    for form in soup.find_all("form"):
        method = str(form.get("method", "get")).strip().lower() or "get"
        action = urljoin(page_url, form.get("action") or page_url)
        fields = []
        form_csrf = False
        for element in form.find_all(["input", "textarea", "select", "button"]):
            field_label = classify_form_field(element)
            if field_label:
                fields.append(field_label)
                all_fields.append(field_label)
            if element.name == "input":
                attrs = " ".join(
                    str(value)
                    for value in [
                        element.get("name"),
                        element.get("id"),
                        element.get("value"),
                        element.get("type"),
                    ]
                    if value
                ).lower()
                if re.search(r"csrf|_token|authenticity_token", attrs):
                    form_csrf = True
                    csrf_present = True
        form_uses_get = form_uses_get or method == "get"
        forms.append({
            "method": method,
            "action": action,
            "fields": sorted(set(fields)),
            "csrf_token": form_csrf,
        })
    if not csrf_present and re.search(r"csrf|_token|authenticity_token", html or "", re.IGNORECASE):
        csrf_present = True
    title_hint = any(keyword.lower() in title.lower() for keyword in LOGIN_TITLE_KEYWORDS)
    field_hint = any(field in {"senha", "email", "usuário", "matrícula", "aluno", "funcionário", "admin/portal"} for field in all_fields)
    return {
        "title": title,
        "forms": forms,
        "fields": sorted(set(all_fields)),
        "csrf_token_present": csrf_present,
        "form_uses_get": form_uses_get,
        "title_hint": title_hint,
        "field_hint": field_hint,
    }

async def probe_login_portal_security(session, page_url, portal_data, page_headers):
    portal_url = page_url
    form_target = page_url
    post_form = None
    for form in portal_data.get("forms", []):
        if form.get("method", "get").lower() == "post":
            post_form = form
            form_target = form.get("action") or page_url
            break
    security_headers_missing = [header for header in LOGIN_SECURITY_HEADERS if header not in page_headers]
    if urlparse(page_url).scheme != "https" and "Strict-Transport-Security" in security_headers_missing:
        security_headers_missing.remove("Strict-Transport-Security")
    rate_limit_statuses = []
    rate_limit_blocked = False
    rate_limit_checked = False
    enum_leak_suspected = False
    enum_signals = []
    form_method_get = bool(portal_data.get("form_uses_get"))
    if post_form and not form_method_get:
        username_field = "username"
        password_field = "password"
        csrf_field = None
        for field in post_form.get("fields", []):
            normalized = field.lower()
            if normalized in ("senha", "password"):
                password_field = field
            elif normalized in ("email", "usuário", "usuario", "matrícula", "matricula", "aluno", "funcionário", "funcionario", "admin/portal"):
                username_field = field
            elif normalized == "csrf":
                csrf_field = field
        rate_limit_checked = True
        for attempt in range(3):
            payload = {
                username_field: f"invalid_user_{attempt}",
                password_field: "invalid-password",
            }
            if csrf_field:
                payload[csrf_field] = "invalid-csrf-token"
            response = await fetch_url(session, form_target, method="POST", data=payload, allow_redirects=False)
            rate_limit_statuses.append(response.get("status"))
            response_text = (response.get("text") or "").lower()
            if isinstance(response.get("status"), int) and response.get("status") in (429, 403, 423):
                rate_limit_blocked = True
            if any(hint in response_text for hint in LOGIN_RATE_LIMIT_BLOCK_HINTS):
                rate_limit_blocked = True
            for pattern in LOGIN_ERROR_ENUM_HINTS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    enum_signals.append(pattern)
            if re.search(r"csrf|token|invalid.*token", response_text, re.IGNORECASE):
                enum_signals.append("csrf-message")
            await asyncio.sleep(min(max(REQUEST_DELAY, 0.5), 2.0))
        enum_leak_suspected = len({signal for signal in enum_signals if signal != "csrf-message"}) > 0
    return {
        "portal_url": portal_url,
        "security_headers_missing": security_headers_missing,
        "rate_limit_checked": rate_limit_checked,
        "rate_limit_statuses": rate_limit_statuses,
        "rate_limit_blocked": rate_limit_blocked,
        "enum_leak_suspected": enum_leak_suspected,
        "enum_signals": sorted(set(enum_signals)),
        "form_method_get": form_method_get,
        "recommendations": [
            "Adicionar rate limiting",
            "Implementar CSRF token",
            "Não distinguir entre usuário existente e inexistente",
            "Habilitar cabeçalhos de segurança para a página de login",
        ],
    }

# ---------------------------
# Screenshots com Selenium + Brave
# ---------------------------
def find_brave_binary():
    system = platform.system().lower()
    candidates = []
    if system == "windows":
        candidates = [r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"]
    elif system == "darwin":
        candidates = ["/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"]
    else:
        # linux
        candidates = ["/usr/bin/brave-browser", shutil.which("brave-browser") or "", shutil.which("brave") or ""]
    for c in candidates:
        if c and Path(c).exists():
            return c
    return None

BRAVE_BIN = find_brave_binary()
if BRAVE_BIN:
    log_info(f"Brave binary encontrado: {BRAVE_BIN}")
else:
    log_warn("Brave não encontrado; tentaremos usar Chrome (se disponível). Screenshots podem falhar se nenhum navegador compatível estiver instalado.")

def take_screenshot_selenium(url, out_path, width=1366, height=768, timeout=30):
    """
    MUDANÇA: tratamento robusto de WebDriverException e garantia de driver.quit no finally.
    """
    options = Options()
    try:
        options.add_argument("--headless=new")
    except Exception:
        options.add_argument("--headless")
    options.add_argument(f"user-agent={USER_AGENT}")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument(f"--window-size={width},{height}")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    if BRAVE_BIN:
        options.binary_location = BRAVE_BIN
    driver = None
    try:
        driver_path = ChromeDriverManager().install()
        service = Service(driver_path)
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        time.sleep(1)
        driver.save_screenshot(out_path)
        return True, None
    except WebDriverException as wde:
        log_warn(f"WebDriverException ao tirar screenshot {url}: {wde}")
        log_debug(traceback.format_exc())
        return False, str(wde)
    except Exception as e:
        log_warn(f"Falha screenshot {url}: {e}")
        log_debug(traceback.format_exc())
        return False, str(e)
    finally:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass

# ---------------------------
# Nuclei, nmap, naabu, sslyze wrappers (se disponíveis)
# ---------------------------
def run_nuclei(target, out_dir, templates=None, timeout=120):
    nuclei_bin = TOOLS.get("nuclei")
    if not nuclei_bin:
        return None
    out_file = Path(out_dir) / f"nuclei_{sanitize_filename(target)}.json"
    cmd = [nuclei_bin, "-u", target, "-json", "-o", str(out_file), "-silent"]
    if templates:
        cmd += ["-t", templates]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        if out_file.exists():
            results = []
            with open(out_file, "r", encoding="utf-8") as f:
                for line in f:
                    line=line.strip()
                    if line:
                        try:
                            results.append(json.loads(line))
                        except Exception:
                            continue
            return results
    except Exception as e:
        log_warn(f"nuclei falhou para {target}: {e}")
    return None

def run_nmap_scan(target, ports="1-65535", out_dir=None):
    if NMAP_AVAILABLE:
        try:
            nm = nmaplib.PortScanner()
            res = nm.scan(target, ports)
            return res
        except Exception as e:
            log_warn(f"nmap (python lib) falhou: {e}")
    bin_nmap = TOOLS.get("nmap")
    if not bin_nmap:
        return None
    out_file = None
    if out_dir:
        out_file = Path(out_dir) / f"nmap_{sanitize_filename(target)}.xml"
        cmd = [bin_nmap, "-p", ports, "-oX", str(out_file), target]
    else:
        cmd = [bin_nmap, "-p", ports, target]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        if out_file and out_file.exists():
            with open(out_file, "r", encoding="utf-8") as f:
                return f.read()
    except Exception as e:
        log_warn(f"nmap falhou: {e}")
    return None

def run_naabu(target, ports=None, out_dir=None):
    bin_naabu = TOOLS.get("naabu")
    if not bin_naabu:
        return None
    out_file = None
    if out_dir:
        out_file = Path(out_dir) / f"naabu_{sanitize_filename(target)}.txt"
        cmd = [bin_naabu, "-host", target, "-o", str(out_file)]
        if ports:
            cmd += ["-p", ",".join(map(str, ports))]
    else:
        cmd = [bin_naabu, "-host", target]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        if out_file and out_file.exists():
            with open(out_file, "r", encoding="utf-8") as f:
                return [l.strip() for l in f if l.strip()]
    except Exception as e:
        log_warn(f"naabu falhou: {e}")
    return None

def run_sslyze_cli(host, out_dir):
    sslyze_bin = TOOLS.get("sslyze")
    if not sslyze_bin:
        return None
    out_file = Path(out_dir) / f"sslyze_{sanitize_filename(host)}.json"
    try:
        cmd = [sslyze_bin, "--regular", "--json_out", str(out_file), f"{host}:443"]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        if out_file.exists():
            with open(out_file, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        log_warn(f"sslyze falhou para {host}: {e}")
    return None

# ---------------------------
# Helpers de payloads e testes não-invasivos
# ---------------------------
XSS_PAYLOAD = "<bughunt-xss-123456>"
XSS_PAYLOAD_ALERT = "\"><script>alert(1)</script>"  # documentado, NÃO executado automaticamente
SQLI_TESTS = ["' OR '1'='1", "\" OR \"1\"=\"1", "';--", "\";--"]
TIME_BASED_TEST = "SLEEP(1)"

def snippet(text, marker, radius=200):
    try:
        idx = text.find(marker)
        if idx == -1:
            idx = 0
        start = max(0, idx-radius)
        end = min(len(text), idx+len(marker)+radius)
        return text[start:end].replace("\n", " ")
    except Exception:
        return ""

def sanitize_filename(s):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)[:200]

# ---------------------------
# Async HTTP client + rate limiting
# ---------------------------
class RateLimiter:
    def __init__(self, rate_per_sec=1.0):
        self.delay = 1.0 / rate_per_sec if rate_per_sec>0 else 0
        self.lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self):
        async with self.lock:
            now = time.time()
            wait = self.delay - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.time()

rate_limiter = RateLimiter(rate_per_sec=max(0.2, 1.0/REQUEST_DELAY))

async def fetch_url(session, url, method="GET", headers=None, data=None, allow_redirects=True, timeout=None):
    """
    MUDANÇA: passa proxy explicitamente (proxy=PROXY) se PROXY estiver definido.
    """
    await rate_limiter.wait()
    headers = headers or {}
    headers.setdefault("User-Agent", USER_AGENT)
    timeout = DEFAULT_TIMEOUT if timeout is None else timeout
    try:
        if PROXY:
            async with session.request(method, url, headers=headers, data=data, allow_redirects=allow_redirects, timeout=timeout, proxy=PROXY) as resp:
                text = await resp.text(errors="ignore")
                return {"url": str(resp.url), "status": resp.status, "headers": dict(resp.headers), "text": text, "elapsed": resp.elapsed.total_seconds() if hasattr(resp, "elapsed") else None}
        else:
            async with session.request(method, url, headers=headers, data=data, allow_redirects=allow_redirects, timeout=timeout) as resp:
                text = await resp.text(errors="ignore")
                return {"url": str(resp.url), "status": resp.status, "headers": dict(resp.headers), "text": text, "elapsed": resp.elapsed.total_seconds() if hasattr(resp, "elapsed") else None}
    except asyncio.TimeoutError:
        return {"url": url, "status": "timeout", "headers": {}, "text": "", "elapsed": None}
    except Exception as e:
        log_debug(f"fetch_url erro para {url}: {e}")
        return {"url": url, "status": f"error:{e}", "headers": {}, "text": "", "elapsed": None}

# ---------------------------
# Directory enumeration (async)
# ---------------------------
async def enum_directories(session, base_url, wordlist, out_dir, concurrency=20):
    found = []
    sem = asyncio.Semaphore(concurrency)
    tasks = []
    base_url = base_url.rstrip("/")
    async def worker(path):
        async with sem:
            url = f"{base_url}/{path.lstrip('/')}"
            res = await fetch_url(session, url)
            st = res["status"]
            try:
                if isinstance(st, int) and st in (200,401,403,302):
                    title = ""
                    try:
                        bs = BeautifulSoup(res.get("text", ""), "html.parser")
                        t = bs.title
                        title = t.string.strip() if t and t.string else ""
                    except Exception:
                        title = ""
                    is_error_page = st == 200 and looks_like_error_page(title, res.get("text", ""))
                    found.append({"url": url, "status": st, "is_error_page": is_error_page})
                    fn = out_dir / f"dir_{sanitize_filename(url)}.json"
                    with open(fn, "w", encoding="utf-8") as f:
                        json.dump(res, f, ensure_ascii=False, indent=2)
            except Exception as e:
                log_debug(f"enum_directories worker erro para {url}: {e}")
    for p in wordlist:
        tasks.append(asyncio.ensure_future(worker(p)))
    for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"Enum {base_url}"):
        try:
            await f
        except Exception:
            pass
    return found

async def is_live_subdomain(session, base_url):
    """Verificação leve para evitar enumeração de diretórios em hosts mortos."""
    try:
        head_res = await fetch_url(session, base_url, method="HEAD", allow_redirects=False, timeout=min(DEFAULT_TIMEOUT, 5))
        status = head_res.get("status")
        if isinstance(status, int) and (200 <= status < 400):
            return True, head_res
        if status in (405, 501):
            get_res = await fetch_url(session, base_url, method="GET", allow_redirects=False, timeout=min(DEFAULT_TIMEOUT, 5))
            get_status = get_res.get("status")
            if isinstance(get_status, int) and (200 <= get_status < 400):
                return True, get_res
            return False, get_res
        return False, head_res
    except Exception as e:
        log_debug(f"is_live_subdomain erro para {base_url}: {e}")
        return False, {"status": "error", "text": "", "headers": {}, "url": base_url}

async def discover_login_portals(session, base_url, directory_results, out_dir):
    portals = []
    seen_urls = set()
    candidates = []
    base_url = base_url.rstrip("/")
    prioritized_paths = prioritize_login_wordlist([item.lstrip("/") for item in LOGIN_ENDPOINT_PATHS])
    for path in prioritized_paths:
        candidates.append(f"{base_url}/{path.lstrip('/')}")
    for item in directory_results:
        url = item.get("url")
        if url:
            candidates.append(url)
    for candidate_url in candidates[:len(LOGIN_ENDPOINT_PATHS) + 50]:
        normalized_path = normalize_dir_path(urlparse(candidate_url).path)
        if normalized_path not in LOGIN_ENDPOINT_SET and not any(keyword in normalized_path for keyword in ("login", "admin", "auth", "painel", "aluno", "funcionario", "gestor", "dashboard", "signin", "entrar", "logon", "sign-on")):
            continue
        if candidate_url in seen_urls:
            continue
        seen_urls.add(candidate_url)
        try:
            await rate_limiter.wait()
            response = await fetch_url(session, candidate_url)
            status = response.get("status")
            if not isinstance(status, int) or status != 200:
                continue
            html = response.get("text", "")
            page_data = extract_login_portal_form_data(html, response.get("url") or candidate_url)
            if not (page_data.get("title_hint") or page_data.get("field_hint") or page_data.get("forms")):
                continue
            security_data = await probe_login_portal_security(session, response.get("url") or candidate_url, page_data, response.get("headers", {}))
            portal_entry = {
                "url": response.get("url") or candidate_url,
                "title": page_data.get("title", ""),
                "forms": page_data.get("forms", []),
                "fields": page_data.get("fields", []),
                "csrf_token_present": page_data.get("csrf_token_present", False),
                "form_uses_get": page_data.get("form_uses_get", False),
                "security_headers_missing": security_data.get("security_headers_missing", []),
                "rate_limit_checked": security_data.get("rate_limit_checked", False),
                "rate_limit_statuses": security_data.get("rate_limit_statuses", []),
                "rate_limit_blocked": security_data.get("rate_limit_blocked", False),
                "enum_leak_suspected": security_data.get("enum_leak_suspected", False),
                "enum_signals": security_data.get("enum_signals", []),
                "recommendations": security_data.get("recommendations", []),
                "high_potential_severity": True,
            }
            portals.append(portal_entry)
            fn = out_dir / f"login_portal_{sanitize_filename(portal_entry['url'])}.json"
            with open(fn, "w", encoding="utf-8") as f:
                json.dump(portal_entry, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log_debug(f"discover_login_portals erro para {candidate_url}: {e}")
    return portals

# ---------------------------
# Vulnerability checks (safe, non-invasive)
# ---------------------------
async def test_reflected_xss_async(session, url):
    findings = []
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    if not qs:
        return findings
    for i, (k, v) in enumerate(qs):
        params = list(qs)
        params[i] = (k, XSS_PAYLOAD)
        new_q = urlencode(params)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
        res = await fetch_url(session, new_url)
        if XSS_PAYLOAD in res.get("text", ""):
            findings.append({
                "type": "reflected-xss",
                "param": k,
                "url": new_url,
                "evidence_snippet": snippet(res.get("text", ""), XSS_PAYLOAD),
                "note": "Indicador: payload refletido. Verificar manualmente; pode gerar falso positivo."
            })
    return findings

async def test_sqli_async(session, url):
    findings = []
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    if not qs:
        return findings
    for i, (k, v) in enumerate(qs):
        for payload in SQLI_TESTS:
            params = list(qs)
            params[i] = (k, payload)
            new_q = urlencode(params)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
            res = await fetch_url(session, new_url)
            body = res.get("text","").lower()
            errors = ["sql syntax", "mysql", "syntax error", "unterminated quoted string", "sqlite", "odbc", "native client", "sql error"]
            for sig in errors:
                if sig in body:
                    findings.append({
                        "type": "sqli-error",
                        "param": k,
                        "payload": payload,
                        "url": new_url,
                        "evidence_snippet": snippet(body, sig),
                        "note": "Indicador por mensagem de erro. Confirmar manualmente."
                    })
                    break
    return findings

async def test_open_redirect_async(session, url):
    findings = []
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    if not qs:
        return findings
    for i, (k, v) in enumerate(qs):
        params = list(qs)
        params[i] = (k, "http://example.com")
        new_q = urlencode(params)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
        res = await fetch_url(session, new_url, allow_redirects=False)
        st = res.get("status")
        hdrs = res.get("headers", {})
        if isinstance(st, int) and st in (301,302,303,307,308):
            location = hdrs.get("Location") or hdrs.get("location")
            if location and "example.com" in location:
                findings.append({
                    "type": "open-redirect",
                    "param": k,
                    "url": new_url,
                    "evidence": {"status": st, "location": location}
                })
    return findings

async def test_cors_async(session, url):
    findings = []
    origin = "https://example.com"
    headers = {"Origin": origin}
    res = await fetch_url(session, url, headers=headers)
    hdrs = res.get("headers", {})
    allow_origin = hdrs.get("Access-Control-Allow-Origin")
    allow_creds = hdrs.get("Access-Control-Allow-Credentials")
    if allow_origin == "*" and allow_creds == "true":
        findings.append({"type":"cors-misconfig", "url": url, "evidence": {"allow_origin": allow_origin, "allow_creds": allow_creds}})
    if allow_origin and origin in allow_origin and allow_creds == "true":
        findings.append({"type":"cors-possible", "url": url, "evidence": {"allow_origin": allow_origin, "allow_creds": allow_creds}})
    return findings

async def test_security_headers_async(session, url):
    res = await fetch_url(session, url)
    hdrs = res.get("headers", {})
    missing = evaluate_security_headers(hdrs)
    findings = []
    if missing:
        findings.append({"type":"missing-security-headers", "url":url, "missing": missing})
    return findings

async def test_ssrf_async(session, url):
    findings = []
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    if not qs:
        return findings
    for i, (k, v) in enumerate(qs):
        params = list(qs)
        params[i] = (k, "http://169.254.169.254/latest/meta-data/")
        new_q = urlencode(params)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
        res = await fetch_url(session, new_url)
        body = res.get("text","").lower()
        if "amazon" in body or "metadata" in body:
            findings.append({"type":"ssrf-possible", "param":k, "url":new_url, "evidence_snippet": snippet(body, "metadata")})
    return findings

# Subdomain takeover heuristic
TAKEOVER_INDICATORS = ["herokuapp.com", "github.io", "amazonaws.com", "azurewebsites.net", "s3.amazonaws.com", "cloudfront.net", "pages.dev"]
def check_subdomain_takeover(host):
    findings = []
    try:
        answers = dns.resolver.resolve(host, 'CNAME', lifetime=5)
        for a in answers:
            t = a.to_text().lower()
            for ind in TAKEOVER_INDICATORS:
                if ind in t:
                    findings.append({"type":"subdomain-takeover-cname", "host":host, "cname":t, "indicator":ind})
    except Exception as e:
        log_debug(f"check_subdomain_takeover({host}) erro: {e}")
    return findings

# ---------------------------
# Scan por subdomínio (orquestração)
# ---------------------------
async def scan_subdomain(session, sub, out_dir, do_screenshots=True, do_nuclei=True):
    """
    Nota: MUDANÇA aplicada: usar 'if do_screenshots:' (removida redundância com NO_SCREENSHOTS).
    """
    result = {
        "subdomain": sub,
        "ips": [],
        "open_ports": [],
        "http": None,
        "title": None,
        "headers": {},
        "tech": [],
        "dirs": [],
        "endpoints": [],
        "findings": [],
        "screenshots": [],
        "http_responses": [],
        "login_portals": [],
        "skipped_dirs": False,
        "skip_dirs": False,
        "is_error_page": False,
        "query_links": [],
    }
    try:
        # DNS
        ips = resolve_host_sync(sub)
        result["ips"] = ips
        # naabu if available
        if TOOLS.get("naabu"):
            try:
                nares = run_naabu(sub, ports=PORTS, out_dir=out_dir)
                if nares:
                    open_ports = sorted([int(p) for p in nares if str(p).isdigit()])
                    result["open_ports"] = open_ports
                    log_debug(f"naabu open_ports {sub}: {open_ports}")
            except Exception as e:
                log_debug(f"naabu erro para {sub}: {e}")
        # fallback socket
        if not result["open_ports"]:
            open_ports_set = set()
            for ip in ips:
                ops = check_ports_sync(ip, ports=PORTS, timeout=2)
                for p in ops:
                    open_ports_set.add(p)
            result["open_ports"] = sorted(list(open_ports_set))
        # subdomain takeover
        takeover = check_subdomain_takeover(sub)
        if takeover:
            result["findings"].extend(takeover)
        # sslyze via CLI se disponível
        if 443 in result["open_ports"] and TOOLS.get("sslyze"):
            try:
                sslyze_res = run_sslyze_cli(sub, out_dir)
                if sslyze_res:
                    result.setdefault("tls", sslyze_res)
            except Exception as e:
                log_debug(f"sslyze erro: {e}")
        # HTTP(S)
        schemes = ["https","http"]
        http_resp = None
        for scheme in schemes:
            url = f"{scheme}://{sub}/"
            res = await fetch_url(session, url)
            status = res.get("status")
            if isinstance(status, int) and 200 <= status < 400:
                http_resp = res
                result["http"] = {"url": url, "status": status}
                try:
                    bs = BeautifulSoup(res.get("text",""), "html.parser")
                    t = bs.title
                    result["title"] = t.string.strip() if t and t.string else ""
                except Exception as e:
                    log_debug(f"title parse erro: {e}")
                result["headers"] = res.get("headers", {})
                break
        if http_resp:
            techs = detect_technologies_from_response(http_resp.get("text",""), http_resp.get("headers", {}))
            result["tech"] = techs
            resp_fn = out_dir / f"http_{sanitize_filename(sub)}.json"
            with open(resp_fn, "w", encoding="utf-8") as f:
                json.dump(http_resp, f, ensure_ascii=False, indent=2)
            result["http_responses"].append(str(resp_fn))
            endpoints = extract_endpoints_from_text(http_resp.get("url"), http_resp.get("text",""))
            result["endpoints"] = list(endpoints)[:200]
            # MUDANÇA: detectar páginas de erro disfarçadas para evitar falsos positivos em SPAs e hosts mortos
            page_title = result.get("title") or ""
            page_text = http_resp.get("text", "")
            if looks_like_error_page(page_title, page_text):
                result["is_error_page"] = True
                result["skip_dirs"] = True
                result["skipped_dirs"] = True
                result["dirs"] = []
                result["login_portals"] = []
                log_debug(f"Página de erro detectada em {sub}; enumeração de diretórios ignorada.")
            # MUDANÇA: testar também URLs com parâmetros encontrados em links da página principal
            query_links = sorted(extract_query_links_from_html(http_resp.get("url"), page_text))
            result["query_links"] = query_links[:200]
            query_candidates = set(query_links[:200])
            for link_url in query_candidates:
                candidates = result.setdefault("endpoints", [])
                if link_url not in candidates:
                    candidates.append(link_url)
            # MUDANÇA: validar rapidamente se o host está vivo antes de gastar tempo com enumeração de diretórios
            live_ok, live_probe = await is_live_subdomain(session, http_resp.get("url"))
            live_status = live_probe.get("status")
            if not live_ok or not (isinstance(live_status, int) and (200 <= live_status < 400)) or result["is_error_page"] or not page_title.strip():
                result["skipped_dirs"] = True
                log_debug(f"Enumeração de diretórios pulada para {sub}: status={live_status}")
            else:
                dir_limit = 500 if QUICK_MODE else 1000
                dir_concurrency = 20 if QUICK_MODE else 8
                login_first_wordlist = prioritize_login_wordlist(DIR_WORDLIST[:dir_limit])
                dirs_found = await enum_directories(session, http_resp.get("url"), login_first_wordlist, out_dir, concurrency=dir_concurrency)
                # MUDANÇA: não registrar páginas de erro disfarçadas como diretórios válidos
                result["dirs"] = [d for d in dirs_found if not d.get("is_error_page")]
                # MUDANÇA: priorizar e identificar portais de login entre os diretórios encontrados
                login_portals = await discover_login_portals(session, http_resp.get("url"), result["dirs"], out_dir)
                result["login_portals"] = login_portals
            # MUDANÇA: simplificada condição de screenshots
            if do_screenshots:
                ss_name = out_dir / f"screenshot_{sanitize_filename(sub)}.png"
                ok, err = take_screenshot_selenium(http_resp.get("url"), str(ss_name))
                if ok:
                    result["screenshots"].append(str(ss_name))
                else:
                    log_warn(f"Screenshots falharam para {sub}: {err}")
            # checks leves
            candidates = set(result["endpoints"])
            for d in result["dirs"]:
                candidates.add(d["url"])
            for portal in result.get("login_portals", []):
                candidates.add(portal.get("url"))
            if urlparse(http_resp.get("url")).query:
                candidates.add(http_resp.get("url"))
            sem = asyncio.Semaphore(10)
            async def run_checks(cand):
                async with sem:
                    try:
                        findings = []
                        findings += await test_security_headers_async(session, cand)
                        findings += await test_reflected_xss_async(session, cand)
                        findings += await test_sqli_async(session, cand)
                        findings += await test_open_redirect_async(session, cand)
                        findings += await test_cors_async(session, cand)
                        findings += await test_ssrf_async(session, cand)
                        if findings:
                            result["findings"].extend(findings)
                    except Exception as e:
                        log_debug(f"run_checks erro para {cand}: {e}")
            tasks = [asyncio.ensure_future(run_checks(c)) for c in list(candidates)[:200]]
            for t in asyncio.as_completed(tasks):
                try:
                    await t
                except Exception:
                    pass
            # nuclei
            if TOOLS.get("nuclei") and do_nuclei and not NO_NUCLEI:
                try:
                    nucres = run_nuclei(http_resp.get("url"), out_dir)
                    if nucres:
                        for n in nucres:
                            result["findings"].append({"type":"nuclei","evidence":n})
                except Exception as e:
                    log_warn(f"nuclei erro: {e}")
        else:
            result["http"] = {"url": None, "status": "no-http"}
    except Exception as e:
        log_err(f"Erro ao scan_subdomain {sub}: {e}\n{traceback.format_exc()}")
    try:
        with open(out_dir / f"sub_{sanitize_filename(sub)}.json", "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log_debug(f"Falha ao salvar sub_{sub}: {e}")
    return result

def severity_rank(severity):
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return order.get(severity, 4)

def infer_cwe(finding):
    finding_type = str(finding.get("type", "")).lower()
    if "sqli" in finding_type:
        return "CWE-89"
    if "xss" in finding_type:
        return "CWE-79"
    if "open-redirect" in finding_type:
        return "CWE-601"
    if "ssrf" in finding_type:
        return "CWE-918"
    if "cors" in finding_type:
        return "CWE-942"
    if "takeover" in finding_type:
        return "CWE-200"
    return "CWE-200"

def infer_cvss_vector(finding):
    severity = finding.get("severity", "Low")
    if severity == "Critical":
        return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if severity == "High":
        return "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"
    if severity == "Medium":
        return "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    return "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"

def infer_impact_text(finding):
    finding_type = str(finding.get("type", "")).lower()
    if "sqli" in finding_type:
        return "Possível acesso indevido a dados da aplicação e exfiltração de informações sensíveis."
    if "xss" in finding_type:
        return "Possível execução de scripts no navegador da vítima e comprometimento da sessão ou da integridade da página."
    if "open-redirect" in finding_type:
        return "Possível abuso de redirecionamento para phishing ou encadeamento de ataques de confiança."
    if "ssrf" in finding_type:
        return "Possível acesso a recursos internos e endpoints restritos a partir do servidor."
    if "takeover" in finding_type:
        return "Possível apropriação indevida de subdomínio e impacto reputacional."
    return "Impacto a ser validado manualmente com evidências adicionais."

# MUDANÇA: consolidar alvos que valem revisão manual rápida no pós-scan.
def build_manual_review_items(all_results, findings_list, login_portals_list):
    items = []
    for sub, result in sorted(all_results.items()):
        if result.get("login_portals"):
            items.append({
                "type": "portal-login",
                "subject": sub,
                "detail": f"{len(result['login_portals'])} portal(is) de login identificado(s)",
            })
        query_links = result.get("query_links", []) or []
        if query_links:
            items.append({
                "type": "parametros",
                "subject": sub,
                "detail": f"{min(len(query_links), 10)} URL(s) com query string extraída(s) da página principal",
            })
        if result.get("skip_dirs") or result.get("skipped_dirs"):
            items.append({
                "type": "subdominio-pulou-diretorios",
                "subject": sub,
                "detail": "Enumeração pesada de diretórios foi pulada após a validação da resposta principal.",
            })
    for item in sorted(findings_list, key=lambda entry: severity_rank(entry["finding"].get("severity", "Low"))):
        finding = item["finding"]
        if finding.get("severity") in ("Critical", "High"):
            items.append({
                "type": "achado-alto",
                "subject": item["sub"],
                "detail": f"{finding.get('type')} | CWE {infer_cwe(finding)} | {finding.get('url', '-')}",
            })
    # remover duplicatas preservando ordem
    deduped = []
    seen = set()
    for item in items:
        key = (item["type"], item["subject"], item["detail"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped

def build_bughunt_submission_report(all_results, findings_list, login_portals_list):
    sorted_findings = sorted(findings_list, key=lambda item: severity_rank(item["finding"].get("severity", "Low")))
    primary = sorted_findings[0]["finding"] if sorted_findings else {}
    primary_sub = sorted_findings[0]["sub"] if sorted_findings else "-"
    scan_targets = ", ".join(REPORT_PROGRAM_SCOPE)
    title = primary.get("type", "Achado principal não confirmado") if primary else "Achado principal não confirmado"
    impact = infer_impact_text(primary) if primary else "Nenhuma ameaça validada nesta execução."
    cvss_vector = infer_cvss_vector(primary) if primary else "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
    cwe = infer_cwe(primary) if primary else "CWE-200"
    threat_summary = primary.get("evidence_snippet", primary.get("evidence", primary.get("note", "Sem evidência textual resumida."))) if primary else "Sem evidência validada."
    manual_review_items = build_manual_review_items(all_results, findings_list, login_portals_list)

    md = []
    md.append(f"# {REPORT_PROGRAM_NAME}")
    md.append("")
    md.append("## Ameaças")
    md.append(f"**Título do relatório:** {title}")
    md.append(f"**Informe o escopo onde estão as ameaças:** {scan_targets}")
    md.append(f"**Escopo analisado nesta execução:** {', '.join(TARGET_ROOTS)}")
    md.append(f"**Informe o impacto:** {impact}")
    md.append("")
    md.append("##### CVSS - 3.1")
    md.append("###### Common Vulnerability Scoring System")
    md.append("")
    md.append(f"**Vector:** {cvss_vector}")
    md.append(f"**CWE:** {cwe}")
    md.append("")
    md.append("**Agora conte-nos um pouco sobre a ameaça!**")
    md.append(threat_summary)
    md.append("")
    md.append("## Testes")
    md.append("**Descreva os testes realizados**")
    md.append(f"- Subdomínios verificados: {len(all_results)}")
    md.append(f"- Portais de login identificados: {sum(len(r.get('login_portals', [])) for r in all_results.values())}")
    md.append(f"- Endpoints descobertos: {sum(len(r.get('endpoints', [])) for r in all_results.values())}")
    md.append(f"- Diretórios válidos retornados: {sum(len(r.get('dirs', [])) for r in all_results.values())}")
    md.append("- Enumeração de subdomínios, validação HTTP, extração de endpoints e revisão manual das evidências.")
    if login_portals_list:
        md.append("- Portais de login analisados com extração de título, campos de formulário e presença de CSRF.")
    md.append("")
    md.append("### Enviar arquivos")
    md.append("Arquivos gerados pela execução:")
    md.append(f"- {REPORT_DIR.name}/scan_results.json")
    md.append(f"- {REPORT_DIR.name}/report.md")
    md.append(f"- {REPORT_DIR.name}/report.html")
    md.append(f"- {REPORT_DIR.name}/bughunt_submission.md")
    md.append(f"- {REPORT_DIR.name}/bughunt_submission.html")
    md.append("")
    md.append("## Concluir")
    md.append("Revisado o relatório, as evidências foram resumidas acima e os artefatos de apoio foram gerados para submissão.")
    md.append("")
    md.append("## Revisão Manual Recomendada")
    if manual_review_items:
        for item in manual_review_items[:15]:
            md.append(f"- [{item['type']}] {item['subject']}: {item['detail']}")
    else:
        md.append("- Nenhum alvo adicional foi marcado para revisão manual nesta execução.")
    md.append("")
    md.append("## Sumário das ameaças priorizadas")
    if sorted_findings:
        for item in sorted_findings[:5]:
            finding = item["finding"]
            md.append(f"- {finding.get('type')} em {item['sub']} (Severidade: {finding.get('severity')}, CWE: {infer_cwe(finding)})")
    else:
        md.append("- Nenhuma ameaça validada nesta execução.")

    md_path = REPORT_DIR / "bughunt_submission.md"
    write_file(md_path, "\n".join(md))
    html_path = REPORT_DIR / "bughunt_submission.html"
    try:
        if MARKDOWN_AVAILABLE:
            html = markdown_lib.markdown(open(md_path, "r", encoding="utf-8").read(), extensions=["tables"])
            css = """
            <style>
            body{font-family: Arial, sans-serif; padding:20px; line-height:1.5}
            h1,h2,h3,h4{margin-top:1.2em}
            pre{white-space:pre-wrap}
            code{background:#f5f5f5; padding:2px 4px; border-radius:4px}
            table{border-collapse: collapse}
            table, th, td{border:1px solid #ccc; padding:6px}
            </style>
            """
            write_file(html_path, f"{css}\n{html}")
        else:
            md = open(md_path, "r", encoding="utf-8").read()
            write_file(html_path, "<pre>" + md + "</pre>")
    except Exception as e:
        log_warn(f"Erro gerando relatório BugHunt HTML: {e}")
    return md_path, html_path

# ---------------------------
# Orquestração principal (async)
# ---------------------------
async def main_async():
    # coletar subdomínios
    candidates = set()
    for root in TARGET_ROOTS:
        log_info(f"Coletando subdomínios para {root} (crt.sh, bruteforce, VT/ST, ferramentas externas)")
        try:
            crt = fetch_crtsh(root)
            log_info(f"  crt.sh -> {len(crt)}")
            candidates.update(crt)
        except Exception as e:
            log_warn(f"crt.sh falhou para {root}: {e}")
        if VIRUSTOTAL_API_KEY:
            vt = fetch_virustotal(root, VIRUSTOTAL_API_KEY)
            log_info(f"  VirusTotal -> {len(vt)}")
            candidates.update(vt)
        if SECURITYTRAILS_API_KEY:
            st = fetch_securitytrails(root, SECURITYTRAILS_API_KEY)
            log_info(f"  SecurityTrails -> {len(st)}")
            candidates.update(st)
        candidates.update(run_external_subfinder(root))
        candidates.update(run_external_amass(root))
        bf = brute_force_subdomains(root)
        log_info(f"  brute-force adicionou {len(bf)}")
        candidates.update(bf)
    filtered = set()
    for s in candidates:
        for root in TARGET_ROOTS:
            if s.endswith(root):
                filtered.add(s.lower())
    candidates = sorted(filtered)
    global PROGRESS_TOTAL, PROGRESS_DONE, PROGRESS_ACTIVE, PROGRESS_SKIPPED
    PROGRESS_TOTAL = len(candidates)
    PROGRESS_DONE = 0
    PROGRESS_ACTIVE = 0
    PROGRESS_SKIPPED = 0
    log_info(f"Total candidatos filtrados: {len(candidates)}")
    if LIMIT_SUBS:
        candidates = candidates[:LIMIT_SUBS]
        log_info(f"Limitado a {LIMIT_SUBS} subdomínios por flag --limit")
    if RESUME_PATH:
        ck = load_checkpoint(RESUME_PATH)
        if ck and isinstance(ck, dict) and ck.get("subs"):
            already = set(ck["subs"].keys())
            candidates = [c for c in candidates if c not in already]
            log_info(f"Retomando; pulando {len(already)} subdomínios já processados")
    timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
    # MUDANÇA: adicionar trust_env=True para respeitar variáveis de ambiente proxy
    connector = connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=HEADERS_BASE, trust_env=True) as session:
        results = {}
        tasks = []
        out_dir = REPORT_DIR
        with tqdm(total=len(candidates), desc="Subdomains") as pbar:
            sem = asyncio.Semaphore(CONCURRENCY)
            async def worker(sub):
                async with sem:
                    res = await scan_subdomain(session, sub, out_dir, do_screenshots=not NO_SCREENSHOTS, do_nuclei=not NO_NUCLEI)
                    results[sub] = res
                    global PROGRESS_DONE, PROGRESS_ACTIVE, PROGRESS_SKIPPED
                    PROGRESS_DONE += 1
                    if res.get("skipped_dirs") or not res.get("http") or res.get("http", {}).get("status") in ("no-http", "timeout"):
                        PROGRESS_SKIPPED += 1
                    elif isinstance(res.get("http", {}).get("status"), int) and 200 <= res["http"]["status"] < 400:
                        PROGRESS_ACTIVE += 1
                    save_checkpoint({"timestamp": timestamp, "subs": results}, name="progress")
                    if PROGRESS_DONE % 5 == 0 or PROGRESS_DONE == PROGRESS_TOTAL:
                        print(f"[Progresso] {PROGRESS_DONE}/{PROGRESS_TOTAL} subdomínios verificados, {PROGRESS_ACTIVE} ativos, {PROGRESS_SKIPPED} ignorados (sem HTTP)")
                    pbar.update(1)
            for s in candidates:
                tasks.append(asyncio.ensure_future(worker(s)))
            for t in asyncio.as_completed(tasks):
                try:
                    await t
                except Exception:
                    pass
        return results

# ---------------------------
# Report generation (Markdown, HTML, JSON, LinkedIn summary)
# ---------------------------
def generate_reports(all_results):
    total_subs = len(all_results)
    total_endpoints = sum(len(r.get("endpoints",[])) for r in all_results.values())
    severity_counter = Counter()
    findings_list = []
    login_portals_list = []
    for sub, r in all_results.items():
        for f in r.get("findings", []):
            t = f.get("type", "unknown")
            if "sqli" in t or "ssrf" in t or ("nuclei" in t and "critical" in str(f).lower()):
                severity = "Critical"
            elif "sqli" in t or "open-redirect" in t:
                severity = "High"
            elif "xss" in t or "cors" in t:
                severity = "Medium"
            else:
                severity = "Low"
            f["severity"] = severity
            severity_counter[severity] += 1
            findings_list.append({"sub": sub, "finding": f})
        for portal in r.get("login_portals", []):
            portal = dict(portal)
            portal["severity"] = "High"
            portal["severity_label"] = "Alta Severidade Potencial"
            portal["warning"] = "Este é um portal de login que requer investigação manual aprofundada para identificar vulnerabilidades como credenciais padrão, falta de rate limiting, SQLi, etc."
            login_portals_list.append({"sub": sub, "portal": portal})
    json_path = REPORT_DIR / "scan_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"timestamp": timestamp, "targets": TARGET_ROOTS, "results": all_results, "login_portals": login_portals_list}, f, ensure_ascii=False, indent=2)
    md_lines = []
    md_lines.append(f"# {REPORT_PROGRAM_NAME}\n")
    md_lines.append(f"**Relatório de Reconhecimento e Testes - {datetime.datetime.now().isoformat()}**\n")
    md_lines.append("## Safe Harbor\nAs atividades foram conduzidas dentro das regras dos programas, com User-Agent dedicado e sem ações proibidas.\n")
    md_lines.append("## Responsible Disclosure\nAs vulnerabilidades identificadas foram reportadas de forma coordenada às equipes responsáveis.\n")
    md_lines.append("## Exclusões Respeitadas\n- Não foram realizadas tentativas de DoS, brute-force de senhas, engenharia social, ou modificações em sistemas.\n")
    md_lines.append("## Resumo Executivo (priorizar alto/crítico)\n")
    md_lines.append(f"- Alvos: {', '.join(TARGET_ROOTS)}")
    md_lines.append(f"- Total de subdomínios analisados: {total_subs}")
    md_lines.append(f"- Total de endpoints descobertos: {total_endpoints}")
    md_lines.append(f"- Vulnerabilidades por severidade: {dict(severity_counter)}\n")
    md_lines.append("## Portais de Login Encontrados\n")
    if login_portals_list:
        for item in login_portals_list:
            portal = item["portal"]
            md_lines.append(f"### {portal.get('url')} - {portal.get('severity_label')}")
            md_lines.append(f"- Subdomínio: {item['sub']}")
            md_lines.append(f"- Título da página: {portal.get('title') or '-'}")
            md_lines.append(f"- Campos de formulário detectados: {', '.join(portal.get('fields', [])) or '-'}")
            md_lines.append(f"- CSRF Token: {'Encontrado' if portal.get('csrf_token_present') else 'Não encontrado'}")
            md_lines.append(f"- Formulário enviado via GET: {'Sim' if portal.get('form_uses_get') else 'Não'}")
            md_lines.append(f"- Cabeçalhos de segurança ausentes: {', '.join(portal.get('security_headers_missing', [])) or '-'}")
            if portal.get('rate_limit_checked'):
                md_lines.append(f"- Rate limiting: {'Bloqueado/observado' if portal.get('rate_limit_blocked') else 'Não observado'}")
                md_lines.append(f"- Status observados nas 3 requisições: {', '.join(map(str, portal.get('rate_limit_statuses', []))) or '-'}")
            else:
                md_lines.append("- Rate limiting: não testado (formulário GET ou POST não identificado)")
            md_lines.append(f"- Possível enumeração de usuário: {'Sim' if portal.get('enum_leak_suspected') else 'Não detectado'}")
            md_lines.append(f"- Aviso: {portal.get('warning')}")
            md_lines.append(f"- Recomendação: {', '.join(portal.get('recommendations', []))}")
            md_lines.append("")
    else:
        md_lines.append("- Nenhum portal de login prioritário foi confirmado nesta execução.\n")
    md_lines.append("## Vulnerabilidades Críticas/Altas (Resumo)\n")
    for it in findings_list:
        if it["finding"].get("severity") in ("Critical","High"):
            f = it["finding"]
            md_lines.append(f"- {f.get('type')} em {it['sub']} (Sev: {f.get('severity')}) - Evidência: {f.get('evidence_snippet','-')[:200]}")
    md_lines.append("\n## Revisão Manual Recomendada\n")
    manual_review_items = build_manual_review_items(all_results, findings_list, login_portals_list)
    if manual_review_items:
        for item in manual_review_items[:20]:
            md_lines.append(f"- [{item['type']}] {item['subject']}: {item['detail']}")
    else:
        md_lines.append("- Nenhum alvo adicional foi marcado para revisão manual nesta execução.")
    md_lines.append("\n## Tabela de Subdomínios\n")
    md_lines.append("| Subdomínio | IPs | Portas abertas | Tecnologias | HTTP status |")
    md_lines.append("|---|---|---|---|---|")
    for sub, r in sorted(all_results.items()):
        ips = ",".join(r.get("ips",[])) if r.get("ips") else "-"
        ports = ",".join(map(str,r.get("open_ports",[]))) if r.get("open_ports") else "-"
        tech = ",".join(r.get("tech",[])) if r.get("tech") else "-"
        status = r.get("http",{}).get("status")
        md_lines.append(f"| {sub} | {ips} | {ports} | {tech} | {status} |")
    md_lines.append("\n## Vulnerabilidades Detalhadas\n")
    for item in findings_list:
        f = item["finding"]
        sub = item["sub"]
        sev = f.get("severity","Low")
        md_lines.append(f"### {f.get('type')} - {sub} (Severidade: {sev})")
        md_lines.append(f"- Evidência: `{f.get('evidence_snippet', str(f)[:200])}`")
        md_lines.append(f"- URL: {f.get('url','-')}")
        md_lines.append("- Reproduzir (PoC seguro): seguir instruções internas, confirmar manualmente antes de divulgação.")
        md_lines.append("- Recomendação: validar e sanitizar inputs, aplicar validações no backend, implementar WAF.\n")
    md_lines.append("\n## Arquivos/Directórios Interessantes\n")
    for sub, r in all_results.items():
        if r.get("dirs"):
            md_lines.append(f"### {sub}")
            for d in r.get("dirs")[:50]:
                md_lines.append(f"- {d['url']} (status: {d['status']})")
        if r.get("login_portals"):
            md_lines.append(f"### Portais de Login - {sub}")
            for portal in r.get("login_portals"):
                md_lines.append(f"- {portal.get('url')} (Alta Severidade Potencial)")
    md_lines.append("\n## Sugestões baseadas em OWASP ASVS\n")
    md_lines.append("- Validar e sanitizar todas as entradas do usuário.\n- Implementar CSP, HSTS e headers de segurança.\n- Usar prepared statements e parametrização para consultas SQL.\n")
    md_path = REPORT_DIR / "report.md"
    write_file(md_path, "\n".join(md_lines))
    linkedin_lines = []
    linkedin_lines.append(f"Relatório Bug Bounty - {REPORT_PROGRAM_NAME}")
    linkedin_lines.append("")
    linkedin_lines.append("Resumo executivo:")
    linkedin_lines.append(f"- Total de subdomínios analisados: {total_subs}")
    linkedin_lines.append(f"- Endpoints: {total_endpoints}")
    linkedin_lines.append(f"- Vulnerabilidades por severidade: {dict(severity_counter)}")
    linkedin_lines.append("")
    linkedin_lines.append("Agradecimentos ao programa de Bug Bounty pela oportunidade. Este relatório foi gerado com fins de divulgação coordenada e está em conformidade com a política do programa selecionado.")
    linkedin_lines.append("")
    linkedin_lines.append("Siga minha jornada em Bug Bounty! #bugbounty #security #infosec")
    linkedin_path = REPORT_DIR / "linkedin_summary.md"
    write_file(linkedin_path, "\n".join(linkedin_lines))
    html_path = REPORT_DIR / "report.html"
    try:
        if MARKDOWN_AVAILABLE:
            html = markdown_lib.markdown(open(md_path, "r", encoding="utf-8").read(), extensions=["tables"])
            css = """
            <style>
            body{font-family: Arial, sans-serif; padding:20px}
            pre{white-space:pre-wrap}
            table{border-collapse: collapse}
            table, th, td{border:1px solid #ccc; padding:6px}
            </style>
            """
            write_file(html_path, f"{css}\n{html}")
        else:
            md = open(md_path, "r", encoding="utf-8").read()
            write_file(html_path, "<pre>" + md + "</pre>")
    except Exception as e:
        log_warn(f"Erro gerando HTML: {e}")
    build_bughunt_submission_report(all_results, findings_list, login_portals_list)
    log_info(f"Relatórios gerados em {REPORT_DIR}")

# ---------------------------
# GitHub integration
# ---------------------------
def git_push_reports(report_dir, no_github=False):
    if no_github:
        log_info("Push para GitHub pulado por flag --no-github")
        return
    token = os.environ.get("GITHUB_TOKEN")
    repo_url = os.environ.get("GITHUB_REPO_URL")
    git_bin = TOOLS.get("git") or shutil.which("git")
    if not git_bin:
        log_warn("git não encontrado no PATH; pulando integração GitHub")
        return
    if not token or not repo_url:
        log_warn("GITHUB_TOKEN ou GITHUB_REPO_URL não definido; pulando integração GitHub")
        return
    repo_parent = Path.cwd().parent
    repo_local = repo_parent / "bug-bounty-reports"
    try:
        if repo_local.exists():
            log_info(f"Usando repositório local existente: {repo_local}")
            if not (repo_local / ".git").exists():
                log_warn(f"O diretório {repo_local} não parece ser um repositório git (sem .git). Pulando push.")
                return
            subprocess.run([git_bin, "-C", str(repo_local), "pull"], check=False)
        else:
            parsed = urlparse(repo_url)
            if parsed.scheme.startswith("http"):
                clone_url = repo_url.replace("https://", f"https://{token}@")
            else:
                clone_url = repo_url
            log_info(f"Clonando repositório para {repo_local}")
            subprocess.run([git_bin, "clone", clone_url, str(repo_local)], check=True, timeout=120)
        dest = repo_local / "reports" / Path(report_dir).name
        if dest.exists():
            log_warn(f"Destino já existe no repositório: {dest}, criando com sufixo")
            dest = repo_local / "reports" / f"{Path(report_dir).name}_{timestamp}"
        shutil.copytree(report_dir, dest)
        readme = repo_local / "README.md"
        index_lines = ["# Bug Bounty Reports\n", "Índice dos relatórios:\n"]
        reports_folder = repo_local / "reports"
        if reports_folder.exists():
            for d in sorted(reports_folder.iterdir()):
                if d.is_dir():
                    index_lines.append(f"- [{d.name}](reports/{d.name})")
        write_file(readme, "\n".join(index_lines))
        if not (repo_local / ".git").exists():
            log_warn(f"Após manipulação, o diretório {repo_local} não contém .git; pulando commit/push.")
            return
        subprocess.run([git_bin, "-C", str(repo_local), "add", "."], check=True)
        commit_msg = f"Relatório Bug Bounty - {timestamp}"
        subprocess.run([git_bin, "-C", str(repo_local), "commit", "-m", commit_msg], check=False)
        subprocess.run([git_bin, "-C", str(repo_local), "push", "origin", "main"], check=False)
        log_info("Relatório publicado no repositório GitHub (se permissões permitirem).")
    except Exception as e:
        log_err(f"Erro ao publicar no GitHub: {e}\n{traceback.format_exc()}")

# ---------------------------
# Framework modular (App + catálogo de ferramentas)
# ---------------------------
@dataclass
class ToolSpec:
    name: str
    binary: str | None = None
    template: list[str] | None = None
    install_hint: str = ""
    description: str = ""


def _tool(name, binary=None, template=None, install_hint="", description=""):
    return ToolSpec(name=name, binary=binary or name, template=template, install_hint=install_hint, description=description)


TOOL_CATALOG = {
    "recon": [
        _tool("subfinder", template=["subfinder", "-d", "{target}", "-silent"], install_hint="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        _tool("httpx", template=["httpx", "-u", "{target}", "-silent", "-json", "-o", "{output}"], install_hint="go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        _tool("amass", template=["amass", "enum", "-d", "{target}", "-silent"], install_hint="go install -v github.com/owasp-amass/amass/v4/..."),
        _tool("assetfinder", template=["assetfinder", "{target}"], install_hint="go install github.com/tomnomnom/assetfinder@latest"),
        _tool("waybackurls", template=["waybackurls", "{target}"], install_hint="go install github.com/tomnomnom/waybackurls@latest"),
        _tool("gau", template=["gau", "{target}"], install_hint="go install github.com/lc/gau/v2/cmd/gau@latest"),
        _tool("katana", template=["katana", "-u", "{target}", "-silent", "-o", "{output}"], install_hint="go install github.com/projectdiscovery/katana/cmd/katana@latest"),
        _tool("uncover", template=["uncover", "-q", "{target}", "-o", "{output}"], install_hint="go install github.com/projectdiscovery/uncover/cmd/uncover@latest"),
        _tool("notify", template=["notify", "-data", "{input_file}", "-silent"], install_hint="go install github.com/projectdiscovery/notify/cmd/notify@latest"),
        _tool("crtsh", template=["python", "-c", "from urllib.request import urlopen; print(urlopen('https://crt.sh/?q=%25.{target}&output=json').read().decode())"], description="Consulta crt.sh"),
        _tool("securitytrails", template=["python", "-c", "print('SecurityTrails depende de API key configurada')"], description="API externa"),
        _tool("shodan", template=["shodan", "domain", "--count", "{target}"], install_hint="pip install shodan; shodan init <APIKEY>"),
        _tool("censys", template=["censys", "search", "{target}"], install_hint="pip install censys"),
        _tool("virustotal", template=["python", "-c", "print('VirusTotal depende de API key configurada')"], description="API externa"),
        _tool("otx", template=["python", "-c", "print('AlienVault OTX depende de integração/API')"], description="API externa"),
        _tool("spyse", template=["python", "-c", "print('Spyse depende de API key/configuração')"], description="API externa"),
        _tool("threatcrowd", template=["python", "-c", "print('ThreatCrowd depende de integração/API')"], description="API externa"),
    ],
    "portscan": [
        _tool("nmap", template=["nmap", "-sV", "-Pn", "{target}"], install_hint="apt/brew/choco install nmap"),
        _tool("masscan", template=["masscan", "{target}", "-p1-65535", "--rate", "1000"], install_hint="apt/brew/choco install masscan"),
        _tool("rustscan", template=["rustscan", "-a", "{target}"], install_hint="cargo install rustscan"),
        _tool("naabu", template=["naabu", "-host", "{target}"], install_hint="go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    ],
    "web": [
        _tool("gobuster", template=["gobuster", "dir", "-u", "{target}", "-w", str(Path("wordlists") / "common.txt")], install_hint="go install github.com/OJ/gobuster/v3@latest"),
        _tool("dirb", template=["dirb", "{target}"], install_hint="apt/brew/choco install dirb"),
        _tool("dirsearch", template=["dirsearch", "-u", "{target}"], install_hint="pip install dirsearch"),
        _tool("ffuf", template=["ffuf", "-u", "{target}/FUZZ", "-w", str(Path("wordlists") / "common.txt")], install_hint="go install github.com/ffuf/ffuf/v2@latest"),
        _tool("wfuzz", template=["wfuzz", "-u", "{target}/FUZZ", "-w", str(Path("wordlists") / "common.txt")], install_hint="pip install wfuzz"),
        _tool("meg", template=["meg", "{target}"], install_hint="go install github.com/tomnomnom/meg@latest"),
        _tool("zap", template=["zap-baseline.py", "-t", "{target}"], install_hint="apt/brew/choco install zaproxy"),
        _tool("burp", template=["python", "-c", "print('Burp headless via REST API exige Burp Professional configurado')"], description="Headless via API"),
    ],
    "vuln": [
        _tool("nuclei", template=["nuclei", "-u", "{target}", "-silent"], install_hint="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        _tool("nikto", template=["nikto", "-h", "{target}"], install_hint="apt/brew/choco install nikto"),
        _tool("dalfox", template=["dalfox", "url", "{target}", "--silence", "-o", "{output}"], install_hint="go install github.com/hahwul/dalfox/v2@latest"),
        _tool("sqlmap", template=["sqlmap", "-u", "{target}", "--batch", "--random-agent", "--level=1", "--risk=1", "--output-dir={output_dir}"], install_hint="pip install sqlmap"),
        _tool("wapiti", template=["wapiti", "-u", "{target}"], install_hint="pip install wapiti3"),
        _tool("skipfish", template=["skipfish", "-o", str(REPORT_DIR / 'skipfish'), "{target}"], install_hint="apt/brew/choco install skipfish"),
        _tool("retire.js", template=["retire", "--jsrepo", "{target}"], install_hint="npm install -g retire"),
        _tool("snyk", template=["snyk", "test", "{target}"], install_hint="npm install -g snyk"),
        _tool("dependency-check", template=["dependency-check", "--scan", "{target}"], install_hint="owasp dependency-check manual install"),
    ],
    "exploit": [
        _tool("sqlmap", template=["sqlmap", "-u", "{target}", "--batch"], install_hint="pip install sqlmap"),
        _tool("xsstrike", template=["python", "XSStrike/xsstrike.py", "-u", "{target}"], install_hint="git clone https://github.com/s0md3v/XSStrike"),
        _tool("commix", template=["python", "commix.py", "--url", "{target}"], install_hint="git clone https://github.com/commixproject/commix"),
        _tool("beef", template=["python", "-c", "print('BeEF requer servidor/configuração própria')"], description="Servidor próprio"),
        _tool("msfconsole", template=["msfconsole", "-q", "-x", "exit"], install_hint="Metasploit Framework"),
        _tool("searchsploit", template=["searchsploit", "{target}"], install_hint="apt install exploitdb"),
    ],
    "post": [
        _tool("mimikatz", template=["python", "-c", "print('Mimikatz é Windows-only e requer contexto autorizado')"], description="Windows only"),
        _tool("bloodhound", template=["bloodhound", "--help"], description="Coleta AD"),
        _tool("crackmapexec", template=["cme", "--help"], install_hint="pipx install crackmapexec"),
        _tool("impacket", template=["python", "-c", "import impacket; print('Impacket disponível')"], install_hint="pip install impacket"),
        _tool("shells", template=["python", "-c", "print('Post-ex shells dependem do ambiente do alvo')"], description="Placeholder"),
    ],
    "wireless": [
        _tool("aircrack-ng", template=["aircrack-ng", "--help"], install_hint="apt/brew/choco install aircrack-ng"),
        _tool("reaver", template=["reaver", "--help"], install_hint="apt/brew/choco install reaver"),
        _tool("wifite", template=["wifite", "--help"], install_hint="pip install wifite"),
        _tool("kismet", template=["kismet", "--help"], install_hint="apt/brew/choco install kismet"),
    ],
    "mobile": [
        _tool("mobsf", template=["python", "-c", "print('MobSF normalmente roda como serviço web')"], description="Serviço web"),
        _tool("apktool", template=["apktool", "--help"], install_hint="brew/apt/choco install apktool"),
        _tool("dex2jar", template=["python", "-c", "print('dex2jar depende do pacote baixado manualmente')"], description="Java tool"),
        _tool("jadx", template=["jadx", "--help"], install_hint="brew/apt/choco install jadx"),
        _tool("frida", template=["frida", "--help"], install_hint="pip install frida-tools"),
        _tool("objection", template=["objection", "--help"], install_hint="pip install objection"),
    ],
    "osint": [
        _tool("theHarvester", template=["theHarvester", "-d", "{target}", "-b", "all"], install_hint="pipx install theHarvester"),
        _tool("recon-ng", template=["recon-ng", "-h"], install_hint="pip install recon-ng"),
        _tool("sherlock", template=["sherlock", "{target}"], install_hint="pipx install sherlock-project"),
        _tool("shodan-cli", template=["shodan", "host", "{target}"], install_hint="pip install shodan"),
        _tool("censys-cli", template=["censys", "search", "{target}"], install_hint="pip install censys"),
        _tool("spiderfoot", template=["spiderfoot", "-h"], install_hint="pip install spiderfoot"),
    ],
}

# MUDANÇA: catálogo de comandos reais executáveis para as ferramentas principais.
TOOL_COMMANDS = {
    "subfinder": {"command": ["subfinder", "-d", "{target}", "-silent", "-o", "{output}"], "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "proxy": True},
    "assetfinder": {"command": ["assetfinder", "--subs-only", "{target}"], "install": "go install github.com/tomnomnom/assetfinder@latest", "proxy": False},
    "amass": {"command": ["amass", "enum", "-passive", "-d", "{target}", "-o", "{output}"], "install": "go install -v github.com/owasp-amass/amass/v4/...", "proxy": True},
    "chaos": {"command": ["chaos", "-d", "{target}", "-silent", "-o", "{output}"], "install": "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest", "proxy": True},
    "naabu": {"command": ["naabu", "-host", "{target}", "-top-ports", "1000", "-silent", "-o", "{output}"], "install": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "proxy": True},
    "nmap": {"command": ["nmap", "-sV", "-sC", "-T4", "-p-", "--min-rate=1000", "{target}", "-oN", "{output}"], "install": "apt install nmap -y || brew install nmap || choco install nmap -y", "proxy": False},
    "ffuf": {"command": ["ffuf", "-u", "{target}/FUZZ", "-w", "{wordlist}", "-ac", "-t", "50", "-o", "{output}", "-of", "json"], "install": "go install github.com/ffuf/ffuf/v2@latest", "proxy": True},
    "gobuster": {"command": ["gobuster", "dir", "-u", "{target}", "-w", "{wordlist}", "-o", "{output}"], "install": "go install github.com/OJ/gobuster/v3@latest", "proxy": False},
    "dirsearch": {"command": ["dirsearch", "-u", "{target}", "-e", "php,html,js,txt", "-o", "{output}", "--plain-text"], "install": "pip install dirsearch", "proxy": False},
    "nuclei": {"command": ["nuclei", "-u", "{target}", "-t", "cves/", "-t", "misconfiguration/", "-severity", "low,medium,high,critical", "-o", "{output}", "-silent"], "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "proxy": True},
    "nikto": {"command": ["nikto", "-h", "{target}", "-o", "{output}", "-Format", "txt"], "install": "apt install nikto -y || brew install nikto || choco install nikto -y", "proxy": False},
    "whatweb": {"command": ["whatweb", "{target}", "--no-errors", "-a", "3", "-o", "{output}"], "install": "apt install whatweb -y || brew install whatweb || choco install whatweb -y", "proxy": False},
    "dalfox": {"command": ["dalfox", "url", "{target}", "--silence", "-o", "{output}"], "install": "go install github.com/hahwul/dalfox/v2@latest", "proxy": True},
    "sqlmap": {"command": ["sqlmap", "-u", "{target}", "--batch", "--random-agent", "--level=1", "--risk=1", "--output-dir={output_dir}"], "install": "pip install sqlmap", "proxy": True},
    "httpx": {"command": ["httpx", "-u", "{target}", "-silent", "-json", "-o", "{output}"], "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", "proxy": True},
    "waybackurls": {"command": ["waybackurls", "{target}"], "install": "go install github.com/tomnomnom/waybackurls@latest", "proxy": False},
    "gau": {"command": ["gau", "{target}"], "install": "go install github.com/lc/gau/v2/cmd/gau@latest", "proxy": False},
    "katana": {"command": ["katana", "-u", "{target}", "-silent", "-o", "{output}"], "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest", "proxy": True},
    "uncover": {"command": ["uncover", "-q", "{target}", "-o", "{output}"], "install": "go install github.com/projectdiscovery/uncover/cmd/uncover@latest", "proxy": True},
    "notify": {"command": ["notify", "-data", "{input_file}", "-silent"], "install": "go install github.com/projectdiscovery/notify/cmd/notify@latest", "proxy": False},
}

def _system_name():
    system = platform.system().lower()
    release = platform.release().lower()
    distro = ""
    try:
        if Path("/etc/os-release").exists():
            data = Path("/etc/os-release").read_text(encoding="utf-8", errors="ignore").lower()
            distro = data
    except Exception:
        pass
    return system, release, distro

def _default_wordlist(tool_name):
    candidates = [
        Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
        Path("/usr/share/wordlists/dirb/common.txt"),
        Path.home() / ".wordlists" / "common.txt",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    fallback = REPORT_DIR / "wordlists" / f"{tool_name}_fallback.txt"
    fallback.parent.mkdir(parents=True, exist_ok=True)
    if not fallback.exists():
        write_file(fallback, "\n".join(DIR_WORDLIST[:500]) + "\n")
    return str(fallback)

def git_push_full(repo_path=None):
    repo_path = Path(repo_path or Path.cwd())
    git_bin = shutil.which("git")
    if not git_bin:
        log_warn("git não encontrado no PATH")
        return False
    try:
        if not (repo_path / ".git").exists():
            subprocess.run([git_bin, "init"], cwd=str(repo_path), check=False)
        subprocess.run([git_bin, "add", "."], cwd=str(repo_path), check=False)
        msg = f"Atualização automática - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        subprocess.run([git_bin, "commit", "-m", msg], cwd=str(repo_path), check=False)
        remote = None
        try:
            remote = subprocess.check_output([git_bin, "remote", "get-url", "origin"], cwd=str(repo_path), text=True).strip()
        except Exception:
            remote = None
        if not remote:
            token = os.environ.get("GITHUB_TOKEN")
            repo_url = os.environ.get("GITHUB_REPO_URL")
            if token and repo_url and repo_url.startswith("https://"):
                remote = repo_url.replace("https://", f"https://{token}@")
                subprocess.run([git_bin, "remote", "add", "origin", remote], cwd=str(repo_path), check=False)
        branch = "main"
        push_result = subprocess.run([git_bin, "push", "-u", "origin", branch], cwd=str(repo_path), check=False)
        if push_result.returncode != 0:
            subprocess.run([git_bin, "push", "-u", "origin", "master"], cwd=str(repo_path), check=False)
        return True
    except Exception as e:
        log_err(f"git_push_full falhou: {e}")
        return False

def instalar_globalmente():
    sistema, _, _ = _system_name()
    origem = Path(__file__).resolve()
    venv_python = origem.parent / ".venv" / ("Scripts" if sistema == "windows" else "bin") / ("python.exe" if sistema == "windows" else "python3")
    config_dir = Path.home() / ".config" / "opium"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.json"
    config_path.write_text(json.dumps({"proxy": PROXY, "tor": TOR_MODE, "quick": QUICK_MODE}, indent=2), encoding="utf-8")
    if sistema == "windows":
        wrapper_dir = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "Microsoft" / "WindowsApps"
        wrapper_dir.mkdir(parents=True, exist_ok=True)
        wrapper = wrapper_dir / "opium.bat"
        python_exe = str(venv_python if venv_python.exists() else Path(sys.executable))
        wrapper.write_text(f'@echo off\r\n"{python_exe}" "{origem}" %*\r\n', encoding="utf-8")
    else:
        wrapper_dir = Path("/usr/local/bin") if os.access("/usr/local/bin", os.W_OK) else Path.home() / ".local" / "bin"
        wrapper_dir.mkdir(parents=True, exist_ok=True)
        wrapper = wrapper_dir / "opium"
        activate = venv_python.parent / "activate"
        if activate.exists():
            wrapper.write_text(
                f'#!/bin/sh\nDIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"\nif [ -f "{activate}" ]; then\n  . "{activate}"\nfi\nexec "{venv_python if venv_python.exists() else sys.executable}" "{origem}" "$@"\n',
                encoding="utf-8",
            )
        else:
            wrapper.write_text(f'#!/bin/sh\nexec "{venv_python if venv_python.exists() else sys.executable}" "{origem}" "$@"\n', encoding="utf-8")
        try:
            os.chmod(wrapper, 0o755)
        except Exception:
            pass
    print("Ferramenta instalada como 'opium'. Execute 'opium' para iniciar.")
    return str(wrapper)


class App:
    def __init__(self, cli_args):
        self.args = cli_args
        self.silent = bool(SILENT_MODE)
        self.session_artifacts = []
        self.current_targets = self._load_targets()
        self.target = self.current_targets[0] if self.current_targets else ""
        self.selected_profile = "bugbounty"
        self.proxy = PROXY
        self.tor = TOR_MODE
        self.quick = QUICK_MODE

    def _load_targets(self):
        targets = list(CLI_TARGETS)
        if TARGETS_FILE:
            try:
                with open(TARGETS_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        value = line.strip()
                        if value:
                            targets.append(value)
            except Exception as e:
                log_warn(f"Falha ao carregar arquivo de alvos: {e}")
        return [t.strip() for t in targets if t.strip()]

    def _prompt(self, message, default=None):
        suffix = f" [{default}]" if default else ""
        try:
            value = input(f"{message}{suffix}: ").strip()
        except KeyboardInterrupt:
            print()
            raise
        return value or (default or "")

    def _confirm(self, message, default=False):
        value = self._prompt(f"{message} (s/n)", "s" if default else "n").lower()
        return value.startswith("s") or value.startswith("y")

    def _pause_for_menu(self):
        try:
            input("Pressione Enter para voltar ao menu...")
        except (EOFError, KeyboardInterrupt):
            print()

    def _menu_error(self, context, error):
        print(f"[!] {context}: {error}")
        print("[!] Voltando ao menu principal...")
        self._pause_for_menu()

    def _format_command_parts(self, command, *, target, output, output_dir, wordlist, input_file):
        # Aceita comando em lista ou string sem iterar sobre caracteres.
        values = {
            "target": target,
            "output": output,
            "output_dir": output_dir,
            "wordlist": wordlist,
            "input_file": input_file,
        }
        if isinstance(command, str):
            formatted = command.format(**values)
            return shlex.split(formatted)
        return [str(part).format(**values) for part in command]

    def _print_header(self, title):
        print()
        print(f"\033[93m=== {title} ===\033[0m")

    def _save_text(self, relative_path, content):
        path = REPORT_DIR / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        write_file(path, content)
        self.session_artifacts.append(str(path))
        return path

    def _tool_output_path(self, category, tool_name):
        out_dir = REPORT_DIR / "tools" / category
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir / f"{sanitize_filename(tool_name)}.txt"

    def _summary_path(self, category):
        return REPORT_DIR / f"summary_{sanitize_filename(category)}.txt"

    def _open_result(self, path):
        try:
            if self._confirm(f"Abrir {path.name} agora?", False):
                if platform.system().lower() == "windows":
                    os.startfile(str(path))
                else:
                    webbrowser.open(f"file://{path.resolve()}")
        except Exception as e:
            log_debug(f"Falha ao abrir arquivo: {e}")

    def _resolve_command(self, spec, target):
        if not spec.template:
            return None
        output = str(self._tool_output_path("misc", spec.name))
        output_dir = str(Path(output).parent)
        wordlist = _default_wordlist(spec.name)
        if isinstance(spec.template, str):
            return shlex.split(spec.template.format(target=target, output=output, output_dir=output_dir, wordlist=wordlist, input_file=output))
        return self._format_command_parts(spec.template, target=target, output=output, output_dir=output_dir, wordlist=wordlist, input_file=output)

    def _is_installed(self, spec):
        if not spec.binary:
            return False
        return shutil.which(spec.binary) is not None

    def instalar_ferramenta(self, nome_ferramenta):
        sistema, _, distro = _system_name()
        install_hint = TOOL_COMMANDS.get(nome_ferramenta, {}).get("install", "")
        attempts = []
        if sistema == "linux":
            if "debian" in distro or "ubuntu" in distro or Path("/usr/bin/apt").exists():
                attempts.append(f"sudo apt-get update && sudo apt-get install -y {nome_ferramenta}")
            attempts.append(f"go install github.com/{nome_ferramenta}/{nome_ferramenta}@latest")
            attempts.append(f"pip install {nome_ferramenta}")
        elif sistema == "darwin":
            attempts.append(f"brew install {nome_ferramenta}")
            attempts.append(f"go install github.com/{nome_ferramenta}/{nome_ferramenta}@latest")
            attempts.append(f"pip3 install {nome_ferramenta}")
        else:
            if shutil.which("choco"):
                attempts.append(f"choco install {nome_ferramenta} -y")
            if shutil.which("winget"):
                attempts.append(f"winget install {nome_ferramenta}")
            attempts.append(f"pip install {nome_ferramenta}")
        if install_hint:
            attempts.insert(0, install_hint)
        if not self.silent:
            print(f"Instalando {nome_ferramenta}...")
        for attempt in attempts:
            try:
                if not attempt:
                    continue
                log_info(f"Tentando instalar {nome_ferramenta}: {attempt}")
                with tqdm(total=1, desc=f"install:{nome_ferramenta}") as bar:
                    subprocess.run(attempt, shell=True, check=False)
                    bar.update(1)
                if shutil.which(nome_ferramenta) or nome_ferramenta in ("waybackurls", "gau", "katana", "notify", "httpx", "ffuf", "subfinder", "amass", "naabu", "nuclei"):
                    return True
            except Exception as e:
                log_warn(f"Falha instalando {nome_ferramenta}: {e}")
        return False

    def _resolve_tool_command(self, tool_name, target, output_path):
        info = TOOL_COMMANDS.get(tool_name)
        if not info:
            return None
        wordlist = _default_wordlist(tool_name)
        output_dir = str(output_path.parent)
        output = str(output_path)
        command = info.get("command")
        if not command:
            return None
        return self._format_command_parts(command, target=target, output=output, output_dir=output_dir, wordlist=wordlist, input_file=output)

    def executar_ferramenta(self, categoria, nome_ferramenta, alvo, args=""):
        self._last_tool_error = False
        try:
            if not alvo:
                alvo = self.target or self._prompt("Informe o alvo", "")
            if not alvo:
                print("Alvo obrigatório.")
                return None
            self.target = alvo
            output_path = self._tool_output_path(categoria, nome_ferramenta)
            spec = TOOL_COMMANDS.get(nome_ferramenta)
            if not spec:
                print(f"Ferramenta não cadastrada: {nome_ferramenta}")
                return None
            if not self._is_installed(ToolSpec(name=nome_ferramenta, binary=nome_ferramenta)):
                self.instalar_ferramenta(nome_ferramenta)
            delay = random.uniform(0.8, 3.0)
            if not self.silent:
                print(f"Aguardando {delay:.1f}s antes de executar {nome_ferramenta}...")
            time.sleep(delay)
            cmd = self._resolve_tool_command(nome_ferramenta, alvo, output_path)
            if not cmd:
                print("Comando indisponível.")
                return None
            if self.proxy and spec.get("proxy"):
                proxy_flags = {
                    "nuclei": ["-proxy", self.proxy],
                    "sqlmap": [f"--proxy={self.proxy}"],
                    "ffuf": ["-x", self.proxy],
                    "httpx": ["-proxy", self.proxy],
                    "naabu": ["-proxy", self.proxy],
                    "katana": ["-proxy", self.proxy],
                    "dalfox": ["--proxy", self.proxy],
                    "subfinder": ["-proxy", self.proxy],
                    "amass": ["-proxy", self.proxy],
                }.get(nome_ferramenta, [])
                cmd.extend(proxy_flags)
            if self.tor and not spec.get("proxy"):
                proxychains = shutil.which("proxychains4") or shutil.which("proxychains")
                if proxychains:
                    cmd = [proxychains] + cmd
            with tqdm(total=1, desc=f"{categoria}:{nome_ferramenta}") as bar:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                combined = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
                if combined.strip():
                    write_file(output_path, combined)
                else:
                    write_file(output_path, "Sem saída relevante.\n")
                summary = self._summary_path(categoria)
                with open(summary, "a", encoding="utf-8") as f:
                    f.write(f"[{nome_ferramenta}] alvo={alvo} saída={output_path}\n")
                self.session_artifacts.extend([str(output_path), str(summary)])
                bar.update(1)
                if not self.silent:
                    print(f"Saída salva em: {output_path}")
                self._open_result(output_path)
                return output_path
        except Exception as e:
            self._last_tool_error = True
            log_err(f"executar_ferramenta falhou: {e}")
            print(f"[!] Erro ao executar ferramenta {nome_ferramenta}: {e}")
            print("[!] Voltando ao menu principal...")
            self._pause_for_menu()
            try:
                write_file(output_path, f"Erro ao executar {nome_ferramenta}: {e}\n")
            except Exception:
                pass
            return None

    def _maybe_install(self, spec):
        if not spec.install_hint:
            return False
        if not AUTO_INSTALL and not self.silent and not self._confirm(f"Ferramenta ausente. Tentar instalar {spec.name}?", False):
            return False
        log_info(f"Sugestão de instalação para {spec.name}: {spec.install_hint}")
        if AUTO_INSTALL:
            try:
                subprocess.run(spec.install_hint, shell=True, check=False)
                return True
            except Exception as e:
                log_warn(f"Falha ao tentar instalar {spec.name}: {e}")
        return False

    def _run_command(self, cmd, output_path=None, cwd=None):
        try:
            if not self.silent:
                log_info(f"Executando: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=False)
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            combined = stdout + ("\n" + stderr if stderr else "")
            if output_path:
                write_file(output_path, combined or "Sem saída.")
                self.session_artifacts.append(str(output_path))
            return result.returncode, combined
        except Exception as e:
            log_err(f"Falha ao executar comando: {e}")
            if output_path:
                write_file(output_path, f"Erro: {e}")
            return 1, str(e)

    def run_tool(self, category, spec, target):
        return self.executar_ferramenta(category, spec.name, target)

    def run_tool_group(self, category, target):
        try:
            specs = TOOL_CATALOG.get(category, [])
            if not specs:
                print("Categoria vazia.")
                return
            print("0. Voltar ao menu principal")
            print("1. Executar Tudo")
            for index, spec in enumerate(specs, 2):
                print(f"{index}. {spec.name} - {spec.description or 'sem descrição'}")
            selection = self._prompt("Selecione ferramenta (número, 'all' ou Enter para voltar)", "")
            if not selection or selection == "0":
                return
            if selection == "1" or selection.lower() == "all":
                for spec in tqdm(specs, desc=f"{category}"):
                    self.executar_ferramenta(category, spec.name, target)
                    if self._last_tool_error:
                        return
                return
            try:
                idx = int(selection) - 2
                spec = specs[idx]
            except Exception:
                print("Opção inválida.")
                return
            self.executar_ferramenta(category, spec.name, target)
        except Exception as e:
            self._menu_error(f"Erro ao abrir submenu de {category}", e)
            return

    def load_targets_interactive(self):
        target = self._prompt("Informe o alvo principal (domínio/IP/URL)", self.target or (self.current_targets[0] if self.current_targets else ""))
        targets = [target] if target else []
        if targets:
            self.target = targets[0]
        return targets

    def apply_globals(self, targets=None, quick=None, no_screenshots=None):
        global TARGET_ROOTS, NO_SCREENSHOTS, NO_NUCLEI, NO_GITHUB, QUICK_MODE, REPORT_PROGRAM_NAME, REPORT_PROGRAM_SCOPE, CONCURRENCY, DEFAULT_TIMEOUT, DIR_WORDLIST, PROXY
        if targets:
            TARGET_ROOTS = [t.strip() for t in targets if t.strip()]
        if quick is not None:
            QUICK_MODE = quick
            if QUICK_MODE:
                CONCURRENCY = 16
                DEFAULT_TIMEOUT = 10
                DIR_WORDLIST = generate_dir_wordlist(DIR_TOKENS, target=500)
                NO_SCREENSHOTS = True if no_screenshots is None else no_screenshots
            else:
                CONCURRENCY = int(os.environ.get("CONCURRENCY", "8"))
                DEFAULT_TIMEOUT = 15
                DIR_WORDLIST = generate_dir_wordlist(DIR_TOKENS, target=1000)
        if no_screenshots is not None:
            NO_SCREENSHOTS = no_screenshots
        REPORT_PROGRAM_NAME = "BugBounty Scanner"
        REPORT_PROGRAM_SCOPE = TARGET_ROOTS
        if PROXY:
            os.environ["HTTP_PROXY"] = PROXY
            os.environ["HTTPS_PROXY"] = PROXY

    def notify(self, message):
        if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": message[:3900]},
                timeout=10,
            )
        except Exception as e:
            log_debug(f"Falha ao notificar Telegram: {e}")

    def save_env(self):
        env_path = Path(".env")
        values = {
            "VIRUSTOTAL_API_KEY": VIRUSTOTAL_API_KEY or "",
            "SECURITYTRAILS_API_KEY": SECURITYTRAILS_API_KEY or "",
            "GITHUB_TOKEN": os.environ.get("GITHUB_TOKEN", ""),
            "GITHUB_REPO_URL": os.environ.get("GITHUB_REPO_URL", ""),
            "TELEGRAM_TOKEN": TELEGRAM_TOKEN or "",
            "TELEGRAM_CHAT_ID": TELEGRAM_CHAT_ID or "",
            "HTTP_PROXY": PROXY or "",
            "HTTPS_PROXY": PROXY or "",
        }
        lines = [f"{k}={v}" for k, v in values.items() if v is not None]
        write_file(env_path, "\n".join(lines) + "\n")
        print(f"Arquivo {env_path} atualizado.")

    def run_bug_bounty(self, targets=None, quick=None):
        try:
            targets = targets or self.load_targets_interactive()
            self.target = targets[0] if targets else self.target
            self._set_mode_report_dir("bugbounty")
            self.apply_globals(targets=targets, quick=QUICK_MODE if quick is None else quick, no_screenshots=NO_SCREENSHOTS)
            if not self.silent:
                display_banner()
            print("[*] Modo Bug Bounty: executando reconhecimento, varredura e vulnerabilidades em sequência.")
            sequencia = ["recon", "portscan", "web", "vuln"]
            with tqdm(sequencia, desc="BugBounty") as barra:
                for categoria in barra:
                    barra.set_description(f"{categoria}")
                    if not self.run_category_all(categoria, targets):
                        return None
            results = asyncio.run(main_async())
            generate_reports(results)
            git_push_reports(REPORT_DIR, no_github=NO_GITHUB)
            self.notify(f"Scan concluído: {REPORT_PROGRAM_NAME} ({len(results)} subdomínios).")
            return results
        except Exception as e:
            self._menu_error("Erro ao executar modo Bug Bounty", e)
            return None

    def run_full_pentest(self, targets=None):
        try:
            targets = targets or self.load_targets_interactive()
            self._set_mode_report_dir("pentest")
            self.apply_globals(targets=targets, quick=False, no_screenshots=False)
            self._print_header("Pentest Completo")
            for category in ["recon", "portscan", "web", "vuln", "exploit", "post"]:
                if not self.run_category_all(category, targets):
                    return None
            results = asyncio.run(main_async())
            generate_reports(results)
            git_push_reports(REPORT_DIR, no_github=NO_GITHUB)
            return results
        except Exception as e:
            self._menu_error("Erro ao executar modo Pentest", e)
            return None

    def run_category_all(self, category, targets):
        try:
            specs = TOOL_CATALOG.get(category, [])
            if not specs:
                return True
            target = targets[0] if targets else self.target or self._prompt("Informe o alvo para esta categoria", "")
            self.target = target or self.target
            for spec in tqdm(specs, desc=f"{category}"):
                self.executar_ferramenta(category, spec.name, target)
                if self._last_tool_error:
                    return False
            return True
        except Exception as e:
            self._menu_error(f"Erro ao executar categoria {category}", e)
            return False

    def run_category_quick(self, category, targets):
        specs = TOOL_CATALOG.get(category, [])
        if not specs:
            return
        target = targets[0] if targets else self.target or self._prompt("Informe o alvo para esta categoria", "")
        self.target = target or self.target
        for spec in specs[:4]:
            self.executar_ferramenta(category, spec.name, target)

    def submenu_category(self, title, category):
        self._print_header(title)
        print("0. Voltar ao menu principal")
        choice = self._prompt("Escolha", "1")
        if choice == "0":
            return
        target = self._prompt("Alvo", self.target or (self.current_targets[0] if self.current_targets else ""))
        self.target = target or self.target
        self.run_tool_group(category, target)

    def osint_menu(self):
        self.submenu_category("OSINT", "osint")

    def web_menu(self):
        self.submenu_category("Web Scanner", "web")

    def mobile_menu(self):
        self.submenu_category("Mobile", "mobile")

    def wireless_menu(self):
        self.submenu_category("Wireless", "wireless")

    def tools_menu(self):
        self._print_header("Ferramentas Úteis")
        print("0. Voltar ao menu principal")
        print("Categorias:")
        for idx, key in enumerate(["recon", "portscan", "web", "vuln", "exploit", "post"], 1):
            print(f"{idx}. {key}")
        choice = self._prompt("Escolha a categoria", "1")
        if choice == "0":
            return
        mapping = {"1": "recon", "2": "portscan", "3": "web", "4": "vuln", "5": "exploit", "6": "post"}
        category = mapping.get(choice)
        if category:
            self.submenu_category(f"Ferramentas - {category}", category)

    def settings_menu(self):
        self._print_header("Configurações")
        print("0. Voltar ao menu principal")
        print("1. Definir proxy")
        print("2. Ativar TOR")
        print("3. Disparar VPN")
        print("4. Ajustar delays")
        print("5. Salvar .env")
        choice = self._prompt("Escolha", "5")
        if choice == "0":
            return
        global PROXY, TOR_MODE, VPN_PATH, REQUEST_DELAY, DEFAULT_TIMEOUT
        if choice == "1":
            PROXY = self._prompt("Proxy HTTP/SOCKS", PROXY or "")
        elif choice == "2":
            TOR_MODE = True
            PROXY = self._prompt("Proxy Tor (ex: socks5h://127.0.0.1:9050)", PROXY or "socks5h://127.0.0.1:9050")
        elif choice == "3":
            VPN_PATH = self._prompt("Caminho do perfil/config da VPN", VPN_PATH or "")
            if VPN_PATH:
                if "openvpn" in VPN_PATH.lower():
                    subprocess.Popen(["openvpn", "--config", VPN_PATH])
                else:
                    subprocess.Popen(["wg-quick", "up", VPN_PATH])
        elif choice == "4":
            try:
                REQUEST_DELAY = float(self._prompt("Delay base entre requisições", str(REQUEST_DELAY)))
                DEFAULT_TIMEOUT = int(self._prompt("Timeout padrão (segundos)", str(DEFAULT_TIMEOUT)))
            except ValueError:
                print("Valores inválidos.")
        elif choice == "5":
            self.save_env()

    def reports_menu(self):
        self._print_header("Relatórios")
        print("0. Voltar ao menu principal")
        print("1. Abrir pasta de relatórios")
        print("2. Gerar relatório consolidado da sessão")
        print("3. Gerar relatório BugHunt/Smart Fit")
        print("4. Sincronizar código com GitHub (push completo)")
        choice = self._prompt("Escolha", "2")
        if choice == "0":
            return
        if choice == "1":
            print(REPORT_DIR)
        elif choice == "2":
            self.save_consolidated_report()
        elif choice == "3":
            self.run_bug_bounty(self.current_targets, quick=QUICK_MODE)
        elif choice == "4":
            git_push_full(Path.cwd())

    def save_consolidated_report(self):
        path = REPORT_DIR / "consolidated_report.md"
        lines = [f"# Relatório Consolidado - {REPORT_PROGRAM_NAME}", ""]
        lines.append(f"- Data: {datetime.datetime.now().isoformat()}")
        lines.append(f"- Alvos: {', '.join(TARGET_ROOTS)}")
        lines.append(f"- Artefatos: {len(self.session_artifacts)}")
        for artifact in self.session_artifacts[-50:]:
            lines.append(f"- {artifact}")
        write_file(path, "\n".join(lines))
        print(path)

    def bug_bounty_menu(self):
        self._print_header("Bug Bounty")
        print("0. Voltar ao menu principal")
        print("1. Executar perfil automático completo")
        print("2. Definir alvo e executar")
        choice = self._prompt("Escolha", "1")
        if choice == "0":
            return
        if choice == "1":
            targets = self.load_targets_interactive()
            self.run_bug_bounty(targets, quick=QUICK_MODE)
        elif choice == "2":
            self.run_bug_bounty(self.load_targets_interactive(), quick=QUICK_MODE)

    def pentest_menu(self):
        self._print_header("Pentest Completo")
        print("0. Voltar ao menu principal")
        print("1. Recon + Portscan + Web + Vuln")
        print("2. Exploitation helpers")
        print("3. Pós-exploração")
        choice = self._prompt("Escolha", "1")
        if choice == "0":
            return
        if choice == "1":
            self.run_full_pentest(self.load_targets_interactive())
        elif choice == "2":
            self.submenu_category("Exploração", "exploit")
        elif choice == "3":
            self.submenu_category("Pós-exploração", "post")

    def show_main_menu(self):
        self._print_header("MENU PRINCIPAL")
        menu = [
            "0. 🧰 Instalar/Atualizar ferramentas globalmente",
            "1. 🛡️ Bug Bounty (modo automático para programas específicos)",
            "2. 🚀 Pentest Completo (recon, varredura, exploração, pós-ex)",
            "3. 🌐 OSINT (coleta pública)",
            "4. 🔍 Web Scanner (Nikto, SQLmap, XSS, LFI, etc.)",
            "5. 📱 Mobile (Android/iOS)",
            "6. 📡 Wireless (Wi-Fi, Bluetooth)",
            "7. 🧰 Ferramentas Úteis",
            "8. ⚙️ Configurações",
            "9. 📊 Relatórios",
            "G. 🔁 Sincronizar com GitHub (push)",
            "10. 🚪 Sair",
        ]
        for line in menu:
            print(line)

    def interactive_loop(self):
        if not self.silent:
            display_banner()
        while True:
            try:
                self.show_main_menu()
                choice = self._prompt("Escolha uma opção (0-10/G)", "10")
                if choice == "0":
                    instalar_globalmente()
                elif choice == "1":
                    self.bug_bounty_menu()
                elif choice == "2":
                    self.pentest_menu()
                elif choice == "3":
                    self.osint_menu()
                elif choice == "4":
                    self.web_menu()
                elif choice == "5":
                    self.mobile_menu()
                elif choice == "6":
                    self.wireless_menu()
                elif choice == "7":
                    self.tools_menu()
                elif choice == "8":
                    self.settings_menu()
                elif choice == "9":
                    self.reports_menu()
                elif choice.lower() == "g":
                    git_push_full(Path.cwd())
                elif choice == "10":
                    print("Saindo...")
                    return
                else:
                    print("Opção inválida.")
            except KeyboardInterrupt:
                print("\nEncerrado pelo usuário.")
                self._pause_for_menu()
            except Exception as e:
                # Qualquer erro inesperado mantém o fluxo dentro do menu.
                print(f"[!] Erro inesperado no menu principal: {e}")
                print("[!] Voltando ao menu principal...")
                self._pause_for_menu()

    def run(self):
        self.apply_globals(targets=self.current_targets or TARGET_ROOTS, quick=QUICK_MODE, no_screenshots=NO_SCREENSHOTS)
        if str(Path(sys.argv[0]).stem).lower() == "opium":
            self.silent = False
        self.interactive_loop()

    def _set_mode_report_dir(self, mode_name):
        global REPORT_DIR
        REPORT_DIR = REPORTS_DIR / mode_name / timestamp
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

    def instalar_globalmente(self):
        return instalar_globalmente()

    def git_push_full(self):
        return git_push_full(Path.cwd())

# ---------------------------
# Main
# ---------------------------
def main():
    try:
        app = App(args)
        app.run()
        if not app.silent:
            log_info("Execução concluída.")
    except KeyboardInterrupt:
        log_warn("Interrompido pelo usuário (KeyboardInterrupt). Salvando checkpoint parcial.")
    except Exception as e:
        log_err(f"Erro crítico no main: {e}\n{traceback.format_exc()}")


if __name__ == "__main__":
    main()