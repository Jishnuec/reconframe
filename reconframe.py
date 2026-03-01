#!/usr/bin/env python3
"""
ReconFrame v3.0  -  Professional Reconnaissance Framework
Usage: python3 reconframe.py [-t TARGET] [-o FILE] [-v] [--no-banner]
"""

import os, sys, re, json, time, shutil, signal, argparse, socket, threading, subprocess, random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==============================================================================
#  CONSTANTS
# ==============================================================================

VERSION     = "3.0.0"
CONFIG_DIR  = "/etc/reconframe"
CONFIG_FILE = CONFIG_DIR + "/config.json"
W           = 82          # total box width
IW          = W - 4       # inner content width (78)
ANSI_RE     = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def _vlen(s):
    return len(ANSI_RE.sub('', s))

# ==============================================================================
#  COLOURS
# ==============================================================================

class C:
    RST = "\033[0m";  BOLD = "\033[1m";  DIM = "\033[2m"
    RED = "\033[91m"; GRN  = "\033[92m"; YLW = "\033[93m"
    BLU = "\033[94m"; MAG  = "\033[95m"; CYN = "\033[96m"
    WHT = "\033[97m"; GRY  = "\033[90m"

def col(text, *attrs):
    return "".join(attrs) + str(text) + C.RST

# ==============================================================================
#  BOX ENGINE
# ==============================================================================

DH="="; DV="|"
BOX_TL="╔"; BOX_TR="╗"; BOX_BL="╚"; BOX_BR="╝"
BOX_H="═";  BOX_V="║";  BOX_ML="╠"; BOX_MR="╣"
SH="─"

SYM_OK   = "[+]"
SYM_ERR  = "[-]"
SYM_WARN = "[!]"
SYM_SKIP = "[~]"
SYM_RUN  = "[>]"
SYM_DOT  = " * "

BC = C.CYN  # default border colour

def _pad(content, width):
    vl = _vlen(content)
    if vl > width:
        plain = ANSI_RE.sub('', content)
        return plain[:max(0, width - 1)] + ">"
    return content + (" " * (width - vl))

def trunc(s, n):
    s = ANSI_RE.sub('', str(s))
    return s if len(s) <= n else s[:n - 1] + ">"

def row(content="", indent=0, bc=None):
    bc    = bc or BC
    avail = W - 4 - indent
    return col(BOX_V, bc) + " " + (" " * indent) + _pad(content, avail) + " " + col(BOX_V, bc)

def top(bc=None):
    bc = bc or BC
    return col(BOX_TL + BOX_H * (W - 2) + BOX_TR, bc)

def bot(bc=None):
    bc = bc or BC
    return col(BOX_BL + BOX_H * (W - 2) + BOX_BR, bc)

def mid(bc=None):
    bc = bc or BC
    return col(BOX_ML + BOX_H * (W - 2) + BOX_MR, bc)

def ruled(label="", bc=None, lc=None):
    bc = bc or BC
    lc = lc or C.CYN
    if not label:
        return mid(bc)
    ls   = " " + col(label, lc, C.BOLD) + " "
    sl   = (W - 2 - _vlen(ls)) // 2
    line = BOX_H * sl + ls + BOX_H * (W - 2 - sl - _vlen(ls))
    return col(BOX_ML + line + BOX_MR, bc)

def center(text):
    pad = max(0, (IW - _vlen(text)) // 2)
    return " " * pad + text

def blank(bc=None):
    return row("", bc=bc)

# ==============================================================================
#  CONFIG MANAGER
# ==============================================================================

class ConfigManager:
    _D = {"total_scans": 0, "created_at": str(datetime.now())}

    def __init__(self):
        self.data = self._load()

    def _load(self):
        for path in [CONFIG_FILE, os.path.expanduser("~/.reconframe.json")]:
            try:
                if os.path.exists(path):
                    with open(path) as f:
                        return dict(self._D, **json.load(f))
            except Exception:
                pass
        return dict(self._D)

    def save(self):
        for path, d in [(CONFIG_FILE, CONFIG_DIR),
                        (os.path.expanduser("~/.reconframe.json"), None)]:
            try:
                if d:
                    os.makedirs(d, exist_ok=True)
                with open(path, "w") as f:
                    json.dump(self.data, f, indent=2)
                return
            except PermissionError:
                continue

    def get(self, k, d=None):  return self.data.get(k, d)
    def set(self, k, v):       self.data[k] = v; self.save()
    def record_scan(self):     self.set("total_scans", self.get("total_scans", 0) + 1)

# ==============================================================================
#  TOOL REGISTRY
# ==============================================================================

# (id, name, description, category, binary, risk)
_TOOL_DEFS = [
    ("nmap",         "Nmap",         "Port scanner & service/version detection",  "Network", "nmap",        "MEDIUM"),
    ("gobuster",     "Gobuster",     "Directory & DNS brute-force enumeration",   "Web",     "gobuster",    "MEDIUM"),
    ("subfinder",    "Subfinder",    "Passive subdomain enumeration engine",      "DNS",     "subfinder",   "LOW"   ),
    ("nikto",        "Nikto",        "Web server misconfiguration scanner",       "Web",     "nikto",       "HIGH"  ),
    ("sqlmap",       "SQLMap",       "Automated SQL injection detection",         "Web",     "sqlmap",      "HIGH"  ),
    ("theharvester", "TheHarvester", "OSINT email, domain & IP harvesting",       "OSINT",   "theHarvester","LOW"   ),
    ("whois",        "Whois",        "Domain registration & ownership lookup",   "OSINT",   "whois",       "LOW"   ),
    ("dnsenum",      "DNSenum",      "DNS zone transfer & brute-force enum",     "DNS",     "dnsenum",     "MEDIUM"),
    ("wafw00f",      "WafW00f",      "Web Application Firewall fingerprinting",  "Web",     "wafw00f",     "LOW"   ),
    ("amass",        "Amass",        "In-depth attack surface mapping",          "DNS",     "amass",       "MEDIUM"),
    ("sslyze",       "SSLyze",       "SSL/TLS configuration & cipher analysis",  "Network", "sslyze",      "LOW"   ),
    ("dnsrecon",     "DNSRecon",     "DNS record enumeration & zone discovery",  "DNS",     "dnsrecon",    "LOW"   ),
]

TOOLS = [
    {"id": d[0], "name": d[1], "desc": d[2], "cat": d[3], "bin": d[4], "risk": d[5]}
    for d in _TOOL_DEFS
]

RISK_CLR = {"LOW": C.GRN, "MEDIUM": C.YLW, "HIGH": C.RED}
CAT_CLR  = {"Network": C.CYN, "Web": C.MAG, "DNS": C.BLU, "OSINT": C.YLW}

# Tools that require a domain name (not an IP)
DNS_TOOLS   = {"subfinder", "dnsenum", "dnsrecon", "amass", "theharvester"}
# Tools that need HTTP/HTTPS
WEB_TOOLS   = {"nikto", "sqlmap", "gobuster", "wafw00f"}
# Tools that require HTTPS specifically
HTTPS_TOOLS = {"sslyze"}

INSTALL_HINTS = {
    "nmap":        "sudo apt install nmap",
    "gobuster":    "sudo apt install gobuster",
    "subfinder":   "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "nikto":       "sudo apt install nikto",
    "sqlmap":      "sudo apt install sqlmap",
    "theHarvester":"sudo apt install theharvester",
    "whois":       "sudo apt install whois",
    "dnsenum":     "sudo apt install dnsenum",
    "wafw00f":     "pip3 install wafw00f",
    "amass":       "sudo snap install amass",
    "sslyze":      "pip3 install sslyze",
    "dnsrecon":    "sudo apt install dnsrecon",
}

# Friendly messages for tool-specific problems
TOOL_SKIP_MSGS = {
    "nikto":        SYM_WARN + " Timed out - target may be slow or unresponsive",
    "theharvester": SYM_WARN + " Requires valid domain name, not IP",
    "dnsenum":      SYM_WARN + " DNS tools need domain, not IP address",
    "subfinder":    SYM_WARN + " Works best with domains, not IPs",
    "amass":        "[T] Takes time - use -v for details",
    "sslyze":       SYM_WARN + " SSL scan only works on HTTPS ports",
    "dnsrecon":     SYM_WARN + " DNS enumeration needs domain name",
}

def tool_by_id(tid):
    return next((t for t in TOOLS if t["id"] == tid), None)

# ==============================================================================
#  TARGET HELPERS
# ==============================================================================

def _domain(target):
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

def _url(target):
    return target if target.startswith("http") else "http://" + target

def _is_ip(target):
    host = _domain(target)
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except (socket.error, OSError):
            pass
    return False

def _port_open(host, port, timeout=2.5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False

def _has_https(target):
    return _port_open(_domain(target), 443)

def _has_web(target):
    host = _domain(target)
    return any(_port_open(host, p) for p in [80, 443, 8080, 8443])

# ==============================================================================
#  SMART TOOL VALIDATION
# ==============================================================================

class ScanContext:
    """Holds resolved target info and per-tool overrides."""
    def __init__(self, target, selected_ids):
        self.target       = target
        self.selected_ids = list(selected_ids)
        self.dns_domain   = None   # override domain for DNS tools
        self.skipped      = {}     # id -> reason string
        self.enabled      = list(selected_ids)

    def skip(self, tid, reason):
        if tid in self.enabled:
            self.enabled.remove(tid)
        self.skipped[tid] = reason


def smart_validate(target, selected_ids):
    """
    Check target vs selected tools and return a ScanContext with
    any necessary skips or domain overrides.  Prints prompts as needed.
    """
    ctx    = ScanContext(target, selected_ids)
    is_ip  = _is_ip(target)

    dns_sel = [t for t in selected_ids if t in DNS_TOOLS]

    # --- DNS tools need a domain, not an IP -----------------------------------
    if dns_sel and is_ip:
        print()
        print(top(bc=C.YLW))
        print(row(center(col("DNS TOOL WARNING", C.YLW, C.BOLD)), bc=C.YLW))
        print(mid(bc=C.YLW))
        print(blank(bc=C.YLW))
        print(row(col("  " + SYM_WARN + " DNS tools need a domain name, not an IP address", C.YLW), bc=C.YLW))
        print(blank(bc=C.YLW))
        print(row(col("  Affected tools:", C.WHT), bc=C.YLW))
        for tid in dns_sel:
            t = tool_by_id(tid)
            nm = t["name"] if t else tid
            msg = TOOL_SKIP_MSGS.get(tid, "")
            print(row(col("    " + SYM_DOT + nm + "  " + msg, C.GRY), bc=C.YLW))
        print(blank(bc=C.YLW))
        print(bot(bc=C.YLW))
        print()
        domain_in = input(
            "  Enter domain for DNS tools (or press Enter to skip them): "
        ).strip()
        if domain_in:
            ctx.dns_domain = domain_in
            print()
            print("  " + col(SYM_OK + " DNS tools will use: " + domain_in, C.GRN, C.BOLD))
            print()
            time.sleep(0.6)
        else:
            for tid in dns_sel:
                msg = TOOL_SKIP_MSGS.get(tid, SYM_WARN + " Skipped: IP target, no domain provided")
                ctx.skip(tid, msg)
            print()
            print("  " + col(SYM_WARN + " DNS tools skipped.", C.YLW))
            print()
            time.sleep(0.6)

    # --- SSLyze needs HTTPS ---------------------------------------------------
    if "sslyze" in selected_ids:
        if not target.startswith("https://") and not _has_https(target):
            ctx.skip("sslyze", TOOL_SKIP_MSGS["sslyze"])

    # --- nikto / sqlmap: check web ports -------------------------------------
    web_sel = [t for t in ["nikto", "sqlmap"] if t in selected_ids]
    if web_sel:
        # Only probe once
        has_web = _has_web(target)
        if not has_web:
            for tid in web_sel:
                ctx.skip(tid, SYM_WARN + " Skipped: no open web port (80/443/8080) detected")

    return ctx

# ==============================================================================
#  TOOL RUNNERS
# ==============================================================================

def _cmd(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "Timed out after %ds" % timeout, -2
    except Exception as ex:
        return "", str(ex), -1

def _avail(name):
    return shutil.which(name) is not None

def _missing(bin_name):
    hint = INSTALL_HINTS.get(bin_name, "install " + bin_name)
    return {"status": "missing", "output": "Not installed  ->  " + hint}

def _result(out, err, rc, t_msg=None):
    if rc == -2:
        return {"status": "timeout",
                "output": t_msg or SYM_WARN + " Timed out - target may be slow or unresponsive"}
    combined = "\n".join(x for x in [out, err] if x.strip())
    return {"status": "ok" if rc == 0 else "error",
            "output": combined or "No output."}


def run_nmap(target, **kw):
    if not _avail("nmap"):
        return _missing("nmap")
    host = _domain(target)
    out, err, rc = _cmd("nmap -sV -sC -A -T4 " + host, 180)
    combined = "\n".join(x for x in [out, err] if x.strip())
    return {"status": "ok" if rc == 0 else "error",
            "output": combined or "No output from nmap for: " + host}


def run_gobuster(target, **kw):
    if not _avail("gobuster"):
        return _missing("gobuster")
    wl = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wl):
        return {"status": "error",
                "output": "Wordlist not found: " + wl + "\nInstall: apt install dirb"}
    out, err, rc = _cmd("gobuster dir -u " + _url(target) + " -w " + wl + " -t 20 -q", 180)
    return _result(out, err, rc, SYM_WARN + " Gobuster timed out - target may be slow")


def run_subfinder(target, dns_domain=None, **kw):
    if not _avail("subfinder"):
        return _missing("subfinder")
    domain = dns_domain or _domain(target)
    out, err, rc = _cmd("subfinder -d " + domain + " -silent", 120)
    return {"status": "ok", "output": out or err or "No subdomains found."}


def run_nikto(target, **kw):
    if not _avail("nikto"):
        return _missing("nikto")
    out, err, rc = _cmd("nikto -h " + _url(target) + " -nointeractive", 300)
    return _result(out, err, rc, TOOL_SKIP_MSGS["nikto"])


def run_sqlmap(target, **kw):
    if not _avail("sqlmap"):
        return _missing("sqlmap")
    out, err, rc = _cmd(
        "sqlmap -u " + _url(target) + " --batch --level=1 --risk=1 --forms", 300)
    return _result(out, err, rc)


def run_theharvester(target, dns_domain=None, **kw):
    b = "theHarvester" if _avail("theHarvester") else "theharvester"
    if not _avail(b):
        return _missing("theHarvester")
    domain = dns_domain or _domain(target)
    out, err, rc = _cmd(b + " -d " + domain + " -b google,bing,duckduckgo -l 100", 120)
    return _result(out, err, rc)


def run_whois(target, **kw):
    if not _avail("whois"):
        return _missing("whois")
    out, err, rc = _cmd("whois " + _domain(target), 30)
    return {"status": "ok" if rc == 0 else "error",
            "output": out or err or "No whois data returned."}


def run_dnsenum(target, dns_domain=None, **kw):
    if not _avail("dnsenum"):
        return _missing("dnsenum")
    domain = dns_domain or _domain(target)
    out, err, rc = _cmd("dnsenum --nocolor " + domain, 120)
    return _result(out, err, rc, SYM_WARN + " DNSenum timed out")


def run_wafw00f(target, **kw):
    if not _avail("wafw00f"):
        return _missing("wafw00f")
    out, err, rc = _cmd("wafw00f " + _url(target), 30)
    return _result(out, err, rc)


def run_amass(target, dns_domain=None, **kw):
    if not _avail("amass"):
        return _missing("amass")
    domain = dns_domain or _domain(target)
    out, err, rc = _cmd("amass enum -passive -d " + domain, 180)
    return {"status": "ok",
            "output": out or err or "No results - amass may need API keys for best results."}


def run_sslyze(target, **kw):
    if not _avail("sslyze"):
        return _missing("sslyze")
    host = _domain(target)
    out, err, rc = _cmd("sslyze " + host, 60)
    return _result(out, err, rc, TOOL_SKIP_MSGS["sslyze"])


def run_dnsrecon(target, dns_domain=None, **kw):
    if not _avail("dnsrecon"):
        return _missing("dnsrecon")
    domain = dns_domain or _domain(target)
    out, err, rc = _cmd("dnsrecon -d " + domain + " -t std", 60)
    combined = "\n".join(x for x in [out, err] if x.strip())
    return {"status": "ok" if rc == 0 else "error",
            "output": combined or "No DNS records found."}


RUNNERS = {
    "nmap":         run_nmap,
    "gobuster":     run_gobuster,
    "subfinder":    run_subfinder,
    "nikto":        run_nikto,
    "sqlmap":       run_sqlmap,
    "theharvester": run_theharvester,
    "whois":        run_whois,
    "dnsenum":      run_dnsenum,
    "wafw00f":      run_wafw00f,
    "amass":        run_amass,
    "sslyze":       run_sslyze,
    "dnsrecon":     run_dnsrecon,
}

# ==============================================================================
#  CINEMATIC STARTUP  (Metasploit-style)
# ==============================================================================

def play_startup_animation():
    """
    MSF-inspired startup sequence:
      Phase 1 – Matrix cascade  : green rain floods the screen
      Phase 2 – Logo crystallise: each art-line glitches then snaps into place
      Phase 3 – Module loader   : categories load one-by-one with tool names
      Phase 4 – Armed banner    : final status line before the main menu
    """

    _GLITCH = list("!@#$%^&*<>[]{}|/\\+=~`01アイウエオカキクケコ")

    _RECON = [
        r" ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗",
        r" ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║",
        r" ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║",
        r" ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║",
        r" ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║",
        r" ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝",
    ]
    _FRAME = [
        r" ███████╗██████╗  █████╗ ███╗   ███╗███████╗",
        r" ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝",
        r" █████╗  ██████╔╝███████║██╔████╔██║█████╗  ",
        r" ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ",
        r" ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗",
        r" ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝",
    ]

    def _glitch_line(line):
        """Return a scrambled version of an art line (non-space chars → random glitch char)."""
        out = ""
        for ch in line:
            out += (col(random.choice(_GLITCH), C.GRN) if ch != " " else " ")
        return out

    def _reveal_art(lines, art_colour):
        """Flash-scramble each line then snap to final colour."""
        for line in lines:
            # Brief glitch flash
            sys.stdout.write("  " + _glitch_line(line) + "\r")
            sys.stdout.flush()
            time.sleep(0.045)
            # Clear line and write the real art
            sys.stdout.write("\033[2K\r")
            sys.stdout.write("  " + col(line, art_colour, C.BOLD) + "\n")
            sys.stdout.flush()

    # ── Phase 1: Matrix rain ─────────────────────────────────────────────────
    RAIN_ROWS = 16
    RAIN_FRAMES = 4
    RAIN_CHARS  = "01アウエカキクサシスナニネノ@#$%^&*<>"

    for _ in range(RAIN_FRAMES):
        _clear()
        print()
        for _ in range(RAIN_ROWS):
            line = ""
            for _ in range(76):
                line += random.choice(RAIN_CHARS) if random.random() < 0.38 else " "
            sys.stdout.write("  " + col(line, C.GRN, C.DIM) + "\n")
        sys.stdout.flush()
        time.sleep(0.12)

    # ── Phase 2: Logo crystallises ────────────────────────────────────────────
    _clear()
    print()
    _reveal_art(_RECON, C.CYN)
    _reveal_art(_FRAME, C.YLW)
    print()

    # Tagline types in character-by-character
    tagline = "  Professional Reconnaissance Framework  |  v" + VERSION
    sys.stdout.write(col("  " + "─" * 60 + "\n", C.GRY, C.DIM))
    for ch in tagline:
        sys.stdout.write(col(ch, C.WHT, C.BOLD))
        sys.stdout.flush()
        time.sleep(0.018)
    sys.stdout.write("\n")
    sys.stdout.write(col("  " + "─" * 60 + "\n", C.GRY, C.DIM))
    print()
    time.sleep(0.25)

    # ── Phase 3: Module loader (MSF-style) ────────────────────────────────────
    MODULE_GROUPS = [
        ("Network",  C.CYN, ["nmap",        "sslyze"                        ]),
        ("Web",      C.MAG, ["gobuster",     "nikto",  "sqlmap",  "wafw00f"  ]),
        ("DNS",      C.BLU, ["subfinder",    "dnsenum","dnsrecon","amass"    ]),
        ("OSINT",    C.YLW, ["whois",        "theharvester"                  ]),
    ]

    total_mods = sum(len(t) for _, _, t in MODULE_GROUPS)
    loaded     = 0

    for cat, clr, tools in MODULE_GROUPS:
        loaded += len(tools)
        prefix   = "  " + col("[*]", C.GRN) + "  " + col("%-10s" % cat, clr, C.BOLD)
        dot_fill = col(" ........ ", C.GRY, C.DIM)
        tool_str = "  ".join(col("[" + t + "]", clr) for t in tools)
        count_s  = col("  (%d/%d)" % (loaded, total_mods), C.GRY, C.DIM)

        # Print prefix + animated dots one-by-one
        sys.stdout.write(prefix + "  ")
        sys.stdout.flush()
        for _ in range(8):
            sys.stdout.write(col(".", C.GRY, C.DIM))
            sys.stdout.flush()
            time.sleep(0.022)
        sys.stdout.write("  " + tool_str + count_s + "\n")
        sys.stdout.flush()
        time.sleep(0.15)

    print()

    # ── Phase 4: Armed banner ─────────────────────────────────────────────────
    armed = "[+] %d modules armed  |  ReconFrame is ready." % total_mods
    sys.stdout.write(col("  " + "=" * 60 + "\n", C.GRY, C.DIM))
    sys.stdout.write("  " + col(armed, C.GRN, C.BOLD) + "\n")
    sys.stdout.write(col("  " + "=" * 60 + "\n", C.GRY, C.DIM))
    print()
    time.sleep(0.7)


# ==============================================================================
#  BANNER  (shown at main menu — same block art as animation)
# ==============================================================================

_BANNER_RECON = [
    r" ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗",
    r" ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║",
    r" ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║",
    r" ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║",
    r" ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║",
    r" ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝",
]
_BANNER_FRAME = [
    r" ███████╗██████╗  █████╗ ███╗   ███╗███████╗",
    r" ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝",
    r" █████╗  ██████╔╝███████║██╔████╔██║█████╗  ",
    r" ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ",
    r" ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗",
    r" ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝",
]

def print_banner():
    print(top())
    print(blank())
    for ln in _BANNER_RECON:
        print(row(center(col(ln, C.CYN, C.BOLD))))
    print(blank())
    for ln in _BANNER_FRAME:
        print(row(center(col(ln, C.YLW, C.BOLD))))
    print(blank())
    print(row(center(col(
        "Professional Reconnaissance Framework  |  v" + VERSION, C.WHT, C.BOLD))))
    print(row(center(col("Authorized Penetration Testing Use Only", C.GRY, C.DIM))))
    print(blank())
    print(bot())


# ==============================================================================
#  MAIN MENU
# ==============================================================================

def print_main_menu(cfg):
    total = cfg.get("total_scans", 0)
    print(top())
    print(row(center(col("MAIN MENU", C.CYN, C.BOLD))))
    print(row(center(col(
        "Session total: " + str(total) + " scan" + ("s" if total != 1 else ""),
        C.GRY, C.DIM))))
    print(mid())
    print(blank())
    for key, lbl, desc in [
        ("1", "Start New Scan",    "Launch interactive recon against a target"),
        ("2", "Tool Availability", "Check which tools are installed"),
        ("3", "About",             "Version info, legal notice & usage tips"),
    ]:
        print(row(
            col(" [" + key + "]", C.GRN, C.BOLD) + "  " +
            col("%-26s" % lbl, C.WHT, C.BOLD) +
            col(desc, C.GRY)
        ))
    print(blank())
    print(row(col(" [0]", C.RED, C.BOLD) + "  " + col("Exit", C.WHT, C.BOLD)))
    print(blank())
    print(bot())

# ==============================================================================
#  ABOUT
# ==============================================================================

def print_about():
    print(top())
    print(row(center(col("ABOUT  RECONFRAME", C.CYN, C.BOLD))))
    print(mid())
    print(blank())
    for k, v in [
        ("Version", "ReconFrame v" + VERSION),
        ("Author",  "ReconFrame Team"),
        ("License", "MIT  -  Free & Open Source"),
        ("Config",  CONFIG_FILE),
        ("Python",  sys.version.split()[0]),
    ]:
        print(row(col("%-14s" % k, C.GRY) + col(v, C.WHT)))
    print(blank())
    print(row(center(col("CAPABILITIES", C.CYN, C.BOLD))))
    print(blank())
    for cap in [
        "12 integrated recon tools: Network * Web * DNS * OSINT",
        "Smart target validation  -  DNS tools auto-detected for IP targets",
        "Port probing before running web/SSL tools",
        "Parallel scanning with live in-place progress bar",
        "Verbose mode (-v): show full raw tool output",
        "Grouped findings report: open ports, dirs, subdomains, vulns",
        "Friendly skip messages with reasons for each skipped tool",
        "Plain-text report export  ( -o report.txt )",
    ]:
        print(row(col("  " + SYM_DOT + " ", C.CYN) + col(cap, C.GRY)))
    print(blank())
    print(ruled("LEGAL NOTICE", lc=C.YLW))
    print(blank())
    for ln in [
        "Use ReconFrame only on systems you own or have explicit",
        "written authorisation to test. Unauthorised scanning may",
        "constitute a criminal offence under computer misuse laws.",
    ]:
        print(row(col("  " + ln, C.YLW, C.DIM)))
    print(blank())
    print(bot())

# ==============================================================================
#  TOOL AVAILABILITY
# ==============================================================================

def print_tool_availability():
    installed = [t for t in TOOLS if _avail(t["bin"])]
    missing   = [t for t in TOOLS if not _avail(t["bin"])]

    # Column widths: status(4) + name(16) + cat(9) + risk(8) + desc(41) = 78
    C_NAME = 16; C_CAT = 9; C_RISK = 8; C_DESC = 41

    print(top())
    print(row(center(col("TOOL AVAILABILITY", C.CYN, C.BOLD))))
    print(row(center(
        col(str(len(installed)), C.GRN, C.BOLD) + col(" installed  *  ", C.GRY) +
        col(str(len(missing)),   C.RED, C.BOLD) + col(" missing",  C.GRY)
    )))
    print(mid())
    print(blank())
    # Header
    print(row(
        col("%-4s" % "ST",   C.GRY, C.BOLD) +
        col("%-*s" % (C_NAME, "TOOL"),     C.GRY, C.BOLD) +
        col("%-*s" % (C_CAT,  "CATEGORY"), C.GRY, C.BOLD) +
        col("%-*s" % (C_RISK, "RISK"),     C.GRY, C.BOLD) +
        col("%-*s" % (C_DESC, "DESCRIPTION"), C.GRY, C.BOLD)
    ))
    print(row(col(SH * IW, C.GRY, C.DIM)))
    print(blank())
    for t in TOOLS:
        av  = _avail(t["bin"])
        st  = col((SYM_OK + " ") if av else (SYM_ERR + " "), C.GRN if av else C.RED, C.BOLD)
        nm  = col("%-*s" % (C_NAME, t["name"]), C.WHT if av else C.GRY)
        cat = col("%-*s" % (C_CAT,  t["cat"]),  CAT_CLR.get(t["cat"],  C.GRY))
        rsk = col("%-*s" % (C_RISK, t["risk"]), RISK_CLR.get(t["risk"], C.GRY))
        dsc = col("%-*s" % (C_DESC, trunc(t["desc"], C_DESC)), C.GRY)
        print(row(st + nm + cat + rsk + dsc))

    if missing:
        print(blank())
        print(ruled("INSTALL MISSING TOOLS", lc=C.YLW))
        print(blank())
        for t in missing:
            hint = INSTALL_HINTS.get(t["bin"], "install " + t["bin"])
            print(row(col("%-18s" % t["name"], C.WHT) + col(hint, C.YLW, C.DIM)))
    print(blank())
    print(bot())

# ==============================================================================
#  TOOL SELECTION MENU
# ==============================================================================

def tool_selection_menu():
    """Checkbox TUI. Returns list of selected IDs or None if cancelled."""
    selected = set()

    # Column layout:  chk(4) + num(5) + name(14) + cat(9) + risk(8) + desc(38) = 78
    C_NUM = 5; C_NAME = 14; C_CAT = 9; C_RISK = 8; C_DESC = 38

    while True:
        _clear()
        print(top())
        print(row(center(col("SELECT  TOOLS", C.CYN, C.BOLD))))
        print(row(center(col(
            "[num] toggle  *  [a] all  *  [n] none  *  [c] continue  *  [q] cancel",
            C.GRY, C.DIM))))
        print(mid())
        print(blank())

        # Column header
        print(row(
            col("    ", C.GRY) +
            col("%-*s" % (C_NUM,  "#"),        C.GRY, C.BOLD) +
            col("%-*s" % (C_NAME, "TOOL"),     C.GRY, C.BOLD) +
            col("%-*s" % (C_CAT,  "CATEGORY"), C.GRY, C.BOLD) +
            col("%-*s" % (C_RISK, "RISK"),     C.GRY, C.BOLD) +
            col("%-*s" % (C_DESC, "DESCRIPTION"), C.GRY, C.BOLD)
        ))
        print(row(col(SH * IW, C.GRY, C.DIM)))
        print(blank())

        for i, t in enumerate(TOOLS, 1):
            sel  = t["id"] in selected
            chk  = col("[+] ", C.GRN, C.BOLD) if sel else col("[ ] ", C.GRY)
            num  = col("%2d.  " % i,          C.YLW if sel else C.GRY)
            nm   = col("%-*s" % (C_NAME, t["name"]), C.WHT if sel else C.GRY)
            cat  = col("%-*s" % (C_CAT,  t["cat"]),
                       CAT_CLR.get(t["cat"], C.GRY) if sel else C.GRY)
            rsk  = col("%-*s" % (C_RISK, t["risk"]),
                       RISK_CLR.get(t["risk"], C.GRY))
            if not _avail(t["bin"]):
                dsc = col("%-*s" % (C_DESC, "(not installed)"), C.RED, C.DIM)
            else:
                dsc = col("%-*s" % (C_DESC, trunc(t["desc"], C_DESC)), C.GRY, C.DIM)
            print(row(chk + num + nm + cat + rsk + dsc))

        print(blank())
        print(row(center(
            col(str(len(selected)), C.GRN, C.BOLD) +
            col(" of ", C.GRY) +
            col(str(len(TOOLS)), C.GRY) +
            col(" tools selected", C.GRY)
        )))
        print(blank())
        print(bot())

        raw = input("\n  Enter command > ").strip().lower()

        if raw == "q":
            return None
        elif raw == "a":
            selected = {t["id"] for t in TOOLS}
        elif raw == "n":
            selected.clear()
        elif raw == "c":
            if not selected:
                _flash(col("  " + SYM_WARN + " No tools selected.", C.YLW))
            else:
                return list(selected)
        else:
            try:
                idx = int(raw) - 1
                if 0 <= idx < len(TOOLS):
                    tid = TOOLS[idx]["id"]
                    if tid in selected:
                        selected.remove(tid)
                    else:
                        selected.add(tid)
                else:
                    _flash(col("  " + SYM_ERR + " Out of range (1-%d)." % len(TOOLS), C.RED))
            except ValueError:
                _flash(col("  " + SYM_ERR + " Unknown command.", C.RED))

# ==============================================================================
#  SCAN ENGINE
# ==============================================================================

class ScanEngine:
    def __init__(self, ctx, workers=4, rate=0.4):
        self.ctx     = ctx
        self.workers = workers
        self.rate    = rate
        self.results = {}    # id -> {status, output}
        self.timings = {}    # id -> float seconds
        self._lock   = threading.Lock()
        self._stop   = False

    def stop(self):
        self._stop = True

    def run(self):
        enabled  = self.ctx.enabled
        skipped  = self.ctx.skipped
        tools    = [t for t in TOOLS if t["id"] in enabled]
        total    = len(tools)
        done     = [0]
        start    = time.time()
        lk_print = threading.Lock()

        # Pre-populate skipped results
        for tid, reason in skipped.items():
            self.results[tid] = {"status": "skipped", "output": reason}
            self.timings[tid] = 0.0

        # --- Scan header ------------------------------------------------------
        print()
        print(top())
        print(row(center(col("SCAN  INITIALISING", C.CYN, C.BOLD))))
        print(mid())
        print(blank())
        for k, v in [
            ("Target",     self.ctx.target),
            ("DNS domain", self.ctx.dns_domain if self.ctx.dns_domain else "(same as target)"),
            ("Tools",      "%d active  *  %d skipped" % (total, len(skipped))),
            ("Workers",    "%d parallel threads" % self.workers),
            ("Started",    datetime.now().strftime("%Y-%m-%d  %H:%M:%S")),
        ]:
            print(row(col("  %-14s" % k, C.GRY) + col(v, C.WHT)))

        if skipped:
            print(blank())
            print(row(col("  SMART SKIPS:", C.YLW, C.BOLD)))
            for tid, reason in skipped.items():
                t  = tool_by_id(tid)
                nm = t["name"] if t else tid
                print(row(col("    " + SYM_SKIP + " %-16s" % nm, C.YLW) +
                          col(reason, C.GRY, C.DIM)))
        print(blank())
        print(bot())
        print()

        if not tools:
            print(row(col("  " + SYM_WARN + " No tools to run after validation.", C.YLW)))
            return self.results, self.timings

        # --- Live progress display -------------------------------------------
        print(top())
        print(row(center(col("LIVE PROGRESS", C.CYN, C.BOLD))))
        print(mid())
        print(blank())

        status_lines = {}

        def _bar(complete, total_, elapsed):
            filled = int(34 * complete / total_) if total_ else 0
            bar_str = ("=" * filled) + ("-" * (34 - filled))
            pct     = int(100 * complete / total_) if total_ else 0
            inner   = "[" + bar_str + "] " + str(pct) + "%%  " + \
                      str(complete) + "/" + str(total_) + "  +" + "%.0f" % elapsed + "s"
            return center(inner)

        for t in tools:
            ln = row(
                col("  " + SYM_DOT + " ", C.GRY) +
                col("%-10s" % "QUEUED", C.GRY) +
                col("%-16s" % t["name"], C.GRY) +
                col(trunc(t["desc"], 42), C.GRY, C.DIM)
            )
            status_lines[t["id"]] = ln
            print(ln)

        print(blank())
        print(row(_bar(0, total, 0)))
        print(blank())
        print(bot())

        ROWS_BACK = len(tools) + 5  # blank + bar + blank + bot + header separator
        MOVE_UP   = "\033[%dA" % ROWS_BACK

        def _refresh(t_id, new_line, complete, elapsed_):
            with lk_print:
                sys.stdout.write(MOVE_UP)
                sys.stdout.flush()
                print(row(center(col("LIVE PROGRESS", C.CYN, C.BOLD))))
                print(mid())
                print(blank())
                status_lines[t_id] = new_line
                for t in tools:
                    print(status_lines[t["id"]])
                print(blank())
                print(row(_bar(complete, total, elapsed_)))
                print(blank())
                print(bot())
                sys.stdout.flush()

        def _run_one(tool):
            if self._stop:
                return tool["id"], {"status": "skipped", "output": "Interrupted."}, 0.0
            t0  = time.time()
            run = RUNNERS.get(tool["id"])
            kw  = {}
            if tool["id"] in DNS_TOOLS and self.ctx.dns_domain:
                kw["dns_domain"] = self.ctx.dns_domain
            res = run(self.ctx.target, **kw) if run else {"status": "error", "output": "No runner."}
            return tool["id"], res, time.time() - t0

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = {}
            for tool in tools:
                if self._stop:
                    break
                time.sleep(self.rate)
                futures[ex.submit(_run_one, tool)] = tool

            for fut in as_completed(futures):
                if self._stop:
                    break
                tool            = futures[fut]
                tid, res, el    = fut.result()

                with self._lock:
                    self.results[tid] = res
                    self.timings[tid] = el
                    done[0] += 1

                st = res.get("status", "?")
                if   st == "ok":      icon = col("  " + SYM_OK   + " %-10s" % "COMPLETE", C.GRN, C.BOLD)
                elif st == "timeout": icon = col("  " + SYM_WARN  + " %-10s" % "TIMEOUT",  C.YLW, C.BOLD)
                elif st == "missing": icon = col("  " + SYM_WARN  + " %-10s" % "MISSING",  C.YLW, C.BOLD)
                elif st == "skipped": icon = col("  " + SYM_SKIP  + " %-10s" % "SKIPPED",  C.GRY)
                else:                 icon = col("  " + SYM_ERR   + " %-10s" % "FAILED",   C.RED, C.BOLD)

                nm_str  = col("%-16s" % tool["name"], C.WHT if st == "ok" else C.GRY)
                el_str  = col("  %.1fs" % el, C.GRY, C.DIM)
                dsc_str = col("  " + trunc(tool["desc"], 28), C.GRY, C.DIM)
                new_line = row(icon + nm_str + el_str + dsc_str)
                _refresh(tid, new_line, done[0], time.time() - start)

        return self.results, self.timings

# ==============================================================================
#  FINDINGS GROUPER
# ==============================================================================

def _group_findings(results):
    """Parse tool output and return grouped notable findings."""
    groups = {
        "Open Ports":      [],
        "Directories":     [],
        "Subdomains":      [],
        "Vulnerabilities": [],
        "SSL/TLS Issues":  [],
        "DNS Records":     [],
        "OSINT":           [],
        "WAF / Firewall":  [],
    }

    for tid, res in results.items():
        if res.get("status") != "ok":
            continue
        output = res.get("output", "")
        for line in output.splitlines():
            sl = line.strip().lower()
            ln = line.strip()
            if not ln:
                continue
            # Open ports (nmap)
            if re.search(r'\d+/(tcp|udp)\s+open', sl):
                groups["Open Ports"].append("[nmap]  " + ln)
            # Directories (gobuster)
            elif re.search(r'^/\S.*\(status:', sl) or "status: 200" in sl:
                groups["Directories"].append("[gobuster]  " + ln)
            # Subdomains
            elif tid in ("subfinder", "amass", "dnsrecon", "dnsenum"):
                if re.search(r'\.[a-z]{2,}$', sl):
                    groups["Subdomains"].append("[" + tid + "]  " + ln)
            # DNS records
            elif tid in ("dnsrecon", "dnsenum", "whois"):
                if re.search(r'\b(a|aaaa|cname|mx|ns|txt|soa)\b', sl):
                    groups["DNS Records"].append("[" + tid + "]  " + ln)
            # Vulnerabilities
            elif tid in ("nikto", "sqlmap"):
                if any(k in sl for k in ("vuln", "inject", "xss", "osvdb", "+ server")):
                    groups["Vulnerabilities"].append("[" + tid + "]  " + ln)
            # SSL/TLS
            elif tid == "sslyze":
                if any(k in sl for k in ("weak", "expired", "error", "warning")):
                    groups["SSL/TLS Issues"].append("[sslyze]  " + ln)
            # OSINT
            elif tid in ("theharvester", "whois"):
                if any(k in sl for k in ("email", "@", "registrant", "phone")):
                    groups["OSINT"].append("[" + tid + "]  " + ln)
            # WAF
            elif tid == "wafw00f":
                if any(k in sl for k in ("detected", "behind", "waf", "firewall")):
                    groups["WAF / Firewall"].append("[wafw00f]  " + ln)

    return {k: v for k, v in groups.items() if v}

# ==============================================================================
#  RESULTS RENDERER
# ==============================================================================

def render_results(target, results, timings, output_file=None, verbose=False):
    now   = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    saved = []

    def prt(line=""):
        print(line)
        saved.append(ANSI_RE.sub("", line))

    ok_ids  = [tid for tid, r in results.items() if r["status"] == "ok"]
    err_ids = [tid for tid, r in results.items() if r["status"] in ("error", "timeout")]
    mis_ids = [tid for tid, r in results.items() if r["status"] == "missing"]
    skp_ids = [tid for tid, r in results.items() if r["status"] == "skipped"]
    total_t = sum(timings.values())

    # --- Report header --------------------------------------------------------
    prt()
    prt(top())
    prt(row(center(col("SCAN  REPORT", C.CYN, C.BOLD))))
    prt(mid())
    prt(blank())
    for k, v in [
        ("Target",    target),
        ("Timestamp", now),
        ("Duration",  "%.1fs  (%d tools)" % (total_t, len(results))),
    ]:
        prt(row(col("  %-14s" % k, C.GRY) + col(v, C.WHT)))
    prt(row(
        col("  %-14s" % "Results", C.GRY) +
        col(str(len(ok_ids))  + " ok",      C.GRN, C.BOLD) + col("  *  ", C.GRY) +
        col(str(len(err_ids)) + " failed",  C.RED, C.BOLD) + col("  *  ", C.GRY) +
        col(str(len(mis_ids)) + " missing", C.YLW, C.BOLD) + col("  *  ", C.GRY) +
        col(str(len(skp_ids)) + " skipped", C.GRY)
    ))
    prt(blank())

    # --- Grouped Findings -----------------------------------------------------
    groups = _group_findings(results)
    if groups:
        prt(ruled("KEY  FINDINGS", lc=C.GRN))
        prt(blank())
        for grp_name, findings in groups.items():
            prt(row(col("  >> " + grp_name, C.CYN, C.BOLD)))
            for f in findings[:20]:
                sl  = f.lower()
                clr = C.GRN if any(k in sl for k in ("open", "found", "email", "subdomain")) else \
                      C.RED if any(k in sl for k in ("vuln", "inject", "weak", "expired"))    else C.WHT
                prt(row(col("     " + trunc(f, IW - 5), clr)))
            if len(findings) > 20:
                prt(row(col("     ... %d more - save with -o for full list" % (len(findings) - 20),
                            C.GRY, C.DIM)))
            prt(blank())
    else:
        prt(ruled("KEY  FINDINGS", lc=C.GRY))
        prt(blank())
        prt(row(col("  No notable findings automatically detected.", C.GRY, C.DIM)))
        prt(blank())

    # --- Summary table --------------------------------------------------------
    prt(ruled("SUMMARY", lc=C.CYN))
    prt(blank())
    # Columns: name(18) + status(14) + time(8) + cat(10) + note(28) = 78
    prt(row(
        col("%-18s" % "TOOL",     C.GRY, C.BOLD) +
        col("%-14s" % "STATUS",   C.GRY, C.BOLD) +
        col("%-8s"  % "TIME",     C.GRY, C.BOLD) +
        col("%-10s" % "CATEGORY", C.GRY, C.BOLD) +
        col("%-28s" % "NOTE",     C.GRY, C.BOLD)
    ))
    prt(row(col(SH * IW, C.GRY, C.DIM)))

    for t in TOOLS:
        if t["id"] not in results:
            continue
        res = results[t["id"]]
        st  = res["status"]
        el  = timings.get(t["id"], 0.0)

        if   st == "ok":      badge = col(SYM_OK   + " %-12s" % "Complete", C.GRN, C.BOLD)
        elif st == "timeout": badge = col(SYM_WARN  + " %-12s" % "Timeout",  C.YLW, C.BOLD)
        elif st == "missing": badge = col(SYM_WARN  + " %-12s" % "Missing",  C.YLW, C.BOLD)
        elif st == "skipped": badge = col(SYM_SKIP  + " %-12s" % "Skipped",  C.GRY)
        else:                 badge = col(SYM_ERR   + " %-12s" % "Failed",   C.RED, C.BOLD)

        # Auto-note: count open ports or dirs from output
        note = ""
        if st == "ok":
            out_lines = res.get("output", "").splitlines()
            open_p = len([l for l in out_lines if re.search(r'\d+/(tcp|udp)\s+open', l.lower())])
            dirs   = len([l for l in out_lines if re.search(r'^/\S.*\(status:', l.lower())])
            if open_p: note = col(str(open_p) + " open port(s)", C.GRN)
            elif dirs: note = col(str(dirs)   + " director(ies)", C.GRN)

        prt(row(
            col("%-18s" % t["name"],       C.WHT) +
            badge +
            col("%-8s"  % ("%.1fs" % el),  C.GRY, C.DIM) +
            col("%-10s" % t["cat"],         CAT_CLR.get(t["cat"], C.GRY)) +
            (note if note else col(trunc(res.get("output", "No output.").split("\n")[0], 28),
                                   C.GRY, C.DIM))
        ))

    prt(blank())

    # --- Per-tool output sections --------------------------------------------
    MAX_LINES = 300 if verbose else 60

    for t in TOOLS:
        if t["id"] not in results:
            continue
        res    = results[t["id"]]
        st     = res["status"]
        output = res.get("output", "").strip()

        hdr_c = {"ok": C.GRN, "timeout": C.YLW, "missing": C.YLW,
                 "skipped": C.GRY, "error": C.RED}.get(st, C.RED)
        icon  = {"ok": SYM_OK, "timeout": SYM_WARN, "missing": SYM_WARN,
                 "skipped": SYM_SKIP, "error": SYM_ERR}.get(st, SYM_ERR)

        prt(ruled(icon + "  " + t["name"] + "  *  " + t["cat"] + "  *  " + t["desc"], lc=hdr_c))
        prt(blank())

        if not output:
            prt(row(col("  No output captured.", C.GRY, C.DIM)))
        else:
            lines = output.splitlines()
            for ln in lines[:MAX_LINES]:
                s = ln.rstrip()
                if not s:
                    prt(blank())
                    continue
                sl = s.lower()
                if any(k in sl for k in ("open", "found", "discovered", "email", "@", "running")):
                    text_c = C.GRN
                elif any(k in sl for k in ("error", "failed", "denied", "timeout", "filtered")):
                    text_c = C.RED
                elif any(k in sl for k in ("warning", "notice", "info", "note", "weak", "expired")):
                    text_c = C.YLW
                elif s[:1] in ("#", "=", "-", "~", "*", "+"):
                    text_c = C.CYN
                else:
                    text_c = C.WHT
                prt(row(col("  " + s, text_c)))

            if len(lines) > MAX_LINES:
                prt(blank())
                prt(row(col(
                    "  ... %d lines hidden. Use -v for full output or -o to save." % (len(lines) - MAX_LINES),
                    C.YLW, C.DIM)))
        prt(blank())

    prt(bot())

    # --- Save file ------------------------------------------------------------
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(saved))
            print(); print(top())
            print(row(col("  " + SYM_OK + " Report saved  ->  " + output_file, C.GRN, C.BOLD)))
            print(bot())
        except Exception as ex:
            print(); print(top())
            print(row(col("  " + SYM_ERR + " Save failed: " + str(ex), C.RED)))
            print(bot())

# ==============================================================================
#  SCAN FLOW  (interactive)
# ==============================================================================

def scan_flow(cfg, preset_target=None, preset_output=None, verbose=False):
    # Target input
    if preset_target:
        target = preset_target
    else:
        _clear()
        print(top())
        print(row(center(col("TARGET  SPECIFICATION", C.CYN, C.BOLD))))
        print(mid()); print(blank())
        print(row(col("  Enter a hostname, IP address, or URL:", C.WHT)))
        print(blank())
        for ex in ["example.com", "192.168.1.1", "http://target.local"]:
            print(row(col("    " + SYM_DOT + ex, C.GRY, C.DIM)))
        print(blank()); print(bot()); print()
        target = input("  Target > ").strip()
        if not target:
            _flash(col("  " + SYM_ERR + " No target entered.", C.RED))
            return

    # Legal disclaimer
    print(); print(top())
    print(row(center(col("AUTHORISATION  REQUIRED", C.YLW, C.BOLD))))
    print(mid()); print(blank())
    for ln in [
        "By continuing you confirm you are authorised to scan:",
        "  " + target,
        "",
        "Unauthorised scanning is illegal.",
    ]:
        print(row(col("  " + ln, C.YLW, C.DIM)) if ln else blank())
    print(blank()); print(bot()); print()
    if input("  I confirm I am authorised [y/N] > ").strip().lower() != "y":
        _flash(col("  " + SYM_WARN + " Scan cancelled.", C.YLW))
        return

    # Tool selection
    _clear()
    selected = tool_selection_menu()
    if not selected:
        _flash(col("  " + SYM_WARN + " Scan cancelled.", C.YLW))
        return

    # Smart validation
    _clear()
    ctx = smart_validate(target, selected)

    # Output file
    out_file = preset_output
    if not out_file:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        sug = "reconframe_" + _domain(target) + "_" + ts + ".txt"
        print(); print(top())
        print(row(col("  Save report to file (blank to skip):", C.WHT)))
        print(row(col("  Suggested: " + sug, C.GRY, C.DIM)))
        print(bot()); print()
        raw = input("  Output file > ").strip()
        out_file = raw if raw else None

    cfg.record_scan()
    _clear()

    engine = ScanEngine(ctx=ctx, workers=4, rate=0.4)
    orig   = signal.getsignal(signal.SIGINT)

    def _int(sig, frame):
        print("\n  " + col(SYM_WARN + " Interrupt - stopping gracefully...", C.YLW))
        engine.stop()

    signal.signal(signal.SIGINT, _int)
    try:
        results, timings = engine.run()
    finally:
        signal.signal(signal.SIGINT, orig)

    print()
    render_results(target, results, timings, out_file, verbose=verbose)
    print()
    input("  Press ENTER to return to menu > ")

# ==============================================================================
#  HELPERS
# ==============================================================================

def _clear():
    os.system("cls" if os.name == "nt" else "clear")

def _flash(msg, delay=1.4):
    print("\n" + msg)
    time.sleep(delay)

def _prompt(p):
    return input("\n  " + p + " > ").strip()

# ==============================================================================
#  CLI
# ==============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        prog="reconframe",
        description="ReconFrame v3 - Professional Reconnaissance Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 reconframe.py                          # interactive TUI\n"
            "  python3 reconframe.py -t example.com -v        # verbose mode\n"
            "  python3 reconframe.py -t 10.0.0.1 --tools nmap,whois -o out.txt\n"
            "  python3 reconframe.py --list-tools\n"
        ),
    )
    p.add_argument("-t", "--target",  metavar="TARGET", help="Hostname, IP, or URL")
    p.add_argument("-o", "--output",  metavar="FILE",   help="Save report to file")
    p.add_argument("-v", "--verbose", action="store_true", help="Show full tool output")
    p.add_argument("--tools",         metavar="IDS",    help="Comma-separated tool IDs")
    p.add_argument("--list-tools",    action="store_true", help="List tools and exit")
    p.add_argument("--no-banner",     action="store_true", help="Skip startup animation")
    return p.parse_args()

# ==============================================================================
#  ENTRY POINT
# ==============================================================================

def main():
    signal.signal(signal.SIGINT,  lambda s, f: (print("\n\n  Goodbye.\n"), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))

    args = parse_args()
    cfg  = ConfigManager()

    # List tools and exit
    if args.list_tools:
        print(); print(top())
        print(row(center(col("AVAILABLE TOOLS", C.CYN, C.BOLD))))
        print(mid()); print(blank())
        for t in TOOLS:
            av = _avail(t["bin"])
            print(row(
                col((SYM_OK if av else SYM_ERR) + "  ", C.GRN if av else C.RED, C.BOLD) +
                col("%-16s" % t["id"], C.WHT) + "  " +
                col("%-9s"  % t["cat"],  CAT_CLR.get(t["cat"],  C.GRY)) + "  " +
                col("%-8s"  % t["risk"], RISK_CLR.get(t["risk"], C.GRY)) + "  " +
                col(t["desc"], C.GRY)
            ))
        print(blank()); print(bot()); print()
        sys.exit(0)

    # Non-interactive direct scan
    if args.target and args.tools:
        if not args.no_banner:
            _clear()
            play_startup_animation()
            print_banner()
        valid   = {t["id"] for t in TOOLS}
        sel_ids = [i.strip() for i in args.tools.split(",") if i.strip() in valid]
        if not sel_ids:
            print("\n  " + col(SYM_ERR + " No valid tool IDs. Run --list-tools.", C.RED) + "\n")
            sys.exit(1)
        ctx = ScanContext(args.target, sel_ids)
        cfg.record_scan()
        r, timings = ScanEngine(ctx).run()
        print()
        render_results(args.target, r, timings, args.output, verbose=args.verbose)
        sys.exit(0)

    # Interactive TUI
    if not args.no_banner:
        _clear()
        play_startup_animation()

    while True:
        _clear()
        print_banner()
        print_main_menu(cfg)
        print()
        choice = _prompt("Select option")

        if choice == "1":
            _clear()
            scan_flow(cfg, preset_target=args.target,
                      preset_output=args.output, verbose=args.verbose)
        elif choice == "2":
            _clear()
            print_tool_availability()
            print()
            input("  Press ENTER to go back > ")
        elif choice == "3":
            _clear()
            print_about()
            print()
            input("  Press ENTER to go back > ")
        elif choice == "0":
            print("\n  Session complete. Stay ethical.\n")
            sys.exit(0)
        else:
            _flash(col("  " + SYM_ERR + " Invalid option.", C.RED), delay=0.7)


if __name__ == "__main__":
    main()
