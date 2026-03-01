# **Complete README.md for ReconFrame**

Copy and paste this entire code:

```markdown
# 🔍 ReconFrame - Advanced Reconnaissance Framework

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0.0-00ff88.svg?style=for-the-badge&labelColor=0a0e27">
  <img src="https://img.shields.io/badge/Python-3.6+-00ff88.svg?style=for-the-badge&labelColor=0a0e27">
  <img src="https://img.shields.io/badge/License-MIT-00ff88.svg?style=for-the-badge&labelColor=0a0e27">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-00ff88.svg?style=for-the-badge&labelColor=0a0e27">
</p>

<p align="center">
  <b>A cinematic, professional-grade reconnaissance framework that unifies 12 security tools with intelligent automation.</b>
  <br>
  <i>Built for security professionals, penetration testers, and ethical hackers.</i>
</p>

---

## 📋 Table of Contents
- [✨ Overview](#-overview)
- [🔥 Key Features](#-key-features)
- [🎬 Cinematic Startup](#-cinematic-startup)
- [🧠 Smart Target Validation](#-smart-target-validation)
- [📊 Professional Output](#-professional-output)
- [📦 Installation](#-installation)
- [🚀 Usage Examples](#-usage-examples)
- [🛠️ Tool Integration](#️-tool-integration)
- [⚙️ Requirements](#️-requirements)
- [📝 Configuration](#-configuration)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [⚠️ Legal Disclaimer](#️-legal-disclaimer)

---

## ✨ Overview

**ReconFrame** transforms complex reconnaissance into an elegant, automated workflow. Unlike traditional tools that require manual command construction and output parsing, ReconFrame provides:

- **Unified Interface** - One tool to rule them all
- **Intelligent Automation** - Tools run only when applicable
- **Beautiful Output** - Color-coded, grouped findings
- **Cinematic Experience** - MSF-style startup animation

> *"ReconFrame doesn't just run tools - it orchestrates them intelligently."*

---

## 🔥 Key Features

### 🎯 12 Integrated Tools

| Category | Tools | Purpose |
|----------|-------|---------|
| **Network Scanning** | `nmap`, `sslyze` | Port discovery, service detection, SSL/TLS analysis |
| **Web Enumeration** | `gobuster`, `nikto`, `sqlmap`, `wafw00f` | Directory brute-force, vulnerability scanning, WAF detection |
| **DNS Discovery** | `subfinder`, `dnsenum`, `dnsrecon`, `amass` | Subdomain enumeration, zone transfers, DNS records |
| **OSINT Gathering** | `theharvester`, `whois` | Email harvesting, domain registration data |

### ⚡ Advanced Capabilities

| Feature | Description |
|---------|-------------|
| **Parallel Execution** | Run multiple tools simultaneously with configurable thread pool |
| **Live Progress Bar** | Real-time updates in-place (no scrolling spam) |
| **Verbose Mode** `-v` | Full raw tool output when you need details |
| **Report Generation** `-o` | Save results to clean text files |
| **Color-Coded Results** | Green (success), Red (error), Yellow (warning) |
| **Tool Availability Check** | Shows installed vs missing tools with install commands |

---

## 🎬 Cinematic Startup

Experience a Metasploit-style startup sequence:

```ascii
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

  [*] Network ........ [nmap]  [sslyze]
  [*] Web ............ [gobuster] [nikto] [sqlmap] [wafw00f]
  [*] DNS ............ [subfinder] [dnsenum] [dnsrecon] [amass]
  [*] OSINT .......... [whois] [theharvester]

  [+] 12 modules armed  |  ReconFrame is ready.
```

The animation includes:
- **Matrix-style cascade** - Green rain effect
- **Glitch logo reveal** - Scrambled text snapping into place
- **Module loading** - Category-by-category tool display
- **Armed banner** - Final ready message

---

## 🧠 Smart Target Validation

ReconFrame intelligently adapts to your target:

### 🔄 IP vs Domain Detection

```bash
# Scanning an IP? It asks for domain for DNS tools
./reconframe.py -t 54.82.22.214

┌────────────────────────────────────────────────────┐
│                 DNS TOOL WARNING                   │
├────────────────────────────────────────────────────┤
│  [!] DNS tools need a domain name, not an IP       │
│                                                     │
│  Affected tools:                                    │
│    * subfinder  Works best with domains, not IPs    │
│    * dnsenum    DNS tools need domain, not IP       │
│    * dnsrecon   DNS enumeration needs domain        │
│    * amass      Takes time - use -v for details     │
│    * theharvester Requires valid domain name        │
├────────────────────────────────────────────────────┤
│  Enter domain for DNS tools (or press Enter to skip): │
└────────────────────────────────────────────────────┘
```

### 🚦 Port Probing

Before running web tools, ReconFrame checks if ports 80/443/8080 are open:

- **No web ports?** `gobuster`, `nikto`, `sqlmap`, `wafw00f` auto-skip
- **No HTTPS?** `sslyze` auto-skips
- **Clear messages** explain why tools were skipped

### 🎯 Smart Skipping

```ascii
  SMART SKIPS:
    [~] nikto          Timed out - target may be slow or unresponsive
    [~] sslyze         SSL scan only works on HTTPS ports
    [~] dnsenum        DNS tools need domain, not IP address
```

---

## 📊 Professional Output

### Grouped Findings

```ascii
┌────────────────────────────────────────────────────┐
│                   KEY  FINDINGS                     │
├────────────────────────────────────────────────────┤
│  >> Open Ports                                      │
│     [OPEN]   80/tcp   open  http                    │
│     [OPEN]   443/tcp  open  https                   │
│     [OPEN]   22/tcp   open  ssh                     │
│                                                     │
│  >> Directories                                     │
│     [DIR]    /admin        (Status: 403)            │
│     [DIR]    /backup       (Status: 200)            │
│     [DIR]    /api          (Status: 401)            │
│                                                     │
│  >> Vulnerabilities                                 │
│     [HIGH]   SQL Injection at /api?id=1            │
│     [MEDIUM] XSS in search parameter                │
│                                                     │
│  >> SSL/TLS Issues                                  │
│     [WARN]   Expired certificate                    │
│     [WARN]   Weak cipher suite (RC4)               │
└────────────────────────────────────────────────────┘
```

### Summary Table

```ascii
┌────────────────────────────────────────────────────┐
│                      SUMMARY                        │
├────────────────────────────────────────────────────┤
│ TOOL           STATUS       TIME   CATEGORY   NOTE  │
├────────────────────────────────────────────────────┤
│ nmap          [+] Complete  45.2s  Network    3 open ports │
│ gobuster      [+] Complete  32.1s  Web        5 directories │
│ nikto         [!] Timeout   300s   Web        Target slow   │
│ whois         [+] Complete  1.2s   OSINT      AWS owned     │
└────────────────────────────────────────────────────┘
```

### Verbose Mode (`-v`)

```bash
./reconframe.py -t example.com -v
```
Shows full raw output from every tool for deep analysis.

---

## 📦 Installation

### Option 1: Clone from GitHub (Recommended)

```bash
# Clone the repository
git clone https://github.com/jishnuec/reconframe.git
cd reconframe

# Make executable
chmod +x reconframe.py

# Run immediately
./reconframe.py
```

### Option 2: Download Direct

```bash
wget https://raw.githubusercontent.com/jishnuec/reconframe/main/reconframe.py
chmod +x reconframe.py
./reconframe.py
```

---

## 🚀 Usage Examples

### Interactive Mode (Full TUI)

```bash
./reconframe.py
```
Launches the complete terminal interface with:
- Cinematic startup animation
- Main menu with options
- Tool selection with checkboxes
- Guided scan workflow

### Direct Scan Mode

```bash
# Basic scan with default tools
./reconframe.py -t example.com

# Verbose mode (see all tool output)
./reconframe.py -t 192.168.1.1 -v

# Save report to file
./reconframe.py -t example.com -o scan_results.txt

# Scan with specific tools only
./reconframe.py -t 10.0.0.1 --tools nmap,whois,gobuster

# Save verbose output to file
./reconframe.py -t example.com -v -o detailed_scan.txt
```

### Utility Commands

```bash
# List all available tools
./reconframe.py --list-tools

# Skip the startup animation
./reconframe.py --no-banner

# Get help
./reconframe.py --help
```

### Smart Domain Handling

```bash
# Scanning an IP? ReconFrame asks for domain
./reconframe.py -t 54.82.22.214
# → "Enter domain for DNS tools (or press Enter to skip them): zero.webappsecurity.com"
```

---

## 🛠️ Tool Integration Details

### Tool Matrix

| Tool | Purpose | Auto-Skip Conditions | Install Command |
|------|---------|---------------------|-----------------|
| **nmap** | Port & service discovery | Never | `sudo apt install nmap` |
| **whois** | Domain registration lookup | Never | `sudo apt install whois` |
| **gobuster** | Directory enumeration | No web ports (80/443/8080) | `sudo apt install gobuster` |
| **sqlmap** | SQL injection detection | No web ports | `sudo apt install sqlmap` |
| **wafw00f** | WAF fingerprinting | No web ports | `pip3 install wafw00f` |
| **nikto** | Web vulnerability scanner | No web ports, may timeout | `sudo apt install nikto` |
| **subfinder** | Subdomain enumeration | IP target (asks for domain) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **dnsenum** | DNS enumeration | IP target | `sudo apt install dnsenum` |
| **dnsrecon** | DNS record discovery | IP target | `sudo apt install dnsrecon` |
| **amass** | Attack surface mapping | IP target | `sudo snap install amass` |
| **theharvester** | OSINT email gathering | IP target | `sudo apt install theharvester` |
| **sslyze** | SSL/TLS analysis | No HTTPS (port 443) | `pip3 install sslyze` |

### Missing Tool Handling

```bash
# If a tool is missing, ReconFrame shows:
  [-]  WafW00f  Not installed  ->  pip3 install wafw00f
```

---

## ⚙️ Requirements

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **OS** | Linux (any) | Kali Linux |
| **Python** | 3.6 | 3.9+ |
| **RAM** | 512MB | 2GB+ |
| **Storage** | 50MB | 200MB (with tools) |

### Dependencies

ReconFrame has **ZERO Python dependencies** - it only uses the standard library!

External tools are checked at runtime with clear install instructions:

```bash
# Example: Missing nmap
[-] Not installed  ->  sudo apt install nmap
```

---

## 📝 Configuration

### Config File Location

```bash
/etc/reconframe/config.json
# or
~/.reconframe.json
```

### Config Contents

```json
{
  "total_scans": 42,
  "created_at": "2026-02-28 18:28:24.123456"
}
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute

1. **Report bugs** - Open an issue with details
2. **Suggest features** - New tool integrations, UI improvements
3. **Submit PRs** - Code fixes, new features
4. **Improve docs** - Better examples, clearer explanations

### Development Setup

```bash
# Fork the repository
git clone https://github.com/jishnuec/reconframe.git
cd reconframe

# Create feature branch
git checkout -b feature/amazing-feature

# Make changes
# Test thoroughly

# Commit and push
git commit -m "Add amazing feature"
git push origin feature/amazing-feature

# Open a Pull Request
```

---

## 📄 License

**MIT License** - Free for personal and commercial use.

```
MIT License

Copyright (c) 2026 Jishnu Ec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## ⚠️ Legal Disclaimer

### IMPORTANT - READ CAREFULLY

**ReconFrame is designed for authorized security testing ONLY.**

By using this software, you acknowledge and agree that:

1. **Authorization Required**
   - You must only scan systems you own OR have explicit written permission to test
   - Unauthorized scanning may violate laws in your jurisdiction

2. **Legal Compliance**
   - You are responsible for complying with all applicable laws
   - Different countries have different laws regarding security testing
   - Some activities may be illegal without proper authorization

3. **No Liability**
   - The authors accept NO liability for misuse of this software
   - The authors accept NO liability for any damages caused by this software
   - Use at your own risk

4. **Ethical Use**
   - This tool should only be used for legitimate security assessments
   - Help make the internet safer, not break into systems

### Examples of Authorized Use:

✅ Testing your own infrastructure  
✅ Authorized penetration tests with written contracts  
✅ Bug bounty programs with clear scope  
✅ Security research on systems you own  
✅ Educational purposes in controlled environments  

### Examples of UNAUTHORIZED Use:

❌ Scanning random IPs found on Shodan  
❌ Testing systems without permission  
❌ Using for illegal activities  
❌ Violating terms of service  
❌ Any non-consensual testing  

> **"With great power comes great responsibility."** - Use ReconFrame wisely.

---

## 🌟 Star History

If you find ReconFrame useful, please consider:
- ⭐ Starring the repository
- 🐦 Sharing on Twitter/X
- 💬 Telling your security friends
- 🤝 Contributing back

---

## 📬 Contact & Support

| Channel | Purpose |
|---------|---------|
| **GitHub Issues** | Bug reports, feature requests |
| **Email** | jishnuwhoopofficial@gmail.com |
| **Twitter** | @jishnuec |

---

## 🙏 Acknowledgements

- The security community for inspiration
- All the amazing tool authors
- Contributors and users

---

<p align="center">
  <b>Made with ⚡ for the security community</b>
  <br>
  <sub>ReconFrame v3.0 · Professional Reconnaissance Framework</sub>
  <br>
  <sub>MIT Licensed · Free for all</sub>
</p>

<p align="center">
  <a href="https://github.com/jishnuec/reconframe/stargazers">
    <img src="https://img.shields.io/github/stars/jishnuec/reconframe?style=social">
  </a>
  <a href="https://github.com/jishnuec/reconframe/network/members">
    <img src="https://img.shields.io/github/forks/jishnuec/reconframe?style=social">
  </a>
</p>
```
