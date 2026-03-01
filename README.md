# ReconFrame

A reconnaissance framework that brings together 12 security tools under one hood. No more jumping between terminals and remembering different command syntax.

## What it does

Point it at a target. It figures out what tools make sense, runs them, and shows you what matters. DNS tools when you give it a domain. Port scans first, then web tools if it finds web servers.

Comes with nmap, gobuster, nikto, sqlmap, whois, subfinder, dnsenum, dnsrecon, amass, theharvester, wafw00f and sslyze.

## Quick start

```bash
git clone https://github.com/jishnuec/reconframe.git
cd reconframe
chmod +x reconframe.py
./reconframe.py
How to use it
Interactive mode – Just run it and pick options from the menu:

bash
./reconframe.py
Direct scan – Point it at a target and go:

bash
./reconframe.py -t example.com
Save results to a file:

bash
./reconframe.py -t example.com -o results.txt
See everything (verbose mode):

bash
./reconframe.py -t example.com -v
Pick specific tools:

bash
./reconframe.py -t 10.0.0.1 --tools nmap,whois,gobuster
How it works
When you give it an IP address, it'll ask if you want to run DNS tools (they need domain names). Enter one, and it uses that just for DNS stuff while keeping the IP for network scans.

Before running web tools, it checks if ports 80, 443, or 8080 are open. Saves time instead of waiting for timeouts.

Output is grouped by type – open ports in one section, directories in another, vulnerabilities somewhere else. Color coded so you spot issues quickly.

Tools included
Tool	What it does	When it runs
nmap	Port scanning, service detection	Always
whois	Domain registration info	Always
gobuster	Directory brute-force	If web ports open
nikto	Web vulnerability scanner	If web ports open
sqlmap	SQL injection testing	If web ports open
wafw00f	WAF detection	If web ports open
subfinder	Subdomain discovery	Needs domain name
dnsenum	DNS enumeration	Needs domain name
dnsrecon	DNS record discovery	Needs domain name
amass	Attack surface mapping	Needs domain name
theharvester	Email/domain OSINT	Needs domain name
sslyze	SSL/TLS analysis	If HTTPS port open
Requirements
Linux (works on Kali, Ubuntu, Debian)

Python 3.6 or newer

The external tools listed above (script tells you how to install missing ones)

What it looks like
When you start it, there's a short animation – matrix rain, logo appears, modules load. Then you get a menu.

During a scan, you'll see a progress bar updating in place, not scrolling endlessly. When it finishes, results are grouped and colored.

Why I built this
I got tired of switching between tools, forgetting syntax, and parsing through walls of text to find what mattered. ReconFrame handles the boring parts so you can focus on the findings.

License
MIT. Free for anything.

One last thing
Only scan systems you own or have permission to test. This isn't a toy – use it responsibly.
