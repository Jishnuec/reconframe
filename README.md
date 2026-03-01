# ReconFrame

A tool that runs multiple security reconnaissance tools from one place. Instead of learning and typing separate commands for nmap, gobuster, nikto, etc., you just point ReconFrame at a target and it handles the rest.

## What it does

Give it a domain or IP address. It figures out which tools make sense, runs them, and shows you the important findings.


git clone https://github.com/jishnuec/reconframe.git
cd reconframe
chmod +x reconframe.py
./reconframe.py
<<<<<<< HEAD

How to use it
Interactive mode – Just run it and pick options from the menu:
./reconframe.py

Direct scan – Point it at a target and go:
./reconframe.py -t example.com

Save results to a file:
./reconframe.py -t example.com -o results.txt

See everything (verbose mode):
./reconframe.py -t example.com -v

Pick specific tools:
./reconframe.py -t 10.0.0.1 --tools nmap,whois,gobuster
How it works
When you give it an IP address, it'll ask if you want to run DNS tools (they need domain names). Enter one, and it uses that just for DNS stuff while keeping the IP for network scans.
=======
```

## How to use it

**Interactive mode** – Run it with no arguments to get a menu:
```bash
./reconframe.py
```

**Quick scan** – Point it at a target and go:
```bash
./reconframe.py -t example.com
```

**Save output** to a file:
```bash
./reconframe.py -t example.com -o results.txt
```

**See everything** (verbose mode):
```bash
./reconframe.py -t example.com -v
```

## What's included
>>>>>>> 8010dcd (Simplify README)

- **nmap** – Port scanning
- **gobuster** – Find directories  
- **nikto** – Web vulnerabilities
- **sqlmap** – SQL injection tests
- **whois** – Domain info
- **subfinder**, **dnsenum**, **dnsrecon**, **amass** – DNS enumeration
- **theharvester** – Email/domain OSINT
- **wafw00f** – WAF detection
- **sslyze** – SSL/TLS analysis

## Requirements

- Linux (Kali, Ubuntu, Debian)
- Python 3.6 or newer
- The tools above (script tells you how to install missing ones)

## License

MIT. Free for anything.

## Note

Only scan systems you own or have permission to test.
