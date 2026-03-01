# ReconFrame

A tool that runs multiple security reconnaissance tools from one place. Instead of learning and typing separate commands for nmap, gobuster, nikto, etc., you just point ReconFrame at a target and it handles the rest.

## What it does

Give it a domain or IP address. It figures out which tools make sense, runs them, and shows you the important findings.

## Quick start

```bash
git clone https://github.com/jishnuec/reconframe.git
cd reconframe
chmod +x reconframe.py
./reconframe.py
