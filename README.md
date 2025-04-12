# ScanParadis v1.10 - Telegram Security Scanner Bot

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Telegram](https://img.shields.io/badge/Telegram-Bot-green.svg)

A Telegram bot for performing basic security scans and network reconnaissance tasks.

## Features

- **Port Scanning**:
  - IPv4 port scanning (`/IPv4scan`)
  - IPv6 port scanning (`/IPv6scan`)
- **Web Analysis**:
  - WAF detection (`/wafcheck`)
  - Web server fingerprinting (`/whatweb`)
- **Network Recon**:
  - DNS resolution (`/nslookup`)
  - WHOIS lookups (`/whois`)
- **Security Checks**:
  - Default credentials search (`/creds`)

## Requirements

- Python 3.x
- Required Python packages:
  - `pyTelegramBotAPI`
  - `python-whois`
- System utilities:
  - `nmap`
  - `wafw00f`
  - `whatweb`
  - `host` (dnsutils)
  - `whois`
  - DefaultCreds-cheat-sheet (for `/creds` command)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/scanparadis.git
   cd scanparadis

2. Install requirements      
    pip install -r requirements.txt

3.  Install tools
    sudo apt install nmap wafw00f whatweb dnsutils whois
    git clone https://github.com/NetSPI/DefaultCreds-cheat-sheet.git /opt/DefaultCreds-cheat-sheet

4.  Update config.json with your Telegram bot token

## Usage

    python3 scanparadis.py

## Available Commands

    /start - Initial greeting
    /help - Show all available commands
    /IPv4scan - Scan IPv4 address for open ports
    /IPv6scan - Scan IPv6 address for open ports
    /wafcheck - Check for WAF presence
    /whatweb - Identify web technologies
    /nslookup - Perform DNS resolution
    /whois - Get WHOIS information
    /creds - Search for default credentials

## Security Note

This bot is intended for legal security testing only. Always obtain proper authorization before scanning any systems.

GNU General Public License v3.0

Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. THE AUTHOR IS NOT RESPONSIBLE FOR ANY ILLEGAL USE OF THIS TOOL.
