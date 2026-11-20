# xs-ai — AI-Assisted Pentest Orchestrator

Local AI pentest assistant that connects Ollama models on your Windows host to an interactive client on Kali Linux. Load your cheat sheets, walk through pentest phases, and let the AI suggest commands — with human approval at every step.

```
 ___  _____        ___  _____
 \  \/  /  ___    /   \/  _  \ ___
  >    <   \_ \  / /\  \  ___// _ \
 /__/\__\.__) /_/  \_/\__|  /_/ \_\
  Pentest AI Assistant  v0.5
```

## How It Works

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│  Windows     │  HTTP   │  Kali VM     │  SSH    │  Target      │
│  Host        │◄───────►│  client.py   │◄───────►│  Machine     │
│  (Ollama)    │ :11434  │              │         │              │
│              │         │  - AI plans  │         │  - Enum      │
│  WhiteRabbit │         │  - You approve│        │  - Privesc   │
│  Qwen 2.5   │         │  - It runs   │         │  - Access    │
└──────────────┘         └──────────────┘         └──────────────┘
```

- **Windows host** runs Ollama with two models (planner + executor)
- **Kali client** connects to the AI, loads your engagement notes, and walks through phases
- **You approve** every command before it runs — nothing executes without your say
- **Tool split**: built-in commands run directly; tools needing download are suggested with instructions

## Quick Start

### 1. Windows Host Setup

```powershell
# Clone the repo
git clone https://github.com/sudoxs/xs-ai.git
cd xs-ai

# Run setup (elevated PowerShell recommended for firewall rule)
.\host_setup.ps1
```

This will:
- Check Ollama installation and pull required models
- Set `OLLAMA_HOST=0.0.0.0:11434` so Kali can connect
- Add a Windows Firewall rule (Private profile, TCP 11434)
- Restart Ollama and show your connection IPs

### 2. Kali Client Setup

```bash
# Clone the repo
git clone https://github.com/sudoxs/xs-ai.git
cd xs-ai

# No dependencies needed — pure Python 3 stdlib

# Connect to your Windows host
python3 client.py --host <WINDOWS_IP>
```

### 3. Test the Connection

```bash
# From Kali, verify Ollama is reachable
curl -sS http://<WINDOWS_IP>:11434/api/tags
```

## Usage

### Basic Commands

```
python3 client.py --host 192.168.198.1
python3 client.py --host 192.168.198.1 --target 10.10.110.123
python3 client.py --host 192.168.198.1 --cheatsheet notes.md --phase enum
python3 client.py --host 192.168.198.1 --load sessions/saved.json
python3 client.py --host 192.168.198.1 --os-type linux --phase privesc
```

### CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--host` | *(required)* | Ollama host IP (your Windows machine) |
| `--port` | `11434` | Ollama port |
| `--target` | *(prompt)* | Target IP to test |
| `--scope` | `scope.json` | Scope file (restricts allowed targets) |
| `--cheatsheet` | `cheatsheets/` | Cheat sheet file or directory (repeatable) |
| `--phase` | `recon` | Starting phase |
| `--planner-model` | `WhiteRabbitNeo/...` | Planner model name |
| `--executor-model` | `qwen2.5-coder:7b` | Executor/analyzer model name |
| `--report-dir` | `reports/` | Report output directory |
| `--load` | | Load a saved session |
| `--os-type` | | Target OS (`linux` or `windows`) |
| `--api` | `ollama` | AI backend: `ollama`, `openai`, or `anthropic` |
| `--api-key` | | API key for cloud backends (or set `XS_API_KEY` env) |
| `--api-url` | | Custom API base URL |
| `--no-memory` | | Don't load/save project memory |
| `--roles` | `roles.json` | Role mapping config file |
| `--role` | | Inline role mapping (e.g. `--role recon=llama3.1:8b`) |

### Role Mapping (Multi-Model)

Assign different models to different phases or tasks:

```bash
# Use different models per phase
python3 client.py --host 192.168.198.1 \
  --role recon=llama3.1:8b \
  --role privesc=deepseek-coder:33b \
  --role reporter=qwen2.5-coder:7b

# Set a fallback for all planning phases (recon + enum)
python3 client.py --host 192.168.198.1 \
  --role planner=qwen2.5:14b
```

Roles can target phases directly (`recon`, `enum`, `access`, `privesc`, `report`) or abstract roles (`planner`, `analyzer`, `reporter`). Phase overrides take priority over abstract roles.

At runtime, use `:roles` to view, modify, and save mappings:

```
[recon]> :roles                        # Show current mapping
[recon]> :roles recon llama3.1:8b      # Assign model to phase
[recon]> :roles planner qwen2.5:14b    # Set fallback for planning phases
[recon]> :roles save                   # Persist to roles.json
[recon]> :roles rm recon               # Remove a phase override
[recon]> :roles clear                  # Reset all overrides
```

Role chain: `phase -> abstract role -> default planner/executor`

| Phase | Fallback Role | Default Model |
|-------|--------------|---------------|
| recon | planner | WhiteRabbitNeo |
| enum | planner | WhiteRabbitNeo |
| access | analyzer | qwen2.5-coder:7b |
| privesc | analyzer | qwen2.5-coder:7b |
| report | reporter | qwen2.5-coder:7b |

### Cloud API (OpenAI / Anthropic)

```bash
# Use OpenAI instead of local Ollama
python3 client.py --host ignored --api openai --api-key sk-...

# Use Anthropic Claude
python3 client.py --host ignored --api anthropic --api-key sk-ant-...

# Custom endpoint (e.g. Azure OpenAI, local vLLM)
python3 client.py --host ignored --api openai --api-key KEY --api-url http://localhost:8000/v1
```

> **Warning:** Cloud API mode sends command outputs and target info to external servers. Do not use on engagements with strict data-handling requirements. Cloud models may also refuse some offensive commands.

### Interactive Commands

Once inside the client, you have these commands:

#### Navigation & Setup

| Command | Description |
|---------|-------------|
| `<text>` | Talk to the AI — describe what you want |
| `:phase <name>` | Switch phase: `recon`, `enum`, `access`, `privesc`, `report` |
| `:target <ip>` | Change target IP |
| `:os linux\|windows` | Set target OS (affects auto-enum and tool suggestions) |
| `:cred <user> [pass]` | Set credentials (password prompted if omitted) |
| `:status` | Show current session status |
| `:help` | Show all commands |
| `:quit` | Exit (auto-generates report) |

#### SSH & Execution

| Command | Description |
|---------|-------------|
| `:ssh [user@host]` | Connect SSH to target |
| `:ssh-key <path>` | Set SSH private key file |
| `:disconnect` | Disconnect SSH session |
| `:run <cmd>` | Run a command locally (on Kali) |
| `:rrun <cmd>` | Run a command remotely (via SSH on target) |
| `:shell` | Manual shell-paste mode (for existing sessions) |

#### Scanning & Enumeration

| Command | Description |
|---------|-------------|
| `:scan` | Quick nmap scan (top 100 ports) |
| `:fullscan` | Full nmap scan (all 65535 ports) |
| `:auto` | Run auto-enum checks for current phase |
| `:ports` | Detect open ports and show available service checks |
| `:svc <port>` | Run service-specific enum for a port (e.g. `:svc 445`) |
| `:tools` | Show downloadable tool suggestions for current phase |
| `:install` | Check & install missing tools on Kali |

#### Session & Memory

| Command | Description |
|---------|-------------|
| `:memory` | Save project memory (project.md) for next session |
| `:roles` | Show/set model-to-role mapping for each phase |
| `:memory show` | Display current project memory |

#### Session Management

| Command | Description |
|---------|-------------|
| `:findings` | Show all findings discovered so far |
| `:history` | Show full command history |
| `:report` | Generate markdown report |
| `:save [file]` | Save session state to JSON |
| `:load <file>` | Load a saved session |
| `:cheat <file>` | Load an additional cheat sheet |

## Pentest Workflow

### Phase 1: Recon

```
[recon]> :scan                          # Quick port scan
[recon]> :fullscan                      # Full port scan if needed
[recon]> :auto                          # Run all recon checks
[recon]> :ports                         # See which services have enum checks
```

### Phase 2: Enumeration

```
[recon]> :phase enum
[enum]> :svc 80                         # HTTP-specific checks
[enum]> :svc 445                        # SMB-specific checks
[enum]> :svc 21                         # FTP-specific checks
[enum]> :auto                           # General enum checks
[enum]> tell me what you found so far   # Ask AI to summarize
```

### Phase 3: Initial Access

```
[enum]> :phase access
[access]> :cred admin Password123       # Set found credentials
[access]> :tools                        # See tool suggestions (chisel, etc.)
[access]> try SSH with the creds        # AI suggests: CMD: ssh admin@target
[access]> :ssh admin@10.10.110.123      # Connect SSH when you have creds
```

### Phase 4: Privilege Escalation

```
[access]> :phase privesc
[access]> :os linux                     # Set target OS
[privesc]> :auto                        # Run all 28 Linux privesc checks
[privesc]> :tools                       # See suggestions (linpeas, pspy, etc.)
[privesc]> check if we have SeImpersonate   # AI checks and suggests Potato
[privesc]> :report                      # Generate final report
```

## Service-Specific Enumeration

The `:svc <port>` command runs targeted checks for 14 services:

| Port | Service | Checks |
|------|---------|--------|
| 21 | FTP | Anonymous login, banner, bounce |
| 22 | SSH | Banner, algorithms, auth methods |
| 25/587 | SMTP | Commands, open relay, user enum |
| 53 | DNS | Version, brute, zone transfer |
| 80/443/8080 | HTTP | Headers, robots, .git, dirs, nikto, WordPress |
| 111/2049 | NFS | Exports, mount scripts |
| 139/445 | SMB | Null session, enum4linux, signing, MS17-010 |
| 161 | SNMP | Community strings, system/process/software enum |
| 389/636 | LDAP | Anonymous bind, base search |
| 1433 | MSSQL | Info, empty password, brute |
| 3306 | MySQL | Info, empty root, variables |
| 3389 | RDP | Version, encryption, NLA |
| 5985/5986 | WinRM | Version check, brute |
| 6379 | Redis | INFO, CONFIG dump |

## Tool Suggestions

xs-ai distinguishes between **direct execution** and **suggest-only** tools:

### Direct Execution (built-in commands)

These run immediately with your approval:
nmap, curl, gobuster, nikto, enum4linux, smbclient, rpcclient, ldapsearch, snmpwalk, dig, whatweb, wpscan, hydra, hashcat, john, searchsploit, crackmapexec, redis-cli, ftp, ssh, id, whoami, sudo -l, find, getcap, ps, ss, netstat, systeminfo, net, reg query, schtasks, wmic, icacls, and more.

### Suggest-Only (need download)

These are **not executed** — xs-ai checks prerequisites and shows download + usage commands:

| Tool | OS | Phase | What It Does |
|------|----|-------|-------------|
| linpeas | Linux | privesc | Comprehensive privilege escalation audit |
| winPEAS | Windows | privesc | Windows privilege escalation audit |
| pspy | Linux | privesc | Monitor processes without root |
| PrintSpoofer | Windows | privesc | SeImpersonate exploit (Win10/Server 2016+) |
| GodPotato | Windows | privesc | Universal Potato for SeImpersonate |
| SigmaPotato | Windows | privesc | Alternative SeImpersonate exploit |
| JuicyPotato | Windows | privesc | SeImpersonate (older Windows) |
| PwnKit | Linux | privesc | CVE-2021-4034 polkit pkexec exploit |
| DirtyPipe | Linux | privesc | CVE-2022-0847 kernel exploit |
| Baron Samedit | Linux | privesc | CVE-2021-3156 sudo heap overflow |
| traitor | Linux | privesc | Automated Linux privesc |
| Mimikatz | Windows | privesc | Credential harvesting |
| PowerUp | Windows | privesc | PowerShell privesc audit |
| chisel | Any | access | TCP/UDP tunneling for pivoting |
| ligolo-ng | Any | access | Advanced tunneling/pivoting |
| php_filter_chain | Any | access | LFI-to-RCE without file upload |
| git-dumper | Any | enum | Dump exposed .git directories |

Use `:tools` to see relevant suggestions for your current phase and OS.

## AI Protocol

The AI communicates using these tags:

| Tag | Meaning |
|-----|---------|
| `CMD:` | Suggested command to execute (you approve/edit/skip) |
| `FINDING:` | Notable discovery |
| `NEED:` | Information needed from operator |
| `ACCESS:` | Working initial access one-liner |
| `TOOL:` | Downloadable tool suggestion with instructions |
| `DONE:` | Phase complete or stuck |

## Cheat Sheets

Put your engagement notes in `cheatsheets/` as `.md` or `.txt` files. The AI loads them all automatically for context.

```markdown
# My Engagement Notes

## Target Info
- IP: 10.10.110.123
- OS: Linux (Ubuntu 20.04)
- Found: SSH(22), HTTP(80), MySQL(3306)

## Credentials Found
- admin:Password123 (from web login)

## Progress
- [x] Port scan done
- [x] Web enum — found SQLi on /login
- [ ] Try SSH with found creds
- [ ] Privesc
```

You can also load cheat sheets at runtime:
```
[enum]> :cheat /path/to/new_notes.md
```

## Project Memory

xs-ai automatically saves a `project.md` file when you exit. This file contains an AI-readable summary of your engagement:

- Target info (IP, OS, phase)
- Open ports discovered
- All findings
- Credentials used
- What commands worked / didn't work
- Suggested next steps

On next startup, xs-ai loads `project.md` automatically — the AI knows exactly where you left off.

```
# First session
[privesc]> :quit
[*] Project memory saved: project.md

# Next day — AI picks up where you left off
python3 client.py --host 192.168.198.1
[OK] Project memory loaded (project.md)
```

You can also save/view manually:
```
[enum]> :memory              # Save now
[enum]> :memory show         # View current state
```

Disable with `--no-memory`.

## Tool Installation

Run `:install` to check which tools are available on your Kali system. xs-ai checks 26 common pentest tools and offers to install missing ones:

```
[recon]> :install
  Checking 26 tools...
  Missing tools: whatweb, wpscan, crackmapexec
    whatweb: apt install -y whatweb
    wpscan: apt install -y wpscan || gem install wpscan
    crackmapexec: apt install -y crackmapexec || pip3 install crackmapexec
  Install missing tools? [y/n/select]: select
    Install whatweb? [y/n]: y
    Installing whatweb...
    whatweb installed OK
```

## Scope File

`scope.json` restricts which targets can be used:

```json
{
  "allowed_targets": [
    "10.10.110.123",
    "10.10.110.124"
  ]
}
```

If a target is not in scope, xs-ai refuses to scan it.

## Session Save/Load

Sessions are saved as JSON and include all commands, findings, and credentials:

```
[privesc]> :save                          # Auto-named: sessions/session_10_10_110_123_20261120_143022.json
[privesc]> :save sessions/dante_box1.json # Custom name
```

Load a previous session:
```bash
python3 client.py --host 192.168.198.1 --load sessions/dante_box1.json
```

## Reports

Reports are generated as markdown in `reports/` with:

- Summary table (target, OS, date, command count)
- All findings
- Useful results with full output
- Complete command history table
- Commands that produced no results

Generated automatically on `:quit` or manually with `:report`.

## Project Structure

```
xs-ai/
├── client.py           # Main interactive client (Kali)
├── host_setup.ps1      # Windows host setup script
├── scope.json          # Allowed targets
├── project.md          # Auto-generated project memory (AI-readable)
├── cheatsheets/        # Your engagement notes (.md/.txt)
│   └── example.md
├── sessions/           # Saved sessions (auto-created, gitignored)
├── reports/            # Generated reports (auto-created, gitignored)
└── README.md
```

## Network Setup

xs-ai is designed for a VMware Host-only network:

```
Windows Host (192.168.198.1)    ← Ollama AI backend
       │
  VMnet1 (Host-only)
       │
Kali VM (192.168.198.*)         ← xs-ai client
       │
  VMnet8 (NAT) or other
       │
Target machines                 ← Pentest targets
```

The host setup script configures Ollama to listen on `0.0.0.0:11434` and adds a firewall rule for the Private network profile only.

## Models

Default models:
- **Planner**: `WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B` — optimized for security/pentest planning
- **Executor**: `qwen2.5-coder:7b` — fast code/command analysis

You can use any Ollama model:
```bash
python3 client.py --host 192.168.198.1 \
  --planner-model "llama3.1:8b" \
  --executor-model "codellama:7b"
```

## Requirements

- **Windows host**: Ollama installed ([ollama.com](https://ollama.com)), PowerShell 5.1+
- **Kali client**: Python 3.10+ (no pip dependencies — pure stdlib)
- **Network**: Host-only adapter between Windows and Kali

## Security Notes

- All commands require explicit operator approval before execution
- Scope enforcement prevents testing unauthorized targets
- Sessions and reports are gitignored by default
- In Ollama mode: no data is sent to external services — everything stays local
- Cloud API mode shows a security warning — data is sent to the provider
- The AI runs on your local Ollama instance by default

## License

For authorized security testing and educational use only.
