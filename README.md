# xs-ai — AI-Assisted Pentest Orchestrator

Local AI pentest assistant that connects Ollama models on your Windows host to an interactive client on Kali Linux. Load your cheat sheets, walk through pentest phases, and let the AI suggest commands — with human approval at every step.

```
 ██╗  ██╗███████╗       █████╗ ██╗
 ╚██╗██╔╝██╔════╝      ██╔══██╗██║
  ╚███╔╝ ███████╗█████╗███████║██║
  ██╔██╗ ╚════██║╚════╝██╔══██║██║
 ██╔╝ ██╗███████║      ██║  ██║██║
 ╚═╝  ╚═╝╚══════╝      ╚═╝  ╚═╝╚═╝
   PENTEST AI ORCHESTRATOR  v1.3
   by sudoxs
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

## What's New in v1.3

Milestone 6 — **benchmark framework** (`benchmark.py`, `benchmark/cases.json`):

- Measures the **quality of the engine's logic**, not how convincing a model sounds. The core suite is deterministic and offline (no model, no network) and runs in CI as a regression gate: `python3 benchmark.py` (non-zero exit on any failure).
- Covers service identification, CVE-relevance assessment, default-configuration research, authentication-weakness identification, hypothesis generation, attack-chain reasoning, **false-positive reduction**, evidence quality, research-source quality, and report accuracy — with per-category scores and false-positive / false-negative counts.
- Cases are JSON fixtures (data, not code), so new cases need no runner changes and the suite is provider/model-agnostic. Writing it immediately found and fixed two real issues (OpenSSH `8.2p1` version parsing; an over-eager chain expectation).

This completes the Red-Team-Researcher roadmap (Milestones 1–6).

## What's New in v1.2

Milestone 5 — **model-agnostic registry + secure connection modes**:

- **Multi-model registry** (`providers.py`, `models.json`) — declare any number of models, each with its provider (Ollama / OpenAI / Anthropic), endpoint, context size and capabilities. Assign models to roles, or let xs-ai **auto-select** by capability and context, with **graceful fallback** when a model is unavailable. Works with a single local model, several local models, or a mix of local and cloud — no GPU/VRAM assumptions. Copy `models.example.json` → `models.json` to activate; `:models` shows the routing. Without it, the existing single-backend mode is unchanged.
- **Connection modes** (`connection.py`, `--connect-mode`): **direct** (existing; warns on network exposure), **ssh-tunnel** (Ollama stays bound to localhost, reached over an SSH forward — the exact command is printed), and **vpn** (WireGuard/Tailscale overlay IP). Each prints its trust boundaries, and a connection diagnostic reports reachability, latency, and exposure. A VPN protects transport, not the Ollama API — stated explicitly.

## What's New in v1.1

Milestone 4 — **attack chain analysis**:

- **`:chains`** links separate hypotheses and findings on an asset into coherent attack scenarios (e.g. exposed interface → weak/anonymous auth → access → insecure configuration). Each chain states its steps, the evidence for the links, the **assumptions that remain unverified**, what evidence is still needed, and the potential impact.
- Chains are **reasoned scenarios, never proof** — the analyst never claims exploitation or access that wasn't demonstrated, and `not_applicable` hypotheses are excluded. Uses the `attack_chain_analyst` role with a deterministic offline fallback that links conservatively at low confidence.
- Chains persist in sessions, export bundles, and a dedicated report section.

## What's New in v1.0

Milestone 3 — **authentication assessment & safe credential validation**:

- **Five distinct authentication states**, never conflated: *no authentication*, *anonymous access accepted*, *default credential possible (documented, untested)*, *credential validated (actually accepted here)*, *unknown*.
- **`:validate <hypothesis-id>`** — safely validates a single hypothesis. Strict controls (no brute-force, ever): one documented credential or one anonymous/no-auth probe; operator approval required; scope-checked; **attempt-limited** (`--cred-attempts`, default 3) with an optional delay (`--cred-delay`); every attempt recorded as evidence on the hypothesis and in the audit trail. Services without a safe automated probe (e.g. SSH) are left for manual validation.
- **Evidence-driven status updates** — a successful probe promotes a hypothesis to `confirmed` (high confidence) and records the auth state (e.g. anonymous access); a rejection marks it `not_applicable`. A documented-default-credential hypothesis stays *possible* until actually validated.

## What's New in v0.9

Milestone 2 — the **Service Research Engine** (`research.py`): instead of jumping straight to generic enumeration, xs-ai can *research* a discovered service and produce evidence-based, ranked **vulnerability hypotheses**.

- **`:research <port>`** — fingerprints the service (from existing scan output, or a scope-gated banner grab), gathers leads from a local knowledge base (and, with `--online`, NVD), and asks the model to synthesize ranked hypotheses. Falls back to knowledge-base-only hypotheses when no model output is available, so it works with a single local model and fully offline.
- **Separate confidence and severity** — a critical bug with weak evidence is *low confidence*, never a confirmed finding. Each hypothesis records status (`confirmed` / `strongly_suspected` / `potential_config` / `unverified` / `not_applicable`), evidence, references, CVEs, preconditions, and a *safe* validation plan.
- **Honest CVE applicability** — a CVE is never reported just because it mentions the same product. The detected version is compared against affected ranges; out-of-range CVEs are dropped and unknown versions stay unverified.
- **Pluggable, offline-first sources** — `knowledge/*.json` service modules (extensible) plus a best-effort NVD adapter. The source registry is extensible (CISA KEV, GHSA, OWASP, MITRE ATT&CK can be added without touching the engine).
- **`:hypotheses`** lists what's been recorded; hypotheses persist in sessions, export bundles, and the final report.

Research/planning never execute against a target, so they are not blocked by scope; the only target interaction (an optional banner grab) goes through the scope guard.

## What's New in v0.8

Milestone 1 of the Red-Team-Researcher roadmap — security foundation:

- **Centralized, fail-closed scope enforcement** — one `ScopeGuard` validates every target-touching route (CIDR / IP / hostname aware), and blocks commands that embed any out-of-scope IP. No scope configured ⇒ execution blocked (planning still works). Opt out explicitly with `--allow-any-target`. See *Scope File & Fail-Closed Enforcement*.
- **Execution audit trail** — every execute / block / approval / scope change is logged as JSON lines to `audit.log` (`--audit-log`).
- **Runtime scope control** — `:scope show | add <t> | clear`.
- **Extended role vocabulary** — model-agnostic research roles (`lead_researcher`, `recon_analyst`, `service_researcher`, `web_researcher`, `vuln_analyst`, `attack_chain_analyst`, `validation_analyst`, `report_analyst`) assignable via `:roles`/`--role`, each falling back to an existing capability so single-model setups keep working.

(These later shipped in v0.9–v1.3: Service Research Engine, vulnerability hypotheses with evidence/confidence, attack-chain analysis, multi-model registry, secure connection modes, and the benchmark framework.)

## What's New in v0.7

Engagement memory and multi-operator handoff:

- **Re-test guard** — xs-ai remembers every command already run (including work imported from another analyst). Before re-running one, it warns and asks for separate confirmation, and `:auto` / `:svc` skip already-completed checks by default. Force a repeat with `:auto redo` or `:svc <port> redo`.
- **Handoff bundles** — `:export [file]` writes a self-contained bundle (target, phase, OS, credentials, findings, full command history, embedded project memory). Another operator runs `:import <file>` (or `--import FILE` at startup) to **merge** it into their own session. Commands are de-duplicated by normalized command + phase, so overlapping or repeated imports never double-count — and the merged history immediately feeds *their* re-test guard, so they never redo what you already did. Imported commands are tagged `[from <file>]` and the final report gains a "Continued from" line.

## What's New in v0.6

Built to keep small local models (7B/8B) sharp under real engagement load:

- **Context retrieval (RAG)** — instead of dumping every cheat sheet and every past output and truncating, a pure-stdlib TF-IDF retriever feeds the model only the notes and evidence relevant to what you just asked. No embeddings, no dependencies.
- **Output distillation** — huge tool output (nmap, enum4linux, linpeas) is condensed to the signal-dense lines (open ports, `VULNERABLE`, creds, errors) plus context before it reaches the model. The **full, untouched output is always kept** in the report and the auto-saved session JSON — distillation only trims the copy sent to the AI.
- **Structured JSON responses** — the model replies with a schema-constrained JSON object (Ollama `format`, OpenAI `response_format`, Anthropic prefill), which cuts format errors on small models. A tolerant parser handles fenced/prose-wrapped JSON and unescaped control characters, and automatically falls back to the legacy `CMD:` protocol. Disable with `--no-structured`.
- **Dynamic service discovery** — `:svc <port>` on a port with no built-in checklist now banner-grabs the service and asks the AI for tailored, read-only checks. Unusual services and non-standard ports stop getting generic suggestions.
- **Parallel auto-enum** — `--parallel` runs independent enumeration checks concurrently after a single batch approval (3 at a time), speeding up the slow I/O-bound scans without breaking the per-command approval model.
- **Persistent SSH** — remote commands reuse one multiplexed master connection (ControlMaster/ControlPersist), with stale-socket cleanup so a dropped session never blocks the next connect.

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
| `--no-structured` | | Disable schema-constrained JSON responses; use the legacy `CMD:` text protocol |
| `--parallel` | | Run auto-enum checks concurrently after one batch approval |
| `--import` | | Merge another operator's handoff bundle at startup (repeatable) |
| `--allow-any-target` | | Disable fail-closed scope enforcement (lab use only; prints a warning) |
| `--audit-log` | `audit.log` | Execution/approval audit trail file |
| `--online` | | Allow the research engine to query external sources (e.g. NVD); off by default (offline KB only) |
| `--cred-attempts` | `3` | Max validation attempts per hypothesis (no brute-force) |
| `--cred-delay` | `0` | Seconds between validation attempts |
| `--models` | `models.json` | Multi-model registry file; when present, routes roles across models |
| `--connect-mode` | `direct` | Connection mode: `direct`, `ssh-tunnel`, or `vpn` |

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
| `:scope [show\|add <t>\|clear]` | Show or modify the authorized target scope |
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
| `:auto [redo]` | Run auto-enum checks for current phase (use `--parallel` for concurrent batch mode). `redo` re-runs checks already done |
| `:ports` | Detect open ports and show available service checks |
| `:svc <port> [redo]` | Service-specific enum for a port (e.g. `:svc 445`); unknown ports → AI-generated dynamic checks. `redo` re-runs completed checks |
| `:research <port>` | Research a service → ranked, evidence-based vulnerability hypotheses |
| `:hypotheses` | List recorded research hypotheses |
| `:validate <id>` | Safely validate one hypothesis (approval + scope + attempt-limited, no brute-force) |
| `:chains` | Link findings/hypotheses into attack-chain scenarios |
| `:tools` | Show downloadable tool suggestions for current phase |
| `:install` | Check & install missing tools on Kali |

#### Session & Memory

| Command | Description |
|---------|-------------|
| `:memory` | Save project memory (project.md) for next session |
| `:roles` | Show/set model-to-role mapping for each phase |
| `:models` | Show the multi-model registry and role routing |
| `:memory show` | Display current project memory |

#### Session Management

| Command | Description |
|---------|-------------|
| `:findings` | Show all findings discovered so far |
| `:history` | Show full command history |
| `:report` | Generate markdown report |
| `:save [file]` | Save session state to JSON |
| `:load <file>` | Load a saved session (replaces current) |
| `:export [file]` | Export a handoff bundle to share with another operator |
| `:import <file>` | Merge another operator's bundle into the current session |
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

By default (v0.6+) the model replies with a schema-constrained JSON object:

```json
{
  "message": "short analysis / next step",
  "command": "one command to run next, or null",
  "findings": ["notable discovery", ...],
  "needs": ["info needed from operator", ...],
  "access": "initial-access one-liner, or null",
  "tools": ["download-only tool — what it does", ...],
  "done": false,
  "done_summary": ""
}
```

The parser tolerates fenced/prose-wrapped JSON and unescaped control characters, and automatically falls back to the legacy tag protocol below (also used when you pass `--no-structured`):

| Tag | Meaning |
|-----|---------|
| `CMD:` | Suggested command to execute (you approve/edit/skip) |
| `FINDING:` | Notable discovery |
| `NEED:` | Information needed from operator |
| `ACCESS:` | Working initial access one-liner |
| `TOOL:` | Downloadable tool suggestion with instructions |
| `DONE:` | Phase complete or stuck |

## Cheat Sheets

Put your engagement notes in `cheatsheets/` as `.md` or `.txt` files. xs-ai loads them all and, per prompt, retrieves only the chunks relevant to what you're asking (v0.6) — so you can keep large note collections without flooding the model's context window.

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

## Scope File & Fail-Closed Enforcement

`scope.json` lists the targets you are authorized to test. Entries may be exact IPs, **CIDR ranges**, or hostnames:

```json
{
  "allowed_targets": [
    "10.10.110.0/24",
    "192.168.1.50",
    "box.htb"
  ]
}
```

**Scope enforcement is centralized and fail-closed (v0.8+).** Every route that touches a target — auto-enum, parallel checks, service checks, `:scan`/`:fullscan`/`:ports`/`:svc`, `:run`/`:rrun`, SSH connect, and AI-suggested commands — is validated through one `ScopeGuard`. Authorization never depends on the model "remembering" the scope. A command is also blocked if it embeds *any* out-of-scope IP, so an AI suggestion can't reach a host you didn't authorize.

If no scope is configured, **execution is blocked** (research and planning still work). Authorize targets in any of these ways:

- a `scope.json` file (default path, or `--scope <file>`),
- `--target <ip>` on the command line (naming a target authorizes that one host),
- `:scope add <target>` at runtime (`:scope show` / `:scope clear` too),
- `--allow-any-target` to disable enforcement entirely (prints a loud warning — lab use only).

Every execution, block, approval, and scope change is written to an **audit trail** (`audit.log` by default, or `--audit-log <file>`) as JSON lines.

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

## Engagement Handoff & Re-test Guard

xs-ai remembers what has already been run and lets you hand a partially-completed engagement to another operator.

**Re-test guard** — every command is recorded. Before re-running one, xs-ai warns and asks for separate confirmation; `:auto` and `:svc` skip already-completed checks by default. Force a repeat with `redo`:

```
[enum]> :auto                # skips checks already done, runs only new ones
[enum]> :auto redo           # re-runs everything
[enum]> :svc 445 redo        # re-run SMB checks even if done before
```

**Handoff** — operator A exports a bundle; operator B imports it and continues:

```
# Operator A, after some testing
[enum]> :export                      # sessions/handoff_10_10_110_5_<ts>.json
# ...sends the file to operator B...

# Operator B, on their own machine
python3 client.py --host 192.168.198.1 --import handoff_10_10_110_5.json
# or at runtime:
[recon]> :import handoff_10_10_110_5.json
  Imported from handoff_10_10_110_5.json:
    +12 commands, +4 findings, +1 credentials
```

The bundle carries target, phase, OS, credentials, findings, the full command history, and the embedded project memory. On import, commands are de-duplicated by normalized command + phase (so overlapping or repeated imports never double-count), and the merged history immediately drives operator B's re-test guard — they won't redo what A already did. Imported commands are tagged `[from <file>]`, and the final report gains a "Continued from" line recording the handoff.

## Reports

Reports are generated as markdown in `reports/` with:

- Summary table (target, OS, date, command count)
- All findings
- Useful results with full output
- Complete command history table
- Commands that produced no results

Reports store the **full captured output** of every command, never the distilled copy the AI sees. On exit, xs-ai also auto-saves the complete session JSON (untruncated outputs) under `sessions/`, so the raw evidence always survives on disk.

Generated automatically on `:quit` or manually with `:report`.

## Project Structure

```
xs-ai/
├── client.py           # Main interactive client (Kali)
├── research.py         # Service Research Engine (optional; imported if present)
├── providers.py        # Multi-model registry + routing (optional)
├── connection.py       # Connection modes + diagnostics (optional)
├── benchmark.py        # Offline quality benchmark (CI regression gate)
├── benchmark/cases.json # Benchmark fixtures (data; extensible)
├── models.example.json # Copy to models.json to enable multi-model routing
├── knowledge/          # Extensible per-service research modules (*.json)
│   ├── http.json
│   ├── ssh.json
│   ├── ftp.json
│   └── redis.json
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
