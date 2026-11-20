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
import json
import os
import re
try:
    import readline  # noqa: F401 — enables input() line editing on Linux
except ImportError:
    pass
import shlex
import socket
import subprocess
import sys
import textwrap
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

PHASES = ["recon", "enum", "access", "privesc", "report"]

BANNER = r"""
 ___  _____        ___  _____
 \  \/  /  ___    /   \/  _  \ ___
  >    <   \_ \  / /\  \  ___// _ \
 /__/\__\.__) /_/  \_/\__|  /_/ \_\
  Pentest AI Assistant  v0.2
"""

# ---------------------------------------------------------------------------
# Built-in check catalogs for auto-enum
# ---------------------------------------------------------------------------

RECON_CHECKS = [
    ("Quick TCP scan (top 100)", "nmap -Pn -sV --version-light --top-ports 100 -T3 {target}"),
    ("Full TCP scan (all ports)", "nmap -Pn -p- -T4 --min-rate 1000 {target}"),
    ("UDP top 20", "nmap -Pn -sU --top-ports 20 -T3 {target}"),
    ("OS detection", "nmap -Pn -O {target}"),
]

ENUM_LINUX_CHECKS = [
    ("SSH banner grab", "nmap -Pn -p22 -sV {target}"),
    ("HTTP headers", "curl -sI http://{target}/ --connect-timeout 5"),
    ("HTTPS headers", "curl -skI https://{target}/ --connect-timeout 5"),
    ("HTTP robots.txt", "curl -s http://{target}/robots.txt --connect-timeout 5"),
    ("Gobuster dirs", "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 20 -q 2>/dev/null || echo 'gobuster not installed'"),
    ("SMB shares", "smbclient -N -L //{target}/ 2>/dev/null || echo 'smbclient not available or SMB not open'"),
    ("RPCClient null session", "rpcclient -U '' -N {target} -c 'enumdomusers' 2>/dev/null || echo 'rpcclient failed'"),
    ("SNMP community check", "snmpwalk -v2c -c public {target} 2>/dev/null | head -30 || echo 'snmpwalk not available or SNMP not open'"),
]

ENUM_WINDOWS_CHECKS = [
    ("SMB shares", "smbclient -N -L //{target}/ 2>/dev/null || echo 'smbclient not available'"),
    ("Enum4linux", "enum4linux -a {target} 2>/dev/null | head -100 || echo 'enum4linux not installed'"),
    ("RPCClient null session", "rpcclient -U '' -N {target} -c 'enumdomusers;enumdomgroups' 2>/dev/null || echo 'rpcclient failed'"),
    ("LDAP anonymous bind", "ldapsearch -x -H ldap://{target} -b '' -s base namingContexts 2>/dev/null || echo 'ldapsearch not available or LDAP not open'"),
    ("WinRM check", "nmap -Pn -p5985,5986 -sV {target}"),
    ("RDP check", "nmap -Pn -p3389 -sV {target}"),
]

PRIVESC_LINUX_CHECKS = [
    ("Current user", "id; whoami; hostname"),
    ("Kernel info", "uname -a; cat /etc/os-release 2>/dev/null"),
    ("Sudo permissions", "sudo -n -l 2>&1"),
    ("SUID binaries", "find / -perm -4000 -type f 2>/dev/null | head -40"),
    ("Capabilities", "getcap -r / 2>/dev/null | head -30"),
    ("Writable /etc files", "find /etc -writable -type f 2>/dev/null"),
    ("Cron jobs", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron* 2>/dev/null; crontab -l 2>/dev/null"),
    ("Running services", "ps aux --sort=-rss | head -30"),
    ("Interesting files", "find / -name '*.bak' -o -name '*.old' -o -name '*.conf' -o -name '*password*' -o -name '*secret*' 2>/dev/null | grep -v proc | head -30"),
    ("Network connections", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
    ("Home directories", "ls -la /home/ 2>/dev/null; ls -la /root/ 2>/dev/null"),
    ("Writable PATH dirs", "for d in $(echo $PATH | tr ':' ' '); do [ -w \"$d\" ] && echo \"WRITABLE: $d\"; done"),
    ("Docker/LXC check", "id | grep -i docker; ls -la /var/run/docker.sock 2>/dev/null; cat /proc/1/cgroup 2>/dev/null | head -5"),
]

PRIVESC_WINDOWS_CHECKS = [
    ("Current user", "whoami /all"),
    ("System info", "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\" /C:\"Domain\""),
    ("Token privileges", "whoami /priv"),
    ("Local admins", "net localgroup Administrators"),
    ("Services with weak perms", "wmic service get name,pathname,startmode,startname 2>nul | findstr /i /v \"C:\\Windows\" | head -30"),
    ("Scheduled tasks", "schtasks /query /fo TABLE /nh 2>nul | head -30"),
    ("Unquoted service paths", "wmic service get name,displayname,pathname,startmode 2>nul | findstr /i /v \"C:\\Windows\\\" | findstr /i /v \"\\\"\""),
    ("AlwaysInstallElevated", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul"),
    ("Stored credentials", "cmdkey /list"),
    ("Network connections", "netstat -ano | findstr LISTENING"),
]


# ---------------------------------------------------------------------------
# Ollama client
# ---------------------------------------------------------------------------

@dataclass
class OllamaClient:
    base_url: str
    planner_model: str
    executor_model: str

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

    def generate(self, model: str, prompt: str, system: str = "") -> str:
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.15, "num_predict": 2048},
        }
        if system:
            payload["system"] = system
        result = self._post("/api/generate", payload)
        return str(result.get("response", "")).strip()

    def plan(self, prompt: str, system: str = "") -> str:
        return self.generate(self.planner_model, prompt, system)

    def analyze(self, prompt: str, system: str = "") -> str:
        return self.generate(self.executor_model, prompt, system)

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
    if len(combined) > MAX_AI_CONTEXT:
        combined = combined[:MAX_AI_CONTEXT] + "\n...[truncated]..."
    return combined


def _read_file(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        content = f.read()
    return f"# File: {os.path.basename(path)}\n{content}"


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

    def _build_ssh_cmd(self, cmd: str) -> list[str]:
        args = [
            "ssh", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=8",
            "-o", "BatchMode=yes" if self.key_file else "BatchMode=no",
            "-p", str(self.port),
        ]
        if self.key_file:
            args += ["-i", self.key_file]
        args += [f"{self.username}@{self.host}", cmd]
        return args

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

    def evidence_summary(self) -> str:
        parts: list[str] = []
        for rec in self.commands:
            if rec.useful:
                prefix = "[REMOTE] " if rec.remote else ""
                parts.append(f"[{rec.phase}] {prefix}$ {rec.command}\n{rec.output}")
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
            "commands": [
                {
                    "phase": r.phase, "command": r.command,
                    "exit_code": r.exit_code, "output": r.output,
                    "useful": r.useful, "note": r.note, "remote": r.remote,
                }
                for r in self.commands
            ],
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
"""

PHASE_PROMPTS = {
    "recon": """\
Phase: RECONNAISSANCE. Identify open ports, services, versions. Start with network scans.
Suggest nmap scans appropriate for the target. After port discovery, probe interesting services.""",

    "enum": """\
Phase: ENUMERATION. Gather detailed info: users, shares, web apps, misconfigs.
Use credentials if provided. Try service-specific enumeration (HTTP, SMB, LDAP, etc).
If SSH credentials are available, suggest remote commands to run on the target.""",

    "access": """\
Phase: INITIAL ACCESS. Find a way in based on enumeration results.
Suggest exploits, credential attacks, or service-specific techniques.
Give practical one-liner commands. If you find a working method, present it clearly with ACCESS:
Prioritize: known CVEs for detected versions, default creds, misconfigs, web vulns.""",

    "privesc": """\
Phase: PRIVILEGE ESCALATION. You have a shell on the target.
Commands run ON the target via SSH or manual paste.
Systematically check: SUID/SGID, capabilities, sudo, cron, services, kernel, docker, writable paths.
When you find a path, give the exact escalation command with ACCESS:""",
}


def build_ai_prompt(session: Session, user_message: str) -> tuple[str, str]:
    system_parts = [SYSTEM_BASE, PHASE_PROMPTS.get(session.phase, "")]

    if session.ssh:
        system_parts.append(f"SSH session active: {session.ssh.label} — commands run on the target.")
    if session.target_os:
        system_parts.append(f"Target OS: {session.target_os}")
    if session.cheatsheet_context:
        system_parts.append(
            f"Operator's cheat sheet / engagement notes:\n"
            f"---\n{session.cheatsheet_context[:MAX_AI_CONTEXT // 2]}\n---"
        )
    if session.credentials:
        cred_info = ", ".join(f"{k}: {v}" for k, v in session.credentials.items())
        system_parts.append(f"Available credentials: {cred_info}")

    system = "\n\n".join(system_parts)

    prompt_parts = [f"Target: {session.target}"]
    evidence = session.evidence_summary()
    if evidence != "(no useful results yet)":
        prompt_parts.append(f"Evidence so far:\n{evidence[-MAX_AI_CONTEXT // 2:]}")
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
    done: bool = False
    done_summary: str = ""


def parse_ai_response(text: str) -> AIResponse:
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

    lines += ["", "---", "", "## Useful Results", ""]
    for rec in useful:
        prefix = " (remote)" if rec.remote else ""
        lines.append(f"### [{rec.phase}]{prefix} `{rec.command}`")
        if rec.note:
            lines.append(f"**Note:** {rec.note}")
        lines.append(f"```")
        lines.append(rec.output[:4000])
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


def prompt_input(label: str = "xs-ai") -> str:
    try:
        return input(f"\n{COLOR['bold']}[{label}]>{COLOR['reset']} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ":quit"


def approve(cmd: str, remote: bool = False) -> bool | str:
    where = " (REMOTE)" if remote else ""
    cprint("yellow", f"\n  Command{where}: {cmd}")
    try:
        ans = input(f"  {COLOR['bold']}Execute? [y/n/edit]:{COLOR['reset']} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if ans == "edit":
        try:
            edited = input(f"  {COLOR['bold']}New command:{COLOR['reset']} ").strip()
            if edited:
                return edited
        except (EOFError, KeyboardInterrupt):
            return False
    return ans in ("y", "yes")


# ---------------------------------------------------------------------------
# Auto-enum: run a checklist with per-command approval
# ---------------------------------------------------------------------------

def run_auto_checks(checks: list[tuple[str, str]], session: Session,
                    client: OllamaClient | None, execute_fn) -> list[CommandRecord]:
    results: list[CommandRecord] = []
    cprint("cyan", f"\n  Auto-enum: {len(checks)} checks available")

    for i, (title, cmd_template) in enumerate(checks, 1):
        cmd = cmd_template.format(target=session.target)
        cprint("cyan", f"\n  [{i}/{len(checks)}] {title}")
        approval = approve(cmd, remote=bool(session.ssh))
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
            f"[{r.note}] $ {r.command}\n{r.output[:2000]}"
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
      :scan               Quick nmap scan (top 100 ports)
      :fullscan           Full nmap scan (all ports)
      :findings           Show current findings
      :history            Show command history
      :report             Generate report
      :save [file]        Save session state
      :load <file>        Load saved session
      :cheat <file>       Load additional cheat sheet
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


def interactive_loop(client: OllamaClient, session: Session, scope: set[str],
                     report_dir: str):
    cprint("cyan", BANNER)
    cprint("green", f"  Connected to: {client.base_url}")
    cprint("green", f"  Target: {session.target}")
    cprint("green", f"  Phase: {session.phase}")
    if session.cheatsheet_context:
        cprint("green", f"  Cheat sheet loaded ({len(session.cheatsheet_context)} chars)")
    if session.commands:
        cprint("green", f"  Resumed session: {len(session.commands)} commands, {len(session.findings)} findings")
    cprint("dim", "  Type :help for commands\n")

    ssh_key_file: str | None = None

    def execute_cmd(cmd: str) -> tuple[int, str]:
        if session.ssh:
            return session.ssh.run(cmd)
        return run_command(cmd)

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
                if scope and new_target not in scope:
                    cprint("red", f"  {new_target} is not in scope!")
                else:
                    session.target = new_target
                    cprint("green", f"  Target -> {session.target}")
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
                ssh_user = input("  SSH username: ").strip()
            if not ssh_user:
                cprint("red", "  Username required.")
                continue

            cprint("dim", f"  Connecting SSH to {ssh_user}@{ssh_host}:{ssh_port}...")
            conn = SSHConnection(
                host=ssh_host, port=ssh_port, username=ssh_user,
                key_file=ssh_key_file,
                password=session.credentials.get("password"),
            )
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
            session.ssh = None
            cprint("green", "  SSH disconnected.")
            continue

        if user_input == ":shell":
            manual_shell_mode(session)
            continue

        if user_input.startswith(":run "):
            cmd = user_input[5:].strip()
            if cmd:
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
            approval = approve(cmd)
            if approval is not False:
                cmd_to_run = approval if isinstance(approval, str) else cmd
                cprint("dim", f"  Running: {cmd_to_run}")
                code, output = run_command(cmd_to_run, timeout=180)
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
            approval = approve(cmd)
            if approval is not False:
                cmd_to_run = approval if isinstance(approval, str) else cmd
                cprint("dim", f"  Running: {cmd_to_run}")
                code, output = run_command(cmd_to_run, timeout=600)
                is_useful = code == 0 and len(output.strip()) > 10
                rec = CommandRecord(
                    phase="recon", command=cmd_to_run,
                    exit_code=code, output=output, useful=is_useful, note="full scan",
                )
                session.commands.append(rec)
                print(output)
            continue

        if user_input == ":auto":
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
            run_auto_checks(checks, session, client, execute_cmd)
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
        system, prompt = build_ai_prompt(session, user_input)
        try:
            raw = client.plan(prompt, system) if session.phase in ("recon", "enum") else client.analyze(prompt, system)
        except ConnectionError as exc:
            cprint("red", f"  AI error: {exc}")
            continue

        ai = parse_ai_response(raw)

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

        for need in ai.needs:
            cprint("yellow", f"  NEED: {need}")

        if ai.done:
            cprint("cyan", f"  DONE: {ai.done_summary}")
            continue

        if ai.command:
            is_remote = bool(session.ssh)
            approval = approve(ai.command, remote=is_remote)
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
                f"Output:\n{output[:MAX_AI_CONTEXT // 3]}\n\n"
                f"Analyze this output. What did we learn? What should we try next?"
            )
            try:
                analysis = client.analyze(analysis_prompt, system)
            except ConnectionError:
                analysis = ""

            analysis_parsed = parse_ai_response(analysis)
            for f in analysis_parsed.findings:
                if f not in session.findings:
                    session.findings.append(f)
                    cprint("green", f"  FINDING: {f}")

            if analysis_parsed.access_line:
                cprint("yellow", f"\n  ACCESS ONE-LINER: {analysis_parsed.access_line}")

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
    return p


def main() -> int:
    args = build_parser().parse_args()
    base_url = f"http://{args.host}:{args.port}"

    client = OllamaClient(
        base_url=base_url,
        planner_model=args.planner_model,
        executor_model=args.executor_model,
    )

    print(f"[*] Connecting to Ollama at {base_url}...")
    try:
        models = client.ping()
        print(f"[OK] Models available: {', '.join(models)}")
    except Exception as exc:
        print(f"[FAIL] Cannot reach Ollama: {exc}")
        print(f"       Make sure host_setup.ps1 has been run on {args.host}")
        return 1

    scope = load_scope(args.scope)
    if scope:
        print(f"[OK] Scope loaded: {', '.join(sorted(scope))}")
    else:
        print(f"[!] No scope file found ({args.scope}). Scope checking disabled.")

    # Load cheat sheets
    cheat_paths = args.cheatsheet or []
    if os.path.isdir("cheatsheets"):
        cheat_paths.append("cheatsheets")
    cheatsheet_ctx = load_cheatsheets(cheat_paths) if cheat_paths else ""

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

        if scope and target not in scope:
            print(f"[FAIL] {target} is not in scope!")
            return 1

        session = Session(
            target=target,
            phase=args.phase,
            cheatsheet_context=cheatsheet_ctx,
            target_os=args.os_type or "",
        )

    try:
        interactive_loop(client, session, scope, args.report_dir)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
    finally:
        if session.commands:
            path = generate_report(session, args.report_dir)
            print(f"\n[*] Report saved: {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
