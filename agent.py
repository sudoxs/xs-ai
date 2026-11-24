#!/usr/bin/env python3
"""
xs-ai agent — semi-autonomous pentest loop.

The AgentLoop asks the AI model what to do next, presents the plan to the
operator (or auto-approves based on the approve-level), executes commands,
records everything to a JSON action log, and loops until the AI says "done"
or the operator pauses / stops.

Approve levels (cumulative):
  0  ask   — every action needs explicit approval (default)
  1  safe  — auto-approve read-only commands (nmap, curl -s, cat, id, etc.)
  2  low   — also auto-approve low-risk writes (mkdir, echo >>)
  3  full  — auto-approve everything the model suggests (DANGEROUS)

Ctrl+C pauses the loop; the operator can then resume, skip, change level,
or stop entirely.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import signal
import textwrap
import time
from dataclasses import dataclass, field
from typing import Any

SAFE_PREFIXES = (
    "nmap", "curl -s", "curl -k -s", "wget -q", "cat ", "head ", "tail ",
    "ls ", "ls", "dir ", "id", "whoami", "hostname", "uname", "ifconfig",
    "ip addr", "ip route", "netstat", "ss ", "ps ", "env", "printenv",
    "echo ", "ping -c", "dig ", "nslookup ", "host ", "whois ",
    "file ", "stat ", "wc ", "grep ", "find ", "which ", "type ",
    "dpkg -l", "rpm -qa", "apt list", "systemctl status",
    "service --status-all", "ss -tlnp", "netstat -tlnp",
)

LOW_RISK_PREFIXES = (
    "mkdir ", "touch ", "echo ", "cp ", "mv ", "chmod ",
    "wget -O ", "curl -o ",
)


@dataclass
class Action:
    step: int
    phase: str
    action_type: str          # "command", "set_phase", "research", "validate", "done"
    description: str
    command: str = ""
    approved: bool = False
    executed: bool = False
    exit_code: int = -1
    output: str = ""
    skipped: bool = False
    error: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "phase": self.phase,
            "type": self.action_type,
            "description": self.description,
            "command": self.command,
            "approved": self.approved,
            "executed": self.executed,
            "exit_code": self.exit_code,
            "output_preview": self.output[:500] if self.output else "",
            "skipped": self.skipped,
            "error": self.error,
            "timestamp": self.timestamp,
        }


@dataclass
class AgentState:
    running: bool = False
    paused: bool = False
    step: int = 0
    approve_level: int = 0
    actions: list[Action] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)
    log_path: str = ""
    start_time: str = ""
    pause_reason: str = ""

    def elapsed(self) -> str:
        if not self.start_time:
            return "0s"
        t0 = datetime.datetime.fromisoformat(self.start_time)
        delta = datetime.datetime.now() - t0
        mins, secs = divmod(int(delta.total_seconds()), 60)
        return f"{mins}m{secs:02d}s" if mins else f"{secs}s"


DECIDE_SYSTEM = textwrap.dedent("""\
You are the decision engine of an AI-assisted pentest orchestrator.
Given the current pentest session state (target, phase, findings, hypotheses,
command history), decide the SINGLE best next action.

Respond with a JSON object:
{
  "action_type": "command" | "set_phase" | "research" | "validate" | "done",
  "description": "one-line explanation of WHY this action",
  "command": "the exact shell command to run (for command type)",
  "phase": "new phase name (for set_phase type)",
  "hypothesis_id": "H-id (for validate type)",
  "done_reason": "summary (for done type)"
}

Rules:
- ONE action per response, no lists.
- For "command": give the exact, ready-to-run shell command.
- For "research": triggers the :research pipeline on the current target/ports.
- For "validate": triggers :validate on a specific hypothesis.
- For "set_phase": move to the next pentest phase when current is exhausted.
- For "done": the engagement is complete or no more actions are productive.
- Prefer safe, read-only commands first. Only suggest writes/exploits in
  access/privesc phases.
- Never suggest commands that could cause denial of service.
- Never repeat a command that already ran (check command history).
- Reference specific hypotheses/findings when deciding.
""")


def _build_context(session: Any, state: AgentState) -> str:
    lines = [
        f"Target: {session.target}",
        f"Phase: {session.phase}",
        f"OS: {session.target_os or 'unknown'}",
        f"Agent step: {state.step}",
        f"Credentials: {json.dumps(session.credentials) if session.credentials else 'none'}",
        "",
        "--- Recent commands (last 20) ---",
    ]
    for rec in session.commands[-20:]:
        status = "OK" if rec.useful else f"exit={rec.exit_code}"
        lines.append(f"  [{rec.phase}] {rec.command}  ({status})")

    if session.hypotheses:
        lines.append("")
        lines.append("--- Hypotheses ---")
        for h in session.hypotheses:
            hid = h.get("id", "?")
            sev = h.get("severity", "?")
            stat = h.get("status", "?")
            obs = h.get("observation", "")[:100]
            lines.append(f"  {hid}: [{sev}/{stat}] {obs}")

    if session.findings:
        lines.append("")
        lines.append("--- Findings ---")
        for f in session.findings[-10:]:
            lines.append(f"  {f[:120]}")

    recent_actions = state.actions[-5:]
    if recent_actions:
        lines.append("")
        lines.append("--- Agent recent actions ---")
        for a in recent_actions:
            lines.append(f"  step {a.step}: [{a.action_type}] {a.description}")
            if a.output:
                lines.append(f"    output: {a.output[:200]}")

    return "\n".join(lines)


def decide_next_action(client: Any, session: Any, state: AgentState) -> Action:
    context = _build_context(session, state)
    prompt = f"Current pentest state:\n\n{context}\n\nDecide the next action."

    raw = client.run_phase(session.phase, prompt, system=DECIDE_SYSTEM,
                           want_json=True)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r'\{[^{}]*\}', raw, re.DOTALL)
        if m:
            data = json.loads(m.group())
        else:
            return Action(
                step=state.step,
                phase=session.phase,
                action_type="done",
                description="Model returned unparseable response",
                error=raw[:300],
                timestamp=_now(),
            )

    state.step += 1
    return Action(
        step=state.step,
        phase=session.phase,
        action_type=data.get("action_type", "done"),
        description=data.get("description", ""),
        command=data.get("command", data.get("phase", data.get("hypothesis_id", ""))),
        timestamp=_now(),
    )


def auto_approve(action: Action, level: int) -> bool:
    if level >= 3:
        return True
    if action.action_type in ("research", "set_phase", "done"):
        return level >= 1
    if action.action_type == "validate":
        return level >= 1
    if action.action_type == "command":
        cmd = action.command.strip().lower()
        if level >= 1 and any(cmd.startswith(p) for p in SAFE_PREFIXES):
            return True
        if level >= 2 and any(cmd.startswith(p) for p in LOW_RISK_PREFIXES):
            return True
    return False


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def _save_log(state: AgentState) -> None:
    if not state.log_path:
        return
    data = {
        "start_time": state.start_time,
        "total_steps": state.step,
        "approve_level": state.approve_level,
        "actions": [a.to_dict() for a in state.actions],
    }
    try:
        os.makedirs(os.path.dirname(state.log_path) or ".", exist_ok=True)
        with open(state.log_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass


def _cprint(color: str, msg: str) -> None:
    colors = {"red": "31", "green": "32", "yellow": "33", "cyan": "36", "dim": "2"}
    code = colors.get(color, "0")
    print(f"\033[{code}m{msg}\033[0m")


def _ask_approval(action: Action) -> str:
    _cprint("cyan", f"\n  [Agent step {action.step}] {action.action_type}: {action.description}")
    if action.command:
        _cprint("yellow", f"    -> {action.command}")
    while True:
        try:
            choice = input("  [A]pprove / [S]kip / [P]ause / [Q]uit agent? ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "pause"
        if choice in ("a", "approve", "y", "yes", ""):
            return "approve"
        if choice in ("s", "skip"):
            return "skip"
        if choice in ("p", "pause"):
            return "pause"
        if choice in ("q", "quit", "stop"):
            return "quit"
        _cprint("dim", "  Enter a/s/p/q")


def run_agent_loop(
    client: Any,
    session: Any,
    execute_fn,
    state: AgentState,
    max_steps: int = 100,
    research_fn=None,
    validate_fn=None,
) -> AgentState:
    _interrupted = [False]

    def _sigint_handler(sig, frame):
        _interrupted[0] = True
        _cprint("yellow", "\n  [Agent] Ctrl+C — pausing after current step...")

    old_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _sigint_handler)

    state.running = True
    state.paused = False
    if not state.start_time:
        state.start_time = _now()
    if not state.log_path:
        state.log_path = os.path.join(
            "reports",
            f"agent_{session.target}_{datetime.datetime.now():%Y%m%d_%H%M%S}.json",
        )

    _cprint("green", f"  [Agent] Started — level {state.approve_level}, target {session.target}")
    _cprint("dim", "  Press Ctrl+C to pause\n")

    try:
        while state.running and state.step < max_steps:
            if _interrupted[0]:
                state.paused = True
                state.pause_reason = "operator-interrupt"
                _cprint("yellow", "  [Agent] Paused (Ctrl+C)")
                break

            action = decide_next_action(client, session, state)

            if action.action_type == "done":
                action.approved = True
                action.executed = True
                state.actions.append(action)
                _cprint("green", f"  [Agent] Done: {action.description}")
                state.running = False
                break

            if auto_approve(action, state.approve_level):
                action.approved = True
                _cprint("dim", f"  [Agent step {action.step}] auto-approved: {action.description}")
                if action.command:
                    _cprint("dim", f"    -> {action.command}")
            else:
                choice = _ask_approval(action)
                if choice == "approve":
                    action.approved = True
                elif choice == "skip":
                    action.skipped = True
                    state.actions.append(action)
                    _save_log(state)
                    continue
                elif choice == "pause":
                    action.skipped = True
                    state.actions.append(action)
                    state.paused = True
                    state.pause_reason = "operator-pause"
                    _cprint("yellow", "  [Agent] Paused")
                    break
                elif choice == "quit":
                    action.skipped = True
                    state.actions.append(action)
                    state.running = False
                    _cprint("yellow", "  [Agent] Stopped")
                    break

            if action.action_type == "command" and action.approved:
                try:
                    exit_code, output = execute_fn(action.command)
                    action.executed = True
                    action.exit_code = exit_code
                    action.output = output
                except Exception as exc:
                    action.error = str(exc)
                    _cprint("red", f"  [Agent] Command error: {exc}")

            elif action.action_type == "set_phase" and action.approved:
                new_phase = action.command
                if new_phase in ("recon", "enum", "access", "privesc"):
                    session.phase = new_phase
                    action.executed = True
                    _cprint("green", f"  [Agent] Phase -> {new_phase}")
                else:
                    action.error = f"invalid phase: {new_phase}"

            elif action.action_type == "research" and action.approved:
                if research_fn:
                    try:
                        research_fn()
                        action.executed = True
                    except Exception as exc:
                        action.error = str(exc)
                else:
                    action.error = "research_fn not provided"
                    _cprint("yellow", "  [Agent] Research pipeline not wired — skipping")

            elif action.action_type == "validate" and action.approved:
                if validate_fn:
                    try:
                        validate_fn(action.command)
                        action.executed = True
                    except Exception as exc:
                        action.error = str(exc)
                else:
                    action.error = "validate_fn not provided"

            state.actions.append(action)
            _save_log(state)

    except Exception as exc:
        _cprint("red", f"  [Agent] Crash: {exc}")
        state.paused = True
        state.pause_reason = f"crash: {exc}"
        _save_log(state)
    finally:
        signal.signal(signal.SIGINT, old_handler)

    _save_log(state)
    _cprint("dim", f"  [Agent] {state.step} steps, elapsed {state.elapsed()}")
    return state


def format_status(state: AgentState) -> str:
    lines = [
        f"  Running: {state.running}  Paused: {state.paused}",
        f"  Steps: {state.step}  Approve level: {state.approve_level}",
        f"  Elapsed: {state.elapsed()}",
    ]
    if state.pause_reason:
        lines.append(f"  Pause reason: {state.pause_reason}")
    if state.plan:
        lines.append("  Plan:")
        for i, p in enumerate(state.plan, 1):
            lines.append(f"    {i}. {p}")
    return "\n".join(lines)


def format_log(state: AgentState, last_n: int = 10) -> str:
    if not state.actions:
        return "  No actions yet."
    lines = []
    for a in state.actions[-last_n:]:
        mark = "OK" if a.executed else ("SKIP" if a.skipped else "PEND")
        lines.append(f"  [{mark}] step {a.step}: {a.action_type} — {a.description}")
        if a.command:
            lines.append(f"         cmd: {a.command}")
        if a.error:
            lines.append(f"         err: {a.error}")
    return "\n".join(lines)
