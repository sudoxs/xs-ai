#!/usr/bin/env python3
"""
xs-ai agent — autonomous pentest loop.

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
import hashlib
import json
import os
import re
import shlex
import signal
import textwrap
from dataclasses import dataclass, field
from typing import Any, Callable

MAX_AI_CONTEXT = 28_000
PLAN_INTERVAL = 8
PLAN_SIZE = 5
STALL_THRESHOLD = 5
MAX_CONSEC_ERRORS = 5
ERROR_BACKOFF_SECS = 3

SAFE_PREFIXES = (
    "nmap", "curl -s", "curl -k -s", "wget -q", "cat ", "head ", "tail ",
    "ls ", "ls", "dir ", "id", "whoami", "hostname", "uname", "ifconfig",
    "ip addr", "ip route", "netstat", "ss ", "ps ", "env", "printenv",
    "echo ", "ping -c", "dig ", "nslookup ", "host ", "whois ",
    "file ", "stat ", "wc ", "grep ", "which ", "type ",
    "dpkg -l", "rpm -qa", "apt list", "systemctl status",
    "service --status-all", "ss -tlnp", "netstat -tlnp",
)

LOW_RISK_PREFIXES = (
    "mkdir ", "touch ", "echo ", "cp ", "mv ", "chmod ",
)

# `find` can RCE via -exec/-ok/-delete/-fprintf; checked below with a regex
# instead of being on SAFE_PREFIXES.
_FIND_DANGEROUS_RE = re.compile(r"\s-(?:exec|execdir|ok|okdir|delete|fprintf|fprint|fls|fls0)\b")

# `wget -O`/`curl -o` with an output path can clobber arbitrary files; we
# restrict them to stdout-only forms (`curl -s`, `wget -q`) which are already
# on SAFE_PREFIXES.  Explicit `-O`/`-o` requires operator approval.


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
        output_hash = ""
        if self.output and len(self.output) > 2000:
            output_hash = hashlib.sha256(self.output.encode("utf-8", errors="replace")).hexdigest()[:16]
        return {
            "step": self.step,
            "phase": self.phase,
            "type": self.action_type,
            "description": self.description,
            "command": self.command,
            "approved": self.approved,
            "executed": self.executed,
            "exit_code": self.exit_code,
            "output": self.output[:4000] if self.output else "",
            "output_hash": output_hash,
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
    executed_commands: set[str] = field(default_factory=set)
    _last_progress_step: int = 0
    _consec_errors: int = 0

    def elapsed(self) -> str:
        if not self.start_time:
            return "0s"
        t0 = datetime.datetime.fromisoformat(self.start_time)
        delta = datetime.datetime.now() - t0
        mins, secs = divmod(int(delta.total_seconds()), 60)
        return f"{mins}m{secs:02d}s" if mins else f"{secs}s"


def _normalize_command(cmd: str) -> str:
    """Normalize a command for deduplication: collapse whitespace, strip trailing
    semicolons, and sort flag groups (keeping flag-value pairs together) so
    'nmap -sV -p 80 host' and 'nmap -p 80 -sV host' are considered the same."""
    cmd = cmd.strip()
    cmd = re.sub(r"\s+", " ", cmd)
    cmd = cmd.rstrip(";").strip()
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return cmd.lower()
    if not parts:
        return cmd.lower()
    binary = parts[0].lower()
    flag_groups: list[list[str]] = []
    positional: list[str] = []
    i = 1
    while i < len(parts):
        token = parts[i]
        if token.startswith("-"):
            group = [token]
            if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                group.append(parts[i + 1])
                i += 1
            flag_groups.append(group)
        else:
            positional.append(token)
        i += 1
    flag_groups.sort(key=lambda g: g[0].lower())
    flat_flags = [t for g in flag_groups for t in g]
    return " ".join([binary] + flat_flags + positional).lower()


DECIDE_SYSTEM = textwrap.dedent("""\
You are the decision engine of an AI-assisted pentest orchestrator.
Given the current pentest session state (target, phase, findings, hypotheses,
command history, and your current plan), decide the SINGLE best next action.

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
- For the very first recon command, pick a FAST scan first:
  `nmap -Pn -sV --top-ports 100 -T3 <target>`. Do NOT start with `-p-`
  (full port sweep is far too slow for a first step). Do NOT use `-sS`
  unless running as root — prefer `-sT`. Run a deep/full scan only after
  the quick scan has findings.
- For "research": triggers the :research pipeline on the current target/ports.
- For "validate": triggers :validate on a specific hypothesis.
- For "set_phase": move to the next pentest phase when current is exhausted.
  Do NOT set_phase to the phase you are already in — that is a no-op.
- For "done": the engagement is complete or no more actions are productive.
- Prefer safe, read-only commands first. Only suggest writes/exploits in
  access/privesc phases.
- Never suggest commands that could cause denial of service.
- NEVER repeat a command that already ran — check the executed commands list.
  If a similar command was run, choose a different approach or move on.
- Reference specific hypotheses/findings when deciding.
- Follow the current plan steps in order when available.
""")


def _sanitize_command(cmd: str) -> tuple[str, str]:
    """Apply safety rewrites before executing a command.
    Returns (rewritten, note). An empty note means no change."""
    original = cmd
    note = ""
    # nmap -sS needs raw sockets i.e. root. Non-root quietly returns no results
    # and wastes a slot. Downgrade to -sT (TCP connect scan).
    if " nmap " in f" {cmd} " or cmd.startswith("nmap "):
        import shlex as _shlex
        try:
            toks = _shlex.split(cmd)
        except ValueError:
            toks = cmd.split()
        if "-sS" in toks:
            is_root = False
            if hasattr(os, "geteuid"):
                try:
                    is_root = (os.geteuid() == 0)
                except Exception:
                    is_root = False
            if not is_root:
                toks = ["-sT" if t == "-sS" else t for t in toks]
                cmd = " ".join(toks)
                note = "rewrote -sS -> -sT (not running as root; SYN scan needs raw sockets)"
    return cmd, note

PLAN_SYSTEM = textwrap.dedent("""\
You are a pentest planner. Given the current state of the engagement, produce
a focused plan of exactly {n} concrete next steps.

Respond with a JSON object whose "plan" is a list of {n} strings; each string
MUST be a concrete action on the actual target, never a placeholder like
"step N description".

Rules:
- Each step must be a concrete, actionable task (not vague like "investigate").
- For the very first recon step, use a FAST scan: service/version against
  top-ports (e.g. `nmap -Pn -sV --top-ports 100 -T3 <target>`). Do NOT
  start with `-p-` (full 65k port sweep) and do NOT use `-sS` unless the
  session is root — prefer `-sT` (TCP connect scan) otherwise. A full scan
  belongs AFTER the quick scan finds something.
- Steps should build on each other logically.
- Consider what commands have already been run — do not re-plan completed work.
- Focus on the current phase's goals.
- If findings suggest a pivot, plan the pivot path.
""")


# Placeholder lines that weak models parrot straight from the schema example;
# these must be dropped from any plan the model returns.
_PLACEHOLDER_PLAN_RE = re.compile(
    r"^\s*step\s*\d+\s*(?:description|here|text|action)?\s*\.?\s*$",
    re.IGNORECASE,
)
_PLACEHOLDER_PLAN_EXACT = {
    "step 1 description", "step 2 description", "step 3 description",
    "step 4 description", "step 5 description",
    "concrete action on the actual target",
    "<a concrete, executable step>",
}


def _is_placeholder_plan_step(s: str) -> bool:
    s = (s or "").strip()
    if not s:
        return True
    if s.lower() in _PLACEHOLDER_PLAN_EXACT:
        return True
    return bool(_PLACEHOLDER_PLAN_RE.match(s))


def _build_context(session: Any, state: AgentState) -> str:
    """Build AI context with budget management."""
    budget = MAX_AI_CONTEXT
    sections: list[str] = []

    # header (always included, ~200 chars)
    header = "\n".join([
        f"Target: {session.target}",
        f"Phase: {session.phase}",
        f"OS: {session.target_os or 'unknown'}",
        f"Agent step: {state.step}",
        f"Credentials: {json.dumps(session.credentials) if session.credentials else 'none'}",
    ])
    sections.append(header)
    budget -= len(header)

    # plan (high priority, small)
    if state.plan:
        plan_text = "\n--- Current Plan ---\n" + "\n".join(
            f"  {i}. {p}" for i, p in enumerate(state.plan, 1))
        sections.append(plan_text)
        budget -= len(plan_text)

    # executed commands set (for dedup awareness)
    if state.executed_commands:
        dedup_text = "\n--- Already executed (DO NOT repeat) ---\n"
        for cmd in sorted(state.executed_commands)[-30:]:
            dedup_text += f"  {cmd}\n"
        if len(dedup_text) > budget // 4:
            dedup_text = dedup_text[:budget // 4] + "\n  ... (truncated)\n"
        sections.append(dedup_text)
        budget -= len(dedup_text)

    # hypotheses (high value)
    if session.hypotheses:
        hyp_text = "\n--- Hypotheses ---\n"
        for h in session.hypotheses:
            hid = h.get("id", "?")
            sev = h.get("severity", "?")
            stat = h.get("status", "?")
            obs = h.get("observation", "")[:120]
            line = f"  {hid}: [{sev}/{stat}] {obs}\n"
            if len(hyp_text) + len(line) > budget // 3:
                hyp_text += "  ... (truncated)\n"
                break
            hyp_text += line
        sections.append(hyp_text)
        budget -= len(hyp_text)

    # findings (high value)
    if session.findings:
        find_text = "\n--- Findings ---\n"
        for f in session.findings[-15:]:
            line = f"  {f[:150]}\n"
            if len(find_text) + len(line) > budget // 4:
                find_text += "  ... (truncated)\n"
                break
            find_text += line
        sections.append(find_text)
        budget -= len(find_text)

    # recent commands with output (use remaining budget)
    cmd_text = "\n--- Recent commands (last 20) ---\n"
    for rec in session.commands[-20:]:
        status = "OK" if rec.useful else f"exit={rec.exit_code}"
        cmd_text += f"  [{rec.phase}] {rec.command}  ({status})\n"
    if len(cmd_text) > budget // 2:
        cmd_text = cmd_text[:budget // 2] + "\n  ... (truncated)\n"
    sections.append(cmd_text)
    budget -= len(cmd_text)

    # recent agent actions with fuller output (use remaining budget)
    recent_actions = state.actions[-8:]
    if recent_actions:
        act_text = "\n--- Agent recent actions ---\n"
        for a in recent_actions:
            act_text += f"  step {a.step}: [{a.action_type}] {a.description}\n"
            if a.output:
                out_preview = a.output[:min(600, max(100, budget // len(recent_actions)))]
                act_text += f"    output: {out_preview}\n"
            if a.error:
                act_text += f"    error: {a.error[:200]}\n"
        if len(act_text) > budget:
            act_text = act_text[:budget] + "\n  ... (truncated)\n"
        sections.append(act_text)

    return "\n".join(sections)


def _generate_plan(
    client: Any,
    session: Any,
    state: AgentState,
    model_resolver: Callable | None = None,
) -> list[str]:
    """Ask the AI to generate a focused plan for the next steps."""
    context = _build_context(session, state)
    prompt = f"Current pentest state:\n\n{context}\n\nGenerate a {PLAN_SIZE}-step plan."
    system = PLAN_SYSTEM.replace("{n}", str(PLAN_SIZE))

    try:
        raw = client.run_phase("recon", prompt, system=system, want_json=True)
        data = json.loads(raw)
        plan = data.get("plan", [])
        if isinstance(plan, list) and plan:
            # Drop placeholder lines like "step 1 description" that weak
            # models echo straight from the schema example — a plan full of
            # those is worse than no plan.
            filtered = [str(s).strip() for s in plan[:PLAN_SIZE]
                        if not _is_placeholder_plan_step(str(s))]
            if filtered:
                return filtered
    except Exception:
        pass
    return []


def decide_next_action(
    client: Any,
    session: Any,
    state: AgentState,
    model_resolver: Callable | None = None,
) -> Action:
    context = _build_context(session, state)
    prompt = f"Current pentest state:\n\n{context}\n\nDecide the next action."

    try:
        raw = client.run_phase(session.phase, prompt, system=DECIDE_SYSTEM,
                               want_json=True)
    except Exception as exc:
        # A transient model error must NOT silently end the loop. Return a
        # retry-marker action; the loop treats consecutive errors as a stall.
        state.step += 1
        return Action(
            step=state.step,
            phase=session.phase,
            action_type="retry",
            description=f"Model error: {exc}",
            error=str(exc)[:300],
            timestamp=_now(),
        )

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r'\{[^{}]*\}', raw, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group())
            except json.JSONDecodeError:
                return Action(
                    step=state.step, phase=session.phase, action_type="done",
                    description="Model returned unparseable response",
                    error=raw[:300], timestamp=_now(),
                )
        else:
            return Action(
                step=state.step, phase=session.phase, action_type="done",
                description="Model returned unparseable response",
                error=raw[:300], timestamp=_now(),
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


_COMPOUND_SPLIT_RE = re.compile(r"\s*(?:;|&&|\|\||\|(?!\|)|`|\$\()\s*")
_SHELL_REDIRECT_RE = re.compile(r"\s*(?:[12]?>|>>)\s*")


def _extract_simple_commands(cmd: str) -> list[str]:
    """Split a command on shell compound operators. Returns each sub-command."""
    parts = _COMPOUND_SPLIT_RE.split(cmd)
    return [p.strip() for p in parts if p.strip()]


def _has_shell_redirect(cmd: str) -> bool:
    """Check if a command contains shell output redirects (> or >>)."""
    return bool(_SHELL_REDIRECT_RE.search(cmd))


def _is_safe_find(sc: str) -> bool:
    """`find ...` is safe only without -exec/-delete/-fprintf and friends."""
    if not sc.startswith("find "):
        return False
    return _FIND_DANGEROUS_RE.search(" " + sc) is None


def auto_approve(action: Action, level: int) -> bool:
    if level >= 3:
        return True
    if action.action_type in ("research", "set_phase", "done"):
        return level >= 1
    if action.action_type == "validate":
        return level >= 1
    if action.action_type == "command":
        cmd = action.command.strip().lower()
        if _has_shell_redirect(cmd):
            return False
        sub_cmds = _extract_simple_commands(cmd)
        if not sub_cmds:
            return False

        def _is_safe(sc: str) -> bool:
            if sc.startswith("find "):
                return _is_safe_find(sc)
            return any(sc.startswith(p) for p in SAFE_PREFIXES)

        def _is_low_risk(sc: str) -> bool:
            return _is_safe(sc) or any(sc.startswith(p) for p in LOW_RISK_PREFIXES)

        if level >= 1 and all(_is_safe(sc) for sc in sub_cmds):
            return True
        if level >= 2 and all(_is_low_risk(sc) for sc in sub_cmds):
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
        "plan": state.plan,
        "actions": [a.to_dict() for a in state.actions],
    }
    try:
        os.makedirs(os.path.dirname(state.log_path) or ".", exist_ok=True)
        with open(state.log_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError as exc:
        _cprint("yellow", f"  [Agent] Warning: could not save log: {exc}")


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
    scope_checker=None,
    model_resolver: Callable | None = None,
    record_fn: Callable | None = None,
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

    # generate initial plan
    if not state.plan:
        _cprint("dim", "  [Agent] Generating initial plan...")
        state.plan = _generate_plan(client, session, state, model_resolver)
        if state.plan:
            _cprint("cyan", "  [Agent] Plan:")
            for i, p in enumerate(state.plan, 1):
                _cprint("cyan", f"    {i}. {p}")
        _save_log(state)

    try:
        while state.running and state.step < max_steps:
            if _interrupted[0]:
                state.paused = True
                state.pause_reason = "operator-interrupt"
                _cprint("yellow", "  [Agent] Paused (Ctrl+C)")
                break

            # track session state before this step for stall detection
            _hyp_count_before = len(session.hypotheses) if hasattr(session, "hypotheses") else 0
            _find_count_before = len(session.findings) if hasattr(session, "findings") else 0

            # re-plan periodically
            if state.step > 0 and state.step % PLAN_INTERVAL == 0:
                _cprint("dim", "  [Agent] Re-planning...")
                new_plan = _generate_plan(client, session, state, model_resolver)
                if new_plan:
                    state.plan = new_plan
                    _cprint("cyan", "  [Agent] Updated plan:")
                    for i, p in enumerate(state.plan, 1):
                        _cprint("cyan", f"    {i}. {p}")

            action = decide_next_action(client, session, state, model_resolver)

            if action.action_type == "done":
                action.approved = True
                action.executed = True
                state.actions.append(action)
                _cprint("green", f"  [Agent] Done: {action.description}")
                state.running = False
                break

            if action.action_type == "retry":
                state._consec_errors += 1
                _cprint("yellow",
                        f"  [Agent] {action.description} "
                        f"(consecutive errors: {state._consec_errors}/{MAX_CONSEC_ERRORS})")
                state.actions.append(action)
                _save_log(state)
                if state._consec_errors >= MAX_CONSEC_ERRORS:
                    state.paused = True
                    state.pause_reason = "too-many-model-errors"
                    _cprint("red",
                            f"  [Agent] Paused — {MAX_CONSEC_ERRORS} consecutive "
                            "model errors. Check the backend and :agent resume.")
                    break
                # small backoff so we don't hammer a flaky backend
                import time as _time
                _time.sleep(ERROR_BACKOFF_SECS)
                continue
            # any non-retry action resets the counter
            state._consec_errors = 0

            # command deduplication check
            if action.action_type == "command" and action.command:
                norm = _normalize_command(action.command)
                if norm in state.executed_commands:
                    _cprint("dim", f"  [Agent step {state.step}] SKIP duplicate: {action.command}")
                    action.skipped = True
                    action.error = "duplicate command"
                    state.actions.append(action)
                    _save_log(state)
                    continue

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

            _phase_was_noop = False
            if action.action_type == "command" and action.approved:
                cmd = action.command.strip()
                _VALID_PHASES = {"recon", "enum", "access", "privesc"}
                if cmd.lower() in _VALID_PHASES:
                    target_phase = cmd.lower()
                    if target_phase == session.phase:
                        _cprint("dim", f"  [Agent] already in phase {target_phase} — no-op")
                        action.action_type = "set_phase"
                        action.skipped = True
                        action.error = f"already in phase {target_phase}"
                        _phase_was_noop = True
                    else:
                        _cprint("yellow", f"  [Agent] '{cmd}' is a phase, not a command — converting to set_phase")
                        action.action_type = "set_phase"
                        session.phase = target_phase
                        action.executed = True
                        _cprint("green", f"  [Agent] Phase -> {target_phase}")
                elif not cmd or cmd.startswith(":"):
                    action.error = f"not a shell command: {cmd}"
                    _cprint("yellow", f"  [Agent] Skipping non-shell command: {cmd}")
                else:
                    # pre-execute safety rewrites (e.g. -sS -> -sT off root)
                    cmd, san_note = _sanitize_command(cmd)
                    if san_note:
                        _cprint("yellow", f"  [Agent] {san_note}")
                        _cprint("dim", f"    -> {cmd}")
                        action.command = cmd
                    try:
                        exit_code, output = execute_fn(cmd)
                        action.executed = True
                        action.exit_code = exit_code
                        action.output = output
                        state.executed_commands.add(_normalize_command(cmd))
                        # Mirror the outcome into session.commands so
                        # downstream consumers (_agent_research scraping
                        # nmap output, reports, prior-run dedup) can see it.
                        if record_fn is not None:
                            try:
                                record_fn(cmd, session.phase, exit_code, output)
                            except Exception as _rec_exc:
                                _cprint("yellow", f"  [Agent] record_fn failed: {_rec_exc}")
                    except Exception as exc:
                        action.error = str(exc)
                        _cprint("red", f"  [Agent] Command error: {exc}")

            elif action.action_type == "set_phase" and action.approved:
                new_phase = action.command
                if new_phase in ("recon", "enum", "access", "privesc"):
                    if new_phase == session.phase:
                        _cprint("dim", f"  [Agent] already in phase {new_phase} — no-op")
                        action.skipped = True
                        action.error = f"already in phase {new_phase}"
                        _phase_was_noop = True
                    else:
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
                    # scope check before validation
                    if scope_checker and action.command:
                        ok, reason = scope_checker(action.command)
                        if not ok:
                            action.error = f"scope blocked: {reason}"
                            _cprint("red", f"  [Agent] Validate blocked by scope: {reason}")
                            state.actions.append(action)
                            _save_log(state)
                            continue
                    try:
                        validate_fn(action.command)
                        action.executed = True
                    except Exception as exc:
                        action.error = str(exc)
                else:
                    action.error = "validate_fn not provided"

            state.actions.append(action)
            _save_log(state)

            # stall detection: pause if N consecutive steps yield no new
            # findings, no new hypotheses, no executed commands, and no phase changes
            _hyp_count_after = len(session.hypotheses) if hasattr(session, "hypotheses") else 0
            _find_count_after = len(session.findings) if hasattr(session, "findings") else 0
            new_intel = (_hyp_count_after > _hyp_count_before
                         or _find_count_after > _find_count_before)
            made_progress = (
                (action.action_type == "command" and action.executed)
                or (action.action_type == "set_phase" and action.executed
                    and not _phase_was_noop)
                or (action.action_type == "research" and action.executed and new_intel)
                or (action.action_type == "validate" and action.executed)
            )
            if made_progress:
                state._last_progress_step = state.step
            elif state.step - state._last_progress_step >= STALL_THRESHOLD:
                _cprint("yellow",
                         f"  [Agent] Stall detected — {STALL_THRESHOLD} steps "
                         "with no new output. Pausing for operator review.")
                state.paused = True
                state.pause_reason = "stall-detected"
                break

    except Exception as exc:
        _cprint("red", f"  [Agent] Crash: {exc}")
        state.paused = True
        state.pause_reason = f"crash: {exc}"
        _save_log(state)
    finally:
        signal.signal(signal.SIGINT, old_handler)

    if state.step >= max_steps and state.running:
        state.running = False
        state.pause_reason = "max-steps-reached"
        _cprint("yellow", f"  [Agent] Stopped — reached max steps ({max_steps})")

    _save_log(state)
    _cprint("dim", f"  [Agent] {state.step} steps, elapsed {state.elapsed()}")
    return state


def format_status(state: AgentState) -> str:
    lines = [
        f"  Running: {state.running}  Paused: {state.paused}",
        f"  Steps: {state.step}  Approve level: {state.approve_level}",
        f"  Elapsed: {state.elapsed()}",
        f"  Commands executed: {len(state.executed_commands)}",
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
