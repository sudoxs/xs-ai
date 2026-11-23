#!/usr/bin/env python3
"""
xs-ai model-provider registry — model-agnostic, multi-model routing.

Users differ: one small local model, several local models, a big GPU model, a
remote/cloud API, or any mix. This registry lets them declare N models (each
with its provider, endpoint, context size and capabilities), assign models to
logical roles, auto-select a model per task, and fall back gracefully when one
is unavailable. No assumption about GPU/VRAM, and everything works with a single
model too.

Pure standard library. Imported optionally by client.py; it does not import
client.py (client passes in a backend factory to avoid a circular import).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class ModelSpec:
    name: str                      # friendly id used in role assignments
    provider: str = "ollama"       # ollama | openai | anthropic
    model: str = ""                # provider's model name
    endpoint: str = ""             # base URL (provider default if empty)
    api_key_env: str = ""          # env var holding the API key (cloud)
    context: int = 8192            # context window (tokens)
    capabilities: list[str] = field(default_factory=list)  # structured/reasoning/fast/tools/vision
    roles: list[str] = field(default_factory=list)         # roles this model is preferred for

    def to_dict(self) -> dict:
        return {
            "name": self.name, "provider": self.provider, "model": self.model,
            "endpoint": self.endpoint, "api_key_env": self.api_key_env,
            "context": self.context, "capabilities": self.capabilities, "roles": self.roles,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ModelSpec":
        return cls(
            name=str(d.get("name") or d.get("model") or "model"),
            provider=d.get("provider", "ollama"), model=d.get("model", ""),
            endpoint=d.get("endpoint", ""), api_key_env=d.get("api_key_env", ""),
            context=int(d.get("context", 8192) or 8192),
            capabilities=list(d.get("capabilities", [])), roles=list(d.get("roles", [])),
        )


# Rough task profiles: which capabilities / minimum context a role benefits from.
# Used only for AUTO-selection; explicit assignments always win.
ROLE_PROFILE = {
    "planner": {"caps": ["reasoning"], "min_ctx": 8192},
    "lead_researcher": {"caps": ["reasoning"], "min_ctx": 16384},
    "attack_chain_analyst": {"caps": ["reasoning"], "min_ctx": 16384},
    "vuln_analyst": {"caps": ["reasoning", "structured"], "min_ctx": 8192},
    "service_researcher": {"caps": ["structured"], "min_ctx": 8192},
    "web_researcher": {"caps": ["structured"], "min_ctx": 8192},
    "recon_analyst": {"caps": ["fast"], "min_ctx": 4096},
    "analyzer": {"caps": ["structured", "fast"], "min_ctx": 4096},
    "report_analyst": {"caps": ["reasoning"], "min_ctx": 16384},
    "reporter": {"caps": ["reasoning"], "min_ctx": 16384},
    "validation_analyst": {"caps": ["structured"], "min_ctx": 4096},
}


@dataclass
class ModelRegistry:
    models: dict[str, ModelSpec] = field(default_factory=dict)
    role_assignments: dict[str, str] = field(default_factory=dict)  # role -> model name
    default: str = ""

    def register(self, spec: ModelSpec) -> None:
        self.models[spec.name] = spec
        if not self.default:
            self.default = spec.name
        for role in spec.roles:
            self.role_assignments.setdefault(role, spec.name)

    def assign(self, role: str, model_name: str) -> bool:
        if model_name not in self.models:
            return False
        self.role_assignments[role] = model_name
        return True

    def default_spec(self) -> ModelSpec | None:
        if self.default and self.default in self.models:
            return self.models[self.default]
        return next(iter(self.models.values()), None)

    def _score(self, spec: ModelSpec, role: str) -> tuple:
        prof = ROLE_PROFILE.get(role, {"caps": [], "min_ctx": 0})
        cap_hits = sum(1 for c in prof["caps"] if c in spec.capabilities)
        ctx_ok = 1 if spec.context >= prof["min_ctx"] else 0
        role_pref = 1 if role in spec.roles else 0
        return (role_pref, cap_hits, ctx_ok, spec.context)

    def resolve_role(self, role: str) -> ModelSpec | None:
        """Explicit assignment first, then capability-based auto-selection."""
        name = self.role_assignments.get(role)
        if name and name in self.models:
            return self.models[name]
        if not self.models:
            return None
        # auto-select the best-scoring model for this role
        best = max(self.models.values(), key=lambda s: self._score(s, role))
        return best

    def fallback_spec(self, exclude: str = "") -> ModelSpec | None:
        for spec in self.models.values():
            if spec.name != exclude:
                return spec
        return None

    def status(self) -> str:
        if not self.models:
            return "no models registered (single-backend mode)"
        lines = [f"  default: {self.default}"]
        for spec in self.models.values():
            caps = ",".join(spec.capabilities) or "-"
            lines.append(f"  {spec.name:16s} {spec.provider}:{spec.model} "
                         f"ctx={spec.context} caps=[{caps}]")
        if self.role_assignments:
            lines.append("  role assignments:")
            for role, name in sorted(self.role_assignments.items()):
                lines.append(f"    {role:20s} -> {name}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "models": [s.to_dict() for s in self.models.values()],
            "role_assignments": self.role_assignments,
            "default": self.default,
        }


def load_registry(path: str = "models.json") -> ModelRegistry:
    reg = ModelRegistry()
    if not os.path.isfile(path):
        return reg
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return reg
    for m in data.get("models", []):
        if isinstance(m, dict) and (m.get("model") or m.get("name")):
            reg.register(ModelSpec.from_dict(m))
    for role, name in (data.get("role_assignments") or {}).items():
        reg.assign(role, name)
    if data.get("default") and data["default"] in reg.models:
        reg.default = data["default"]
    return reg


# ---------------------------------------------------------------------------
# RegistryBackend — a drop-in client that routes each role to its model.
#
# Implements the same surface the interactive loop uses (run_phase / analyze /
# plan / ping / base_url / planner_model / executor_model / structured / roles),
# so the rest of client.py works unchanged when a registry is active.
# ---------------------------------------------------------------------------

class RegistryBackend:
    def __init__(self, registry: ModelRegistry, make_backend, structured: bool = True,
                 roles=None):
        self.registry = registry
        self._make = make_backend          # fn(ModelSpec) -> AIBackend-like client
        self.structured = structured
        self.roles = roles                 # a RoleMap, for display compatibility
        self._cache: dict[str, object] = {}
        d = registry.default_spec()
        self.base_url = (d.endpoint if d and d.endpoint else d.provider) if d else ""
        self.planner_model = self.registry.resolve_role("planner").model if registry.models else ""
        self.executor_model = self.registry.resolve_role("analyzer").model if registry.models else ""

    def _backend(self, spec: ModelSpec):
        if spec.name not in self._cache:
            self._cache[spec.name] = self._make(spec)
        return self._cache[spec.name]

    def _for_role(self, role: str):
        spec = self.registry.resolve_role(role) or self.registry.default_spec()
        if spec is None:
            raise ConnectionError("no models registered")
        return spec

    def run_phase(self, phase: str, prompt: str, system: str = "",
                  want_json: bool = False) -> str:
        spec = self._for_role(phase)
        try:
            return self._backend(spec).run_phase(phase, prompt, system, want_json)
        except ConnectionError:
            fb = self.registry.fallback_spec(exclude=spec.name)
            if fb is None:
                raise
            return self._backend(fb).run_phase(phase, prompt, system, want_json)

    def analyze(self, prompt: str, system: str = "", want_json: bool = False) -> str:
        return self.run_phase("analyzer", prompt, system, want_json)

    def plan(self, prompt: str, system: str = "", want_json: bool = False) -> str:
        return self.run_phase("planner", prompt, system, want_json)

    def ping(self) -> list[str]:
        names = [f"{s.name}({s.provider}:{s.model})" for s in self.registry.models.values()]
        # best-effort reachability of the default model; never fatal
        d = self.registry.default_spec()
        if d is not None:
            try:
                self._backend(d).ping()
            except Exception:
                pass
        return names
