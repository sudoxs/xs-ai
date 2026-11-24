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

import abc
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any


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
        required_caps = prof["caps"]
        cap_hits = sum(1 for c in required_caps if c in spec.capabilities)
        cap_total = len(required_caps) if required_caps else 1
        cap_ratio = cap_hits / cap_total
        ctx_ok = 1 if spec.context >= prof["min_ctx"] else 0
        role_pref = 1 if role in spec.roles else 0
        return (role_pref, cap_ratio, cap_hits, ctx_ok, spec.context)

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

    def fallback_spec(self, exclude: str = "", role: str = "") -> ModelSpec | None:
        candidates = [s for s in self.models.values() if s.name != exclude]
        if not candidates:
            return None
        if role:
            candidates.sort(key=lambda s: self._score(s, role), reverse=True)
        return candidates[0]

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


# ===========================================================================
# Multi-provider LLM abstraction
#
# One small interface — chat() / list_models() / health_check() — with concrete
# providers for Ollama, any OpenAI-compatible API (OpenAI, DeepSeek, Groq,
# Together, OpenRouter, LM Studio, ...), and Google Gemini. A ProviderBackend
# adapter exposes the same surface the interactive loop already uses, so the
# rest of the app never imports a specific provider's HTTP directly.
# ===========================================================================

AI_TIMEOUT_DEFAULT = 180


def redact_key(key: str) -> str:
    """Never print a full API key — show only the last 4 chars."""
    if not key:
        return "(none)"
    return f"...{key[-4:]}" if len(key) > 4 else "****"


class BaseProvider(abc.ABC):
    name = "base"

    def __init__(self, model: str = "", timeout: int = AI_TIMEOUT_DEFAULT):
        self.model = model
        self.timeout = timeout

    @abc.abstractmethod
    def chat(self, messages: list[dict], temperature: float = 0.15,
             want_json: bool = False) -> str:
        ...

    def list_models(self) -> list[str]:
        return [self.model] if self.model else []

    def health_check(self) -> tuple[bool, str]:
        try:
            self.list_models()
            return True, "ok"
        except Exception as exc:
            return False, str(exc)

    def _post_json(self, url: str, payload: dict, headers: dict) -> dict:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json", **headers},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode())

    def _get_json(self, url: str, headers: dict | None = None) -> dict:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=min(self.timeout, 10)) as resp:
            return json.loads(resp.read().decode())


class OllamaProvider(BaseProvider):
    name = "ollama"

    def __init__(self, base_url: str, model: str = "", timeout: int = AI_TIMEOUT_DEFAULT):
        super().__init__(model, timeout)
        self.base_url = base_url.rstrip("/")

    def chat(self, messages, temperature=0.15, want_json=False) -> str:
        payload: dict[str, Any] = {
            "model": self.model, "messages": messages, "stream": False,
            "options": {"temperature": temperature},
        }
        if want_json:
            payload["format"] = "json"
        try:
            result = self._post_json(f"{self.base_url}/api/chat", payload, {})
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise ConnectionError(f"Ollama HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectionError(f"Ollama unreachable: {exc}") from exc
        return str(result.get("message", {}).get("content", "")).strip()

    def list_models(self) -> list[str]:
        data = self._get_json(f"{self.base_url}/api/tags")
        return [m["name"] for m in data.get("models", [])]

    def health_check(self) -> tuple[bool, str]:
        try:
            models = self.list_models()
            return True, f"{len(models)} model(s) available"
        except Exception as exc:
            return False, (f"cannot reach Ollama at {self.base_url} ({exc}). "
                           f"Run host_setup.ps1 on the host and pass --host <IP>.")


class OpenAICompatProvider(BaseProvider):
    """Any OpenAI-compatible /v1/chat/completions endpoint."""
    name = "openai"

    def __init__(self, base_url: str, api_key: str, model: str = "",
                 timeout: int = AI_TIMEOUT_DEFAULT):
        super().__init__(model, timeout)
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    def chat(self, messages, temperature=0.15, want_json=False) -> str:
        payload: dict[str, Any] = {"model": self.model, "messages": messages,
                                   "temperature": temperature}
        if want_json:
            payload["response_format"] = {"type": "json_object"}
        try:
            result = self._post_json(f"{self.base_url}/chat/completions", payload, self._headers())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise ConnectionError(f"OpenAI-compat HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectionError(f"OpenAI-compat unreachable at {self.base_url}: {exc}") from exc
        return str(result["choices"][0]["message"]["content"]).strip()

    def list_models(self) -> list[str]:
        data = self._get_json(f"{self.base_url}/models", self._headers())
        return [m.get("id", "") for m in data.get("data", [])][:20]

    def health_check(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, ("no API key — pass --api-key (or set XS_API_KEY). Example: "
                           "--provider openai --base-url https://api.deepseek.com/v1 "
                           "--api-key sk-... --model deepseek-chat")
        try:
            self.list_models()
            return True, f"reachable at {self.base_url}"
        except Exception as exc:
            return False, f"cannot reach {self.base_url} ({exc}). Check --base-url and --api-key."


class GeminiProvider(BaseProvider):
    """Google AI Studio (generativelanguage.googleapis.com)."""
    name = "gemini"
    BASE = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(self, api_key: str, model: str = "gemini-1.5-flash",
                 timeout: int = AI_TIMEOUT_DEFAULT):
        super().__init__(model or "gemini-1.5-flash", timeout)
        self.api_key = api_key

    def chat(self, messages, temperature=0.15, want_json=False) -> str:
        system = "\n".join(m["content"] for m in messages if m.get("role") == "system")
        contents = []
        for m in messages:
            if m.get("role") == "system":
                continue
            role = "model" if m.get("role") == "assistant" else "user"
            text = m["content"]
            if system and role == "user" and not contents:
                text = f"{system}\n\n{text}"
            contents.append({"role": role, "parts": [{"text": text}]})
        payload: dict[str, Any] = {"contents": contents,
                                   "generationConfig": {"temperature": temperature}}
        if want_json:
            payload["generationConfig"]["responseMimeType"] = "application/json"
        url = f"{self.BASE}/models/{self.model}:generateContent?key={self.api_key}"
        try:
            result = self._post_json(url, payload, {})
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise ConnectionError(f"Gemini HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectionError(f"Gemini unreachable: {exc}") from exc
        try:
            return str(result["candidates"][0]["content"]["parts"][0]["text"]).strip()
        except (KeyError, IndexError):
            return ""

    def list_models(self) -> list[str]:
        data = self._get_json(f"{self.BASE}/models?key={self.api_key}")
        return [m.get("name", "").split("/")[-1] for m in data.get("models", [])][:20]

    def health_check(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, "no API key — pass --api-key. Example: --provider gemini --api-key AIza..."
        try:
            self.list_models()
            return True, f"reachable (model {self.model})"
        except Exception as exc:
            return False, f"cannot reach Gemini ({exc}). Check --api-key."


DEFAULT_BASE_URLS = {"openai": "https://api.openai.com/v1"}
DEFAULT_MODELS = {"ollama": "qwen2.5-coder:7b", "openai": "gpt-4o-mini",
                  "gemini": "gemini-1.5-flash"}


def make_provider(provider: str, *, host: str = "", port: int = 11434,
                  base_url: str = "", api_key: str = "", model: str = "",
                  timeout: int = AI_TIMEOUT_DEFAULT) -> BaseProvider:
    provider = (provider or "ollama").lower()
    mdl = model or DEFAULT_MODELS.get(provider, "")
    if provider == "ollama":
        url = base_url or f"http://{host or '127.0.0.1'}:{port}"
        return OllamaProvider(url, mdl, timeout)
    if provider == "openai":
        return OpenAICompatProvider(base_url or DEFAULT_BASE_URLS["openai"], api_key, mdl, timeout)
    if provider == "gemini":
        return GeminiProvider(api_key, mdl, timeout)
    raise ValueError(f"unknown provider: {provider}")


class ProviderBackend:
    """Adapts a BaseProvider to the interface the interactive loop uses, so no
    caller imports a provider's HTTP directly."""

    def __init__(self, provider: BaseProvider, structured: bool = True, roles=None):
        self.provider = provider
        self.structured = structured
        self.roles = roles
        self.planner_model = self.executor_model = provider.model
        self.base_url = getattr(provider, "base_url", provider.name)

    def run_phase(self, phase: str, prompt: str, system: str = "",
                  want_json: bool = False) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self.provider.chat(messages, want_json=want_json)

    def analyze(self, prompt: str, system: str = "", want_json: bool = False) -> str:
        return self.run_phase("analyzer", prompt, system, want_json)

    def plan(self, prompt: str, system: str = "", want_json: bool = False) -> str:
        return self.run_phase("planner", prompt, system, want_json)

    def ping(self) -> list[str]:
        return self.provider.list_models()
