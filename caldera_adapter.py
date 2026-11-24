#!/usr/bin/env python3
"""
xs-ai caldera_adapter — optional Apache Caldera integration.

Imports knowledge and metadata from Caldera.  Does NOT create or launch
operations, and does NOT execute abilities.  All active use requires
explicit user approval and scope validation.

Caldera is NOT a mandatory dependency.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Caldera API client
# ---------------------------------------------------------------------------

@dataclass
class CalderaConfig:
    base_url: str = ""          # e.g. http://caldera:8888
    api_key: str = ""           # Caldera REST API key
    timeout: int = 15
    enabled: bool = False

    @staticmethod
    def from_env() -> "CalderaConfig":
        return CalderaConfig(
            base_url=os.environ.get("CALDERA_URL", ""),
            api_key=os.environ.get("CALDERA_API_KEY", ""),
            enabled=bool(os.environ.get("CALDERA_URL")),
        )

    @staticmethod
    def from_file(path: str) -> "CalderaConfig":
        if not os.path.isfile(path):
            return CalderaConfig()
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return CalderaConfig(
            base_url=data.get("caldera_url", ""),
            api_key=data.get("caldera_api_key", ""),
            enabled=data.get("caldera_enabled", False),
        )


class CalderaClient:
    def __init__(self, config: CalderaConfig):
        self.config = config
        self._base = config.base_url.rstrip("/")

    def _request(self, path: str, method: str = "GET", body: bytes | None = None) -> dict:
        url = f"{self._base}{path}"
        headers = {"KEY": self.config.api_key, "Content-Type": "application/json"}
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=self.config.timeout)
            return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}", "detail": e.read().decode()[:200]}
        except (urllib.error.URLError, OSError) as e:
            return {"error": str(e)}

    def health_check(self) -> tuple[bool, str]:
        result = self._request("/api/v2/health")
        if "error" in result:
            return False, result["error"]
        return True, "connected"

    def list_abilities(self) -> list[dict]:
        result = self._request("/api/v2/abilities")
        if isinstance(result, list):
            return result
        return []

    def list_adversaries(self) -> list[dict]:
        result = self._request("/api/v2/adversaries")
        if isinstance(result, list):
            return result
        return []

    def list_operations(self) -> list[dict]:
        result = self._request("/api/v2/operations")
        if isinstance(result, list):
            return result
        return []

    def list_agents(self) -> list[dict]:
        result = self._request("/api/v2/agents")
        if isinstance(result, list):
            return result
        return []

    def list_facts(self, source: str = "") -> list[dict]:
        path = f"/api/v2/facts/{source}" if source else "/api/v2/facts"
        result = self._request(path)
        if isinstance(result, list):
            return result
        return []

    def get_ability(self, ability_id: str) -> dict:
        return self._request(f"/api/v2/abilities/{ability_id}")

    def get_adversary(self, adversary_id: str) -> dict:
        return self._request(f"/api/v2/adversaries/{adversary_id}")


# ---------------------------------------------------------------------------
# Knowledge import
# ---------------------------------------------------------------------------

@dataclass
class CalderaAbility:
    ability_id: str
    name: str
    description: str
    tactic: str
    technique_id: str
    technique_name: str
    platforms: dict = field(default_factory=dict)  # platform -> executor list
    privilege: str = ""
    cleanup: list[str] = field(default_factory=list)
    requirements: list[dict] = field(default_factory=list)
    source: str = "caldera"

    def to_dict(self) -> dict:
        return {
            "ability_id": self.ability_id,
            "name": self.name,
            "description": self.description,
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "platforms": self.platforms,
            "privilege": self.privilege,
            "source": self.source,
        }


@dataclass
class CalderaAdversary:
    adversary_id: str
    name: str
    description: str
    ability_ids: list[str] = field(default_factory=list)
    source: str = "caldera"

    def to_dict(self) -> dict:
        return {
            "adversary_id": self.adversary_id,
            "name": self.name,
            "description": self.description,
            "ability_count": len(self.ability_ids),
            "source": self.source,
        }


@dataclass
class CalderaKnowledge:
    abilities: dict[str, CalderaAbility] = field(default_factory=dict)
    adversaries: dict[str, CalderaAdversary] = field(default_factory=dict)
    source_url: str = ""
    import_timestamp: str = ""

    def import_from_client(self, client: CalderaClient) -> dict:
        """Import abilities and adversaries. Returns stats."""
        import datetime
        stats = {"abilities": 0, "adversaries": 0, "errors": 0, "duplicates": 0}
        self.source_url = client.config.base_url
        self.import_timestamp = datetime.datetime.now().isoformat(timespec="seconds")

        for raw in client.list_abilities():
            try:
                aid = raw.get("ability_id", "")
                if not aid:
                    continue
                if aid in self.abilities:
                    stats["duplicates"] += 1
                    continue
                platforms = {}
                for executor in raw.get("executors", []):
                    plat = executor.get("platform", "unknown")
                    platforms.setdefault(plat, []).append({
                        "name": executor.get("name", ""),
                        "command": executor.get("command", "")[:200],
                    })
                self.abilities[aid] = CalderaAbility(
                    ability_id=aid,
                    name=raw.get("name", ""),
                    description=raw.get("description", ""),
                    tactic=raw.get("tactic", ""),
                    technique_id=raw.get("technique_id", ""),
                    technique_name=raw.get("technique_name", ""),
                    platforms=platforms,
                    privilege=raw.get("privilege", ""),
                )
                stats["abilities"] += 1
            except Exception:
                stats["errors"] += 1

        for raw in client.list_adversaries():
            try:
                adv_id = raw.get("adversary_id", "")
                if not adv_id or adv_id in self.adversaries:
                    stats["duplicates"] += 1
                    continue
                ability_ids = []
                for phase_abilities in raw.get("atomic_ordering", []):
                    if isinstance(phase_abilities, str):
                        ability_ids.append(phase_abilities)
                self.adversaries[adv_id] = CalderaAdversary(
                    adversary_id=adv_id,
                    name=raw.get("name", ""),
                    description=raw.get("description", ""),
                    ability_ids=ability_ids,
                )
                stats["adversaries"] += 1
            except Exception:
                stats["errors"] += 1

        return stats

    def lookup_technique(self, technique_id: str) -> list[CalderaAbility]:
        return [a for a in self.abilities.values() if a.technique_id == technique_id]

    def search(self, query: str) -> list[CalderaAbility]:
        q = query.lower()
        return [a for a in self.abilities.values()
                if q in a.name.lower() or q in a.description.lower() or
                q in a.technique_id.lower()]

    def stats(self) -> dict:
        tactics: dict[str, int] = {}
        for a in self.abilities.values():
            tactics[a.tactic] = tactics.get(a.tactic, 0) + 1
        return {
            "abilities": len(self.abilities),
            "adversaries": len(self.adversaries),
            "tactics": tactics,
            "source": self.source_url,
        }

    def save(self, path: str) -> None:
        data = {
            "source_url": self.source_url,
            "import_timestamp": self.import_timestamp,
            "stats": self.stats(),
            "abilities": {aid: a.to_dict() for aid, a in self.abilities.items()},
            "adversaries": {aid: a.to_dict() for aid, a in self.adversaries.items()},
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def load(path: str) -> "CalderaKnowledge":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        kb = CalderaKnowledge(
            source_url=data.get("source_url", ""),
            import_timestamp=data.get("import_timestamp", ""),
        )
        for aid, ad in data.get("abilities", {}).items():
            kb.abilities[aid] = CalderaAbility(
                ability_id=ad["ability_id"], name=ad.get("name", ""),
                description=ad.get("description", ""),
                tactic=ad.get("tactic", ""), technique_id=ad.get("technique_id", ""),
                technique_name=ad.get("technique_name", ""),
                platforms=ad.get("platforms", {}), privilege=ad.get("privilege", ""),
            )
        for adv_id, adv in data.get("adversaries", {}).items():
            kb.adversaries[adv_id] = CalderaAdversary(
                adversary_id=adv["adversary_id"], name=adv.get("name", ""),
                description=adv.get("description", ""),
            )
        return kb


# ---------------------------------------------------------------------------
# AI context helpers
# ---------------------------------------------------------------------------

def format_caldera_context(abilities: list[CalderaAbility], max_items: int = 5) -> str:
    if not abilities:
        return ""
    lines = ["--- Caldera Ability Reference ---"]
    for a in abilities[:max_items]:
        lines.append(f"\n[{a.technique_id}] {a.name} (tactic: {a.tactic})")
        lines.append(f"  {a.description[:200]}")
        lines.append("  NOTE: Reference only. No automatic execution.")
    return "\n".join(lines)
