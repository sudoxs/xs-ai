#!/usr/bin/env python3
"""
xs-ai atomic_red_team — Atomic Red Team data importer and knowledge integration.

Parses Atomic Red Team YAML test definitions and stores them as a structured
knowledge repository that the AI can query during investigation.

NEVER automatically executes tests.  Any future execution requires explicit
authorization, scope validation, and user approval.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# YAML parser (pure-stdlib, no PyYAML dependency)
# ---------------------------------------------------------------------------
# Atomic Red Team YAML is well-structured enough to parse with a simple
# state-machine parser that handles the fields we need. For full YAML
# compliance, users can install PyYAML, and we fall back to this.

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _yaml = None  # type: ignore
    _HAS_YAML = False


def _parse_yaml_file(path: str) -> dict:
    """Parse a YAML file, using PyYAML if available, else a minimal parser."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if _HAS_YAML:
        return _yaml.safe_load(text) or {}
    return _mini_yaml_parse(text)


def _mini_yaml_parse(text: str) -> dict:
    """Minimal YAML parser sufficient for Atomic Red Team definitions."""
    import io
    result: dict = {}
    lines = text.split("\n")
    i = 0

    def _read_block_scalar(start: int, indent: int) -> tuple[str, int]:
        parts = []
        j = start
        while j < len(lines):
            line = lines[j]
            if line.strip() == "" or (len(line) > 0 and len(line) - len(line.lstrip()) > indent):
                parts.append(line)
                j += 1
            elif line.strip() and len(line) - len(line.lstrip()) <= indent and parts:
                break
            else:
                parts.append(line)
                j += 1
        return "\n".join(parts).strip(), j

    # Simple top-level key extraction
    current_key = ""
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(" ") and ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if val and not val.startswith("|") and not val.startswith("-"):
                result[key] = val.strip("'\"")
            current_key = key

    # For atomic_tests, we need a more robust approach
    if "atomic_tests" not in result and "atomic_tests:" in text:
        result["atomic_tests"] = []
        # Extract test blocks by finding "- name:" patterns
        test_blocks = re.split(r"\n  - name:", text)
        if len(test_blocks) > 1:
            for block in test_blocks[1:]:
                test: dict = {"name": "", "description": "", "supported_platforms": [],
                              "executor": {}, "input_arguments": {}, "dependencies": []}
                # name
                name_line = block.split("\n")[0].strip()
                test["name"] = name_line.strip("'\"")

                # auto_generated_guid
                m = re.search(r"auto_generated_guid:\s*(\S+)", block)
                if m:
                    test["auto_generated_guid"] = m.group(1)

                # description
                m = re.search(r"description:\s*[|>]-?\s*\n((?:[ \t]+.*\n?)*)", block)
                if m:
                    test["description"] = re.sub(r"\n[ \t]+", "\n", m.group(1)).strip()
                else:
                    m = re.search(r"description:\s*(.+)", block)
                    if m:
                        test["description"] = m.group(1).strip("'\"")

                # supported_platforms
                platforms = re.findall(r"- (windows|linux|macos|iaas:gcp|iaas:aws|iaas:azure|containers|office-365)", block)
                test["supported_platforms"] = platforms

                # executor name
                m = re.search(r"executor:\s*\n\s+name:\s*(\S+)", block)
                if m:
                    test["executor"]["name"] = m.group(1)

                # elevation_required
                if "elevation_required: true" in block.lower():
                    test["executor"]["elevation_required"] = True

                # command
                m = re.search(r"command:\s*[|>]-?\s*\n((?:[ \t]+.*\n?)*)", block)
                if m:
                    test["executor"]["command"] = re.sub(r"\n[ \t]{6,}", "\n", m.group(1)).strip()

                # cleanup_command
                m = re.search(r"cleanup_command:\s*[|>]-?\s*\n((?:[ \t]+.*\n?)*)", block)
                if m:
                    test["executor"]["cleanup_command"] = re.sub(r"\n[ \t]{6,}", "\n", m.group(1)).strip()

                # steps (alternative to command for manual executors)
                m = re.search(r"steps:\s*[|>]-?\s*\n((?:[ \t]+.*\n?)*)", block)
                if m:
                    test["executor"]["steps"] = re.sub(r"\n[ \t]{6,}", "\n", m.group(1)).strip()

                result["atomic_tests"].append(test)

    return result


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AtomicTest:
    technique_id: str
    technique_name: str
    test_id: str
    test_name: str
    description: str
    supported_platforms: list[str] = field(default_factory=list)
    executor_name: str = ""
    command: str = ""
    steps: str = ""
    cleanup_command: str = ""
    elevation_required: bool = False
    input_arguments: dict = field(default_factory=dict)
    dependencies: list[dict] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "test_id": self.test_id,
            "test_name": self.test_name,
            "description": self.description,
            "supported_platforms": self.supported_platforms,
            "executor_name": self.executor_name,
            "elevation_required": self.elevation_required,
        }
        if self.command:
            d["command"] = self.command
        if self.steps:
            d["steps"] = self.steps
        if self.cleanup_command:
            d["cleanup_command"] = self.cleanup_command
        if self.input_arguments:
            d["input_arguments"] = self.input_arguments
        if self.dependencies:
            d["dependencies"] = self.dependencies
        if self.references:
            d["references"] = self.references
        return d


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

@dataclass
class AtomicRepository:
    tests: dict[str, list[AtomicTest]] = field(default_factory=dict)
    version: str = ""
    source_path: str = ""

    def import_directory(self, atomics_dir: str) -> dict:
        """Import all technique directories from an atomic-red-team/atomics/ folder.
        Returns {imported, skipped, updated, errors}."""
        stats = {"imported": 0, "skipped": 0, "updated": 0, "errors": 0}
        self.source_path = atomics_dir

        if not os.path.isdir(atomics_dir):
            stats["errors"] += 1
            return stats

        for entry in sorted(os.listdir(atomics_dir)):
            if not entry.startswith("T"):
                continue
            yaml_path = os.path.join(atomics_dir, entry, f"{entry}.yaml")
            if not os.path.isfile(yaml_path):
                continue
            try:
                data = _parse_yaml_file(yaml_path)
                tech_id = data.get("attack_technique", entry)
                tech_name = data.get("display_name", "")
                tests_data = data.get("atomic_tests", [])
                if not tests_data:
                    stats["skipped"] += 1
                    continue

                existing_ids = {t.test_id for t in self.tests.get(tech_id, [])}
                new_tests = []
                for td in tests_data:
                    test_id = td.get("auto_generated_guid", "")
                    if test_id in existing_ids:
                        stats["updated"] += 1
                        continue
                    executor = td.get("executor", {})
                    test = AtomicTest(
                        technique_id=tech_id,
                        technique_name=tech_name,
                        test_id=test_id,
                        test_name=td.get("name", ""),
                        description=td.get("description", ""),
                        supported_platforms=td.get("supported_platforms", []),
                        executor_name=executor.get("name", ""),
                        command=executor.get("command", ""),
                        steps=executor.get("steps", ""),
                        cleanup_command=executor.get("cleanup_command", ""),
                        elevation_required=executor.get("elevation_required", False),
                        input_arguments=td.get("input_arguments", {}),
                        dependencies=td.get("dependencies", []),
                    )
                    new_tests.append(test)
                    stats["imported"] += 1

                if tech_id not in self.tests:
                    self.tests[tech_id] = []
                self.tests[tech_id].extend(new_tests)

            except Exception:
                stats["errors"] += 1

        return stats

    def lookup(self, technique_id: str) -> list[AtomicTest]:
        return self.tests.get(technique_id, [])

    def search(self, query: str) -> list[AtomicTest]:
        q = query.lower()
        results = []
        for tests in self.tests.values():
            for t in tests:
                if (q in t.technique_id.lower() or q in t.test_name.lower() or
                        q in t.description.lower() or q in t.technique_name.lower()):
                    results.append(t)
        return results

    def by_platform(self, platform: str) -> list[AtomicTest]:
        p = platform.lower()
        results = []
        for tests in self.tests.values():
            for t in tests:
                if p in [sp.lower() for sp in t.supported_platforms]:
                    results.append(t)
        return results

    def stats(self) -> dict:
        total_tests = sum(len(ts) for ts in self.tests.values())
        platforms: dict[str, int] = {}
        for tests in self.tests.values():
            for t in tests:
                for p in t.supported_platforms:
                    platforms[p] = platforms.get(p, 0) + 1
        return {
            "techniques": len(self.tests),
            "total_tests": total_tests,
            "platforms": platforms,
            "source": self.source_path,
        }

    def save(self, path: str) -> None:
        data = {
            "version": self.version,
            "source_path": self.source_path,
            "stats": self.stats(),
            "techniques": {
                tid: [t.to_dict() for t in tests]
                for tid, tests in self.tests.items()
            },
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def load(path: str) -> "AtomicRepository":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        repo = AtomicRepository(version=data.get("version", ""),
                                source_path=data.get("source_path", ""))
        for tid, tests_data in data.get("techniques", {}).items():
            tests = []
            for td in tests_data:
                tests.append(AtomicTest(
                    technique_id=td["technique_id"],
                    technique_name=td.get("technique_name", ""),
                    test_id=td.get("test_id", ""),
                    test_name=td.get("test_name", ""),
                    description=td.get("description", ""),
                    supported_platforms=td.get("supported_platforms", []),
                    executor_name=td.get("executor_name", ""),
                    command=td.get("command", ""),
                    steps=td.get("steps", ""),
                    cleanup_command=td.get("cleanup_command", ""),
                    elevation_required=td.get("elevation_required", False),
                    input_arguments=td.get("input_arguments", {}),
                    dependencies=td.get("dependencies", []),
                ))
            repo.tests[tid] = tests
        return repo


# ---------------------------------------------------------------------------
# AI integration helpers
# ---------------------------------------------------------------------------

def format_atomic_context(tests: list[AtomicTest], max_tests: int = 5) -> str:
    """Format Atomic Red Team tests for AI context injection."""
    if not tests:
        return ""
    lines = ["--- Atomic Red Team Reference ---"]
    for t in tests[:max_tests]:
        lines.append(f"\n[{t.technique_id}] {t.test_name}")
        lines.append(f"  Platforms: {', '.join(t.supported_platforms)}")
        lines.append(f"  Executor: {t.executor_name}")
        if t.elevation_required:
            lines.append("  Requires elevation: yes")
        lines.append(f"  Description: {t.description[:200]}")
        if t.command:
            lines.append(f"  Command preview: {t.command[:150]}")
        lines.append("  NOTE: Do NOT execute — reference only. Requires explicit authorization.")
    return "\n".join(lines)
