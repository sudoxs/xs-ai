#!/usr/bin/env python3
"""
xs-ai connection modes — keep the existing DIRECT mode and add SECURE remote
options, with explicit trust-boundary documentation and connection diagnostics.

Modes:
  direct       Ollama exposed on a network interface (existing behavior). Higher
               risk: the API has no built-in authentication. Warn when the host
               is not loopback.
  ssh-tunnel   Ollama stays bound to localhost on the host; reach it through an
               SSH local port-forward. The client talks to 127.0.0.1.
  vpn          Reach the host over a private overlay (WireGuard / Tailscale) IP.
               A VPN provides transport confidentiality, NOT application auth.

Pure standard library.
"""

from __future__ import annotations

import socket
import time

MODES = ("direct", "ssh-tunnel", "vpn")


def trust_notes(mode: str) -> list[str]:
    if mode == "ssh-tunnel":
        return [
            "SSH tunnel: Ollama should stay bound to 127.0.0.1 on the host.",
            "Confidentiality + authentication come from SSH; the client talks to localhost.",
            "Set up the forward on the CLIENT, e.g.:",
            "    ssh -N -L 11434:127.0.0.1:11434 <user>@<host>",
            "Trust boundary: anyone who can use the SSH session can reach the model.",
        ]
    if mode == "vpn":
        return [
            "VPN/overlay (WireGuard, Tailscale, …): use the host's overlay IP as --host.",
            "A VPN protects the transport but does NOT authenticate the Ollama API.",
            "Keep the Ollama port firewalled to the overlay interface only.",
            "Trust boundary: every device on the overlay can reach the model.",
        ]
    # direct
    return [
        "DIRECT mode: the Ollama API may be exposed with NO built-in authentication.",
        "Bind to a specific interface and firewall the port to trusted hosts only.",
        "Never create router/port-forward rules to expose it to the internet.",
    ]


def resolve(mode: str, host: str, port: int) -> tuple[str, int, list[str]]:
    """Return (effective_host, effective_port, guidance_lines) for the mode.

    ssh-tunnel rewrites the target to localhost (the forwarded port); direct and
    vpn keep the given host. Guidance always includes the trust notes plus any
    exposure warning."""
    guidance = list(trust_notes(mode))
    if mode == "ssh-tunnel":
        return "127.0.0.1", port, guidance
    if mode == "direct" and host not in ("127.0.0.1", "localhost", "::1"):
        guidance.insert(0, f"⚠ connecting to {host}:{port} directly — ensure this "
                           f"interface/port is firewalled to you only.")
    return host, port, guidance


def diagnose(host: str, port: int, timeout: float = 4.0) -> tuple[bool, str]:
    """Best-effort TCP reachability + latency check. Never raises."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            ms = (time.monotonic() - start) * 1000
            exposure = "loopback (not network-exposed)" if host in ("127.0.0.1", "localhost", "::1") \
                else "reachable over the network"
            return True, f"reachable in {ms:.0f} ms — {exposure}"
    except OSError as exc:
        return False, f"not reachable ({exc})"
