"""Scope allowlist loading and authorization enforcement for ReconCopilot."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from reconcopilot.config import load_config


class ScopeViolationError(PermissionError):
    """Raised when an operation is attempted on an unauthorized target."""


def _extract_host(target: str) -> str:
    """Extracts raw host or IP from URL or host:port string."""
    cleaned = target.strip()
    if not cleaned:
        return ""

    # If it contains scheme or slashes, try urlparse
    if "://" in cleaned or cleaned.startswith("//"):
        parsed = urlparse(cleaned)
        cleaned = parsed.hostname or cleaned
    elif "/" in cleaned and not cleaned.endswith("/"):
        # Could be path or CIDR
        if (
            not re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", cleaned)
            and ":" not in cleaned
        ):
            parsed = urlparse("//" + cleaned)
            cleaned = parsed.hostname or cleaned

    # Strip port if present in host:port (handling IPv6 [::1]:80 vs 1.2.3.4:80)
    if cleaned.startswith("[") and "]" in cleaned:
        # IPv6 with bracket
        closing = cleaned.find("]")
        cleaned = cleaned[1:closing]
    elif ":" in cleaned and cleaned.count(":") == 1:
        # host:port IPv4 or domain
        cleaned = cleaned.split(":")[0]

    return cleaned.strip().lower()


class ScopeAllowlist:
    """Manages authorized IP ranges, specific IPs, and domain patterns."""

    def __init__(self, rules: Iterable[str] | None = None) -> None:
        self.exact_domains: set[str] = set()
        self.wildcard_domains: list[str] = []
        self.ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.ip_addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()

        if rules:
            self.load_rules(rules)

    def add_rule(self, rule: str) -> None:
        """Parses and adds a single rule to the allowlist."""
        rule = rule.strip()
        if not rule or rule.startswith("#"):
            return

        # Strip inline comments
        if " #" in rule:
            rule = rule.split(" #")[0].strip()

        # Try parsing as IP network CIDR
        if "/" in rule:
            try:
                network = ipaddress.ip_network(rule, strict=False)
                self.ip_networks.append(network)
                return
            except ValueError:
                pass

        # Try parsing as standalone IP
        try:
            ip = ipaddress.ip_address(rule)
            self.ip_addresses.add(ip)
            return
        except ValueError:
            pass

        # Parse as domain or wildcard domain
        domain = rule.lower()
        if domain.startswith("*."):
            suffix = domain[2:]
            if suffix:
                self.wildcard_domains.append(suffix)
        elif domain.startswith("."):
            suffix = domain[1:]
            if suffix:
                self.wildcard_domains.append(suffix)
        else:
            self.exact_domains.add(domain)

    def load_rules(self, rules: Iterable[str]) -> None:
        """Loads multiple rules into the allowlist."""
        for r in rules:
            self.add_rule(r)

    @classmethod
    def from_file(cls, file_path: str | Path) -> ScopeAllowlist:
        """Creates a ScopeAllowlist from a text file containing rules."""
        p = Path(file_path).expanduser().resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Scope file not found: {p}")
        with open(p, "r", encoding="utf-8") as f:
            return cls(f.readlines())

    def is_in_scope(self, target: str) -> bool:
        """Checks whether the given target (domain, IP, URL) is authorized.

        Args:
            target: Target string to check.

        Returns:
            True if target matches an allowlisted domain, wildcard, IP or CIDR.
        """
        host = _extract_host(target)
        if not host:
            return False

        # 1. Check if host is an IP address
        try:
            ip = ipaddress.ip_address(host)
            if ip in self.ip_addresses:
                return True
            for net in self.ip_networks:
                if ip in net:
                    return True
            return False
        except ValueError:
            pass

        # 2. Check domain rules
        host_lower = host.lower()
        if host_lower in self.exact_domains:
            return True

        # Check wildcard subdomains:
        # e.g. rule "*.example.com" matches "sub.example.com", "a.b.example.com", and "example.com"
        for suffix in self.wildcard_domains:
            if host_lower == suffix or host_lower.endswith("." + suffix):
                return True

        return False

    def enforce(self, target: str) -> str:
        """Enforces that target is in scope, raising ScopeViolationError if not.

        Returns:
            The normalized target host if allowed.
        """
        if not self.is_in_scope(target):
            raise ScopeViolationError(
                f"Scope violation: target '{target}' is not in authorized allowlist."
            )
        return _extract_host(target)


def get_default_scope() -> ScopeAllowlist:
    """Loads scope allowlist from configured scope file, or empty allowlist."""
    cfg = load_config()
    allowlist_file = cfg.scope.allowlist_file
    if allowlist_file:
        p = Path(allowlist_file).expanduser().resolve()
        if p.is_file():
            return ScopeAllowlist.from_file(p)
    return ScopeAllowlist()


def enforce_scope(
    target: str,
    scope: ScopeAllowlist | None = None,
    strict: bool | None = None,
) -> str:
    """Global helper to enforce scope compliance.

    Args:
        target: Target to validate.
        scope: Optional ScopeAllowlist instance; defaults to configured allowlist.
        strict: Optional flag to override strict mode; defaults to config.scope.strict_mode.

    Returns:
        The normalized host string.
    """
    cfg = load_config()
    is_strict = cfg.scope.strict_mode if strict is None else strict

    if not is_strict:
        return _extract_host(target)

    active_scope = scope or get_default_scope()
    return active_scope.enforce(target)
