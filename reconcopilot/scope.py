"""Scope loading, validation, and enforcement for ReconCopilot.

Provides the ScopeChecker class, scope directory discovery, and the
require_in_scope enforcement decorator and helper function.
"""

from __future__ import annotations

import functools
import inspect
import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

import yaml

from reconcopilot.config import load_config


class ScopeViolationError(PermissionError):
    """Raised when an operation is attempted on an unauthorized target."""


@dataclass
class ScopeCheckResult:
    """Outcome of a scope evaluation for a target."""

    in_scope: bool
    reason: str
    target: str
    normalized_target: str
    matched_rule: str | None = None
    matched_exclusion: str | None = None

    def __bool__(self) -> bool:
        return self.in_scope


def get_scopes_dir(custom_dir: str | Path | None = None) -> Path:
    """Resolves the directory storing scope YAML files.

    Default: ~/.config/reconcopilot/scopes/
    Can be overridden via RECONCOPILOT_SCOPES_DIR or argument.
    """
    if custom_dir is not None:
        p = Path(custom_dir).expanduser().resolve()
    elif os.getenv("RECONCOPILOT_SCOPES_DIR"):
        p = Path(os.environ["RECONCOPILOT_SCOPES_DIR"]).expanduser().resolve()
    else:
        p = Path.home() / ".config" / "reconcopilot" / "scopes"

    p.mkdir(parents=True, exist_ok=True)
    return p


def _extract_host(target: str) -> str:
    """Extracts raw host or IP from URL, CIDR, or host:port string."""
    cleaned = target.strip()
    if not cleaned:
        return ""

    # If it contains scheme or slashes, try urlparse
    if "://" in cleaned or cleaned.startswith("//"):
        parsed = urlparse(cleaned)
        cleaned = parsed.hostname or cleaned
    elif "/" in cleaned and not cleaned.endswith("/"):
        # Check if it is a CIDR network
        is_cidr = False
        try:
            ipaddress.ip_network(cleaned, strict=False)
            is_cidr = True
        except ValueError:
            pass

        if not is_cidr:
            parsed = urlparse("//" + cleaned)
            cleaned = parsed.hostname or cleaned

    # Strip port if present in host:port
    if cleaned.startswith("[") and "]" in cleaned:
        # IPv6 with bracket
        closing = cleaned.find("]")
        cleaned = cleaned[1:closing]
    elif ":" in cleaned and cleaned.count(":") == 1:
        # host:port
        cleaned = cleaned.split(":")[0]

    return cleaned.strip().lower()


class ScopeChecker:
    """Loads and validates target authorization against a defined scope."""

    def __init__(
        self,
        data: dict[str, Any] | None = None,
        file_path: Path | str | None = None,
    ) -> None:
        self.file_path = Path(file_path).resolve() if file_path else None
        data = data or {}

        self.name: str = str(data.get("name", "unnamed")).strip()
        targets_data = data.get("targets", {}) or {}

        # Raw lists
        self.domains: list[str] = [
            str(d).strip().lower()
            for d in targets_data.get("domains", [])
            if str(d).strip()
        ]
        self.ip_ranges: list[str] = [
            str(r).strip() for r in targets_data.get("ip_ranges", []) if str(r).strip()
        ]
        self.exclusions: list[str] = [
            str(e).strip() for e in targets_data.get("exclusions", []) if str(e).strip()
        ]
        self.metadata: dict[str, Any] = data.get("metadata", {}) or {}

        # Parsed structures for efficient lookup
        self._exact_domains: set[str] = set()
        self._wildcard_domains: list[str] = []
        self._ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._ip_addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()

        self._excluded_exact_domains: set[str] = set()
        self._excluded_wildcard_domains: list[str] = []
        self._excluded_ip_networks: list[
            ipaddress.IPv4Network | ipaddress.IPv6Network
        ] = []
        self._excluded_ip_addresses: set[
            ipaddress.IPv4Address | ipaddress.IPv6Address
        ] = set()

        self._parse_inclusions()
        self._parse_exclusions()

    def _parse_inclusions(self) -> None:
        for domain in self.domains:
            self._add_domain_rule(domain, is_exclusion=False)
        for ip_entry in self.ip_ranges:
            self._add_ip_rule(ip_entry, is_exclusion=False)

    def _parse_exclusions(self) -> None:
        for entry in self.exclusions:
            cleaned = entry.strip()
            # Try parsing as IP or CIDR first
            if not self._add_ip_rule(cleaned, is_exclusion=True):
                # Otherwise parse as domain
                self._add_domain_rule(cleaned, is_exclusion=True)

    def _add_domain_rule(self, rule: str, is_exclusion: bool = False) -> None:
        cleaned = rule.strip().lower()
        if not cleaned:
            return

        if cleaned.startswith("*."):
            suffix = cleaned[2:]
            if suffix:
                if is_exclusion:
                    self._excluded_wildcard_domains.append(suffix)
                else:
                    self._wildcard_domains.append(suffix)
        elif cleaned.startswith("."):
            suffix = cleaned[1:]
            if suffix:
                if is_exclusion:
                    self._excluded_wildcard_domains.append(suffix)
                else:
                    self._wildcard_domains.append(suffix)
        else:
            if is_exclusion:
                self._excluded_exact_domains.add(cleaned)
            else:
                self._exact_domains.add(cleaned)

    def _add_ip_rule(self, rule: str, is_exclusion: bool = False) -> bool:
        cleaned = rule.strip()
        if "/" in cleaned:
            try:
                net = ipaddress.ip_network(cleaned, strict=False)
                if is_exclusion:
                    self._excluded_ip_networks.append(net)
                else:
                    self._ip_networks.append(net)
                return True
            except ValueError:
                return False
        else:
            try:
                ip = ipaddress.ip_address(cleaned)
                if is_exclusion:
                    self._excluded_ip_addresses.add(ip)
                else:
                    self._ip_addresses.add(ip)
                return True
            except ValueError:
                return False

    @classmethod
    def from_file(cls, path: str | Path) -> ScopeChecker:
        """Loads a scope from a YAML file."""
        p = Path(path).expanduser().resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Scope file not found: {p}")

        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if not isinstance(data, dict):
            raise ValueError(
                f"Invalid scope file contents in {p}: expected YAML mapping"
            )

        return cls(data=data, file_path=p)

    @classmethod
    def from_name(cls, name: str, scopes_dir: str | Path | None = None) -> ScopeChecker:
        """Finds and loads a scope by name from the scopes directory."""
        clean_name = name.strip()
        base_dir = get_scopes_dir(scopes_dir)

        # Candidates: name, name.yaml, name.yml
        candidates = [
            base_dir / f"{clean_name}.yaml",
            base_dir / f"{clean_name}.yml",
            base_dir / clean_name,
        ]

        for cand in candidates:
            if cand.is_file():
                return cls.from_file(cand)

        # Also search inside files if file name differs from scope name
        for entry in base_dir.glob("*.y*ml"):
            if entry.is_file():
                try:
                    with open(entry, "r", encoding="utf-8") as f:
                        d = yaml.safe_load(f)
                    if isinstance(d, dict) and d.get("name") == clean_name:
                        return cls(data=d, file_path=entry)
                except Exception:
                    continue

        raise FileNotFoundError(
            f"Scope '{clean_name}' not found in {base_dir}. Run 'reconcopilot scope list' to view available scopes."
        )

    def to_dict(self) -> dict[str, Any]:
        """Converts scope data to a standard dictionary matching YAML schema."""
        return {
            "name": self.name,
            "targets": {
                "domains": list(self.domains),
                "ip_ranges": list(self.ip_ranges),
                "exclusions": list(self.exclusions),
            },
            "metadata": dict(self.metadata),
        }

    def save(self, scopes_dir: str | Path | None = None) -> Path:
        """Saves scope to YAML file under scopes directory."""
        base_dir = get_scopes_dir(scopes_dir)
        safe_filename = re.sub(r"[^\w\-.]", "_", self.name) + ".yaml"
        target_path = base_dir / safe_filename

        data = self.to_dict()
        with open(target_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False, default_flow_style=False)

        self.file_path = target_path
        return target_path

    def check(self, target: str) -> ScopeCheckResult:
        """Evaluates whether target is in scope, with complete reasoning.

        Exclusions take strict priority over inclusions.
        """
        host = _extract_host(target)
        if not host:
            return ScopeCheckResult(
                in_scope=False,
                reason="OUT OF SCOPE: target is empty or invalid",
                target=target,
                normalized_target="",
            )

        # Case 1: Target is an IP address or network
        try:
            target_ip = ipaddress.ip_address(host)
            return self._check_ip(target_ip, target, host)
        except ValueError:
            pass

        # Check if target is a CIDR network
        try:
            target_net = ipaddress.ip_network(host, strict=False)
            return self._check_ip_network(target_net, target, host)
        except ValueError:
            pass

        # Case 2: Target is a domain name
        return self._check_domain(host, target)

    def _check_ip(
        self,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        raw_target: str,
        normalized: str,
    ) -> ScopeCheckResult:
        # 1. EXCLUSIONS FIRST: Check if IP matches any exclusion
        if ip in self._excluded_ip_addresses:
            return ScopeCheckResult(
                in_scope=False,
                reason=f"OUT OF SCOPE: explicitly excluded (matches exclusion '{ip}')",
                target=raw_target,
                normalized_target=normalized,
                matched_exclusion=str(ip),
            )

        for net in self._excluded_ip_networks:
            if ip in net:
                return ScopeCheckResult(
                    in_scope=False,
                    reason=f"OUT OF SCOPE: explicitly excluded (matches exclusion network '{net}')",
                    target=raw_target,
                    normalized_target=normalized,
                    matched_exclusion=str(net),
                )

        # 2. INCLUSIONS: Check if IP matches allowed ranges
        if ip in self._ip_addresses:
            return ScopeCheckResult(
                in_scope=True,
                reason=f"IN SCOPE: matches IP address {ip}",
                target=raw_target,
                normalized_target=normalized,
                matched_rule=str(ip),
            )

        for net in self._ip_networks:
            if ip in net:
                return ScopeCheckResult(
                    in_scope=True,
                    reason=f"IN SCOPE: matches IP range {net}",
                    target=raw_target,
                    normalized_target=normalized,
                    matched_rule=str(net),
                )

        return ScopeCheckResult(
            in_scope=False,
            reason=f"OUT OF SCOPE: IP '{normalized}' does not match any in-scope IP ranges",
            target=raw_target,
            normalized_target=normalized,
        )

    def _check_ip_network(
        self,
        net: ipaddress.IPv4Network | ipaddress.IPv6Network,
        raw_target: str,
        normalized: str,
    ) -> ScopeCheckResult:
        # Exclusions take priority
        for exc_net in self._excluded_ip_networks:
            if net.subnet_of(exc_net) or net == exc_net:
                return ScopeCheckResult(
                    in_scope=False,
                    reason=f"OUT OF SCOPE: explicitly excluded (matches exclusion network '{exc_net}')",
                    target=raw_target,
                    normalized_target=normalized,
                    matched_exclusion=str(exc_net),
                )

        # Inclusions
        for inc_net in self._ip_networks:
            if net.subnet_of(inc_net) or net == inc_net:
                return ScopeCheckResult(
                    in_scope=True,
                    reason=f"IN SCOPE: matches IP range {inc_net}",
                    target=raw_target,
                    normalized_target=normalized,
                    matched_rule=str(inc_net),
                )

        return ScopeCheckResult(
            in_scope=False,
            reason=f"OUT OF SCOPE: network '{normalized}' does not match any in-scope IP ranges",
            target=raw_target,
            normalized_target=normalized,
        )

    def _check_domain(self, host: str, raw_target: str) -> ScopeCheckResult:
        host_lower = host.lower()

        # 1. EXCLUSIONS FIRST:
        # Exact exclusion match
        if host_lower in self._excluded_exact_domains:
            return ScopeCheckResult(
                in_scope=False,
                reason=f"OUT OF SCOPE: explicitly excluded (matches exclusion '{host_lower}')",
                target=raw_target,
                normalized_target=host_lower,
                matched_exclusion=host_lower,
            )

        # Subdomains of exact domain exclusions (e.g. mail.acme.com excludes smtp.mail.acme.com)
        for exc_exact in self._excluded_exact_domains:
            if host_lower.endswith("." + exc_exact):
                return ScopeCheckResult(
                    in_scope=False,
                    reason=f"OUT OF SCOPE: explicitly excluded (subdomain of exclusion '{exc_exact}')",
                    target=raw_target,
                    normalized_target=host_lower,
                    matched_exclusion=exc_exact,
                )

        # Wildcard exclusion match
        for exc_suffix in self._excluded_wildcard_domains:
            if host_lower == exc_suffix or host_lower.endswith("." + exc_suffix):
                return ScopeCheckResult(
                    in_scope=False,
                    reason=f"OUT OF SCOPE: explicitly excluded (matches exclusion '*.{exc_suffix}')",
                    target=raw_target,
                    normalized_target=host_lower,
                    matched_exclusion=f"*.{exc_suffix}",
                )

        # 2. INCLUSIONS:
        # Exact domain match
        if host_lower in self._exact_domains:
            return ScopeCheckResult(
                in_scope=True,
                reason=f"IN SCOPE: matches exact domain '{host_lower}'",
                target=raw_target,
                normalized_target=host_lower,
                matched_rule=host_lower,
            )

        # Wildcard domain match (*.acme.com matches acme.com and sub.acme.com)
        for suffix in self._wildcard_domains:
            if host_lower == suffix or host_lower.endswith("." + suffix):
                return ScopeCheckResult(
                    in_scope=True,
                    reason=f"IN SCOPE: matches wildcard *.{suffix}",
                    target=raw_target,
                    normalized_target=host_lower,
                    matched_rule=f"*.{suffix}",
                )

        return ScopeCheckResult(
            in_scope=False,
            reason=f"OUT OF SCOPE: target '{host_lower}' does not match any in-scope domains or IP ranges",
            target=raw_target,
            normalized_target=host_lower,
        )

    def is_in_scope(self, target: str) -> bool:
        """Returns True if target is authorized within this scope."""
        return self.check(target).in_scope

    def enforce(self, target: str) -> str:
        """Validates target against scope, raising ScopeViolationError if unauthorized."""
        result = self.check(target)
        if not result.in_scope:
            raise ScopeViolationError(
                f"Scope violation for '{self.name}': {result.reason}"
            )
        return result.normalized_target


def list_scopes(scopes_dir: str | Path | None = None) -> list[ScopeChecker]:
    """Lists all scopes discovered in the scopes directory."""
    base_dir = get_scopes_dir(scopes_dir)
    found_scopes: dict[str, ScopeChecker] = {}

    for entry in sorted(base_dir.glob("*.y*ml")):
        if entry.is_file():
            try:
                sc = ScopeChecker.from_file(entry)
                found_scopes[sc.name] = sc
            except Exception:
                continue

    return list(found_scopes.values())


def resolve_active_scope(
    scope_hint: str | ScopeChecker | Path | None = None,
) -> ScopeChecker | None:
    """Resolves active scope from parameter, environment, or default discovery."""
    if isinstance(scope_hint, ScopeChecker):
        return scope_hint

    if isinstance(scope_hint, Path):
        return ScopeChecker.from_file(scope_hint)

    if isinstance(scope_hint, str) and scope_hint.strip():
        hint = scope_hint.strip()
        # If it looks like a path
        if (
            "/" in hint
            or "\\" in hint
            or hint.endswith(".yaml")
            or hint.endswith(".yml")
        ):
            p = Path(hint).expanduser().resolve()
            if p.is_file():
                return ScopeChecker.from_file(p)
        # Otherwise search by scope name
        try:
            return ScopeChecker.from_name(hint)
        except FileNotFoundError:
            raise

    # Check env var
    env_scope = os.getenv("RECONCOPILOT_SCOPE")
    if env_scope:
        return ScopeChecker.from_name(env_scope)

    # Check configuration
    cfg = load_config()
    active_name = cfg.get("scope", {}).get("active_scope") or cfg.get("scope", {}).get(
        "name"
    )
    if active_name:
        try:
            return ScopeChecker.from_name(active_name)
        except FileNotFoundError:
            pass

    # If scopes exist in ~/.config/reconcopilot/scopes/
    all_scopes = list_scopes()
    if len(all_scopes) == 1:
        return all_scopes[0]

    # Look for a scope named "default"
    for s in all_scopes:
        if s.name == "default":
            return s

    # Fallback to legacy allowlist_file if configured
    allowlist_file = cfg.scope.allowlist_file
    if allowlist_file and Path(allowlist_file).is_file():
        p = Path(allowlist_file)
        if p.suffix in (".yaml", ".yml"):
            return ScopeChecker.from_file(p)
        # Parse text lines as domain/IP inclusions
        with open(p, "r", encoding="utf-8") as f:
            lines = [
                ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")
            ]
        return ScopeChecker(
            data={
                "name": "legacy_file",
                "targets": {"domains": lines, "ip_ranges": [], "exclusions": []},
            }
        )

    return None


def require_in_scope(
    target_or_func: Any = None,
    *,
    scope: str | ScopeChecker | Path | None = None,
    target_param: str = "target",
    scope_param: str = "scope",
) -> Any:
    """Enforces scope authorization. Can be used as a helper function or as a decorator.

    1. As a helper function:
        normalized_target = require_in_scope("api.acme.com", scope="acme-corp")

    2. As a decorator:
        @require_in_scope
        def run_recon(target: str, ...):
            ...

        @require_in_scope(scope="acme-corp")
        def run_recon(target: str, ...):
            ...
    """

    def _validate_target(
        raw_target: str, scope_val: str | ScopeChecker | Path | None
    ) -> str:
        cfg = load_config()
        active = resolve_active_scope(scope_val)

        if active is not None:
            return active.enforce(raw_target)

        # No active scope found
        if cfg.scope.strict_mode:
            raise ScopeViolationError(
                f"Scope violation: target '{raw_target}' rejected because no authorized scope is configured "
                "and strict mode is enabled. Use 'reconcopilot scope create' or pass an active scope."
            )
        return _extract_host(raw_target)

    # Usage as helper function: require_in_scope("target.com", scope="...")
    if isinstance(target_or_func, str):
        return _validate_target(target_or_func, scope)

    # Usage as decorator with arguments: @require_in_scope(scope="...")
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()

            # Extract target
            target_val = bound.arguments.get(target_param)
            if target_val is None and len(args) > 0 and isinstance(args[0], str):
                target_val = args[0]

            # Extract scope
            scope_val = scope or bound.arguments.get(scope_param)

            if target_val:
                normalized = _validate_target(str(target_val), scope_val)
                # If target was in bound args, update with normalized
                if target_param in bound.arguments:
                    bound.arguments[target_param] = normalized

            return fn(*bound.args, **bound.kwargs)

        return wrapper

    # Usage as bare decorator: @require_in_scope
    if callable(target_or_func):
        return decorator(target_or_func)

    return decorator


# Backwards compatibility alias for Phase 1
class ScopeAllowlist(ScopeChecker):
    """Backwards compatibility wrapper for ScopeChecker."""

    def __init__(self, rules: Iterable[str] | None = None) -> None:
        domains: list[str] = []
        ip_ranges: list[str] = []
        if rules:
            for r in rules:
                clean = r.strip()
                if not clean or clean.startswith("#"):
                    continue
                if "/" in clean or clean.replace(".", "").isdigit():
                    ip_ranges.append(clean)
                else:
                    domains.append(clean)
        super().__init__(
            data={
                "name": "allowlist",
                "targets": {
                    "domains": domains,
                    "ip_ranges": ip_ranges,
                    "exclusions": [],
                },
            }
        )

    def add_rule(self, rule: str) -> None:
        clean = rule.strip()
        if not clean or clean.startswith("#"):
            return
        if "/" in clean or clean.replace(".", "").isdigit():
            self._add_ip_rule(clean)
            self.ip_ranges.append(clean)
        else:
            self._add_domain_rule(clean)
            self.domains.append(clean)


def enforce_scope(
    target: str,
    scope: ScopeAllowlist | ScopeChecker | None = None,
    strict: bool | None = None,
) -> str:
    """Backwards compatible enforcement helper."""
    if strict is False:
        return _extract_host(target)
    return require_in_scope(target, scope=scope)
