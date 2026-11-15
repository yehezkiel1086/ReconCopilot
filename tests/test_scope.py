"""Tests for scope allowlist loading and enforcement."""

import pytest

from reconcopilot.scope import ScopeAllowlist, ScopeViolationError, enforce_scope


def test_empty_scope_blocks_all() -> None:
    scope = ScopeAllowlist()
    assert not scope.is_in_scope("example.com")
    assert not scope.is_in_scope("192.168.1.1")
    with pytest.raises(ScopeViolationError):
        scope.enforce("example.com")


def test_exact_domain_match() -> None:
    scope = ScopeAllowlist(["example.com", "target.org"])
    assert scope.is_in_scope("example.com")
    assert scope.is_in_scope("target.org")
    assert not scope.is_in_scope("sub.example.com")
    assert not scope.is_in_scope("other.org")


def test_wildcard_domain_match() -> None:
    scope = ScopeAllowlist(["*.example.com", "*.internal.net"])
    assert scope.is_in_scope("example.com")
    assert scope.is_in_scope("sub.example.com")
    assert scope.is_in_scope("deep.sub.example.com")
    assert scope.is_in_scope("internal.net")
    assert scope.is_in_scope("app.internal.net")
    assert not scope.is_in_scope("example.net")
    assert not scope.is_in_scope("notexample.com")


def test_ip_and_cidr_matching() -> None:
    scope = ScopeAllowlist(
        [
            "10.0.0.0/8",
            "192.168.1.100",
            "2001:db8::/32",
        ]
    )
    assert scope.is_in_scope("10.1.2.3")
    assert scope.is_in_scope("10.254.254.254")
    assert scope.is_in_scope("192.168.1.100")
    assert not scope.is_in_scope("192.168.1.101")
    assert not scope.is_in_scope("172.16.0.1")
    assert scope.is_in_scope("2001:db8::1")
    assert not scope.is_in_scope("2001:db9::1")


def test_url_and_port_stripping() -> None:
    scope = ScopeAllowlist(["*.example.com", "192.168.1.50"])
    assert scope.is_in_scope("https://api.example.com:8443/v1/auth")
    assert scope.is_in_scope("http://192.168.1.50:8080/dashboard")
    assert not scope.is_in_scope("https://evil.com/fake?redir=api.example.com")


def test_scope_from_file_with_comments(tmp_path) -> None:
    rules_file = tmp_path / "scope.txt"
    rules_file.write_text(
        "# Authorized targets for penetration test\n"
        "\n"
        "*.company.corp # Primary domain\n"
        "192.168.10.0/24\n"
        "10.50.1.1\n"
        "  # Ignored comment\n"
    )

    scope = ScopeAllowlist.from_file(rules_file)
    assert scope.is_in_scope("api.company.corp")
    assert scope.is_in_scope("192.168.10.42")
    assert scope.is_in_scope("10.50.1.1")
    assert not scope.is_in_scope("10.50.1.2")
    assert not scope.is_in_scope("company.com")


def test_enforce_scope_success_and_failure() -> None:
    scope = ScopeAllowlist(["allowed.org"])
    normalized = enforce_scope("https://allowed.org/login", scope=scope, strict=True)
    assert normalized == "allowed.org"

    with pytest.raises(ScopeViolationError):
        enforce_scope("forbidden.org", scope=scope, strict=True)

    # When strict=False, non-allowlisted targets pass through
    assert enforce_scope("forbidden.org", scope=scope, strict=False) == "forbidden.org"
