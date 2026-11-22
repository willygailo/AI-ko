"""ScopePolicy allowlist, exclusions, DNS boundary, and injection prevention tests."""
from __future__ import annotations

import pytest

from app.core.scope import ScopePolicy, ScopeViolationError


def test_allows_exact_and_wildcard_domains():
    policy = ScopePolicy(allowed_domains=["example.com", "*.staging.example.org"])
    assert policy.validate_target("https://example.com/api/v1/users", resolve_dns=False)
    assert policy.validate_target("https://api.staging.example.org/health", resolve_dns=False)
    assert policy.validate_target("staging.example.org", resolve_dns=False)


def test_blocks_out_of_scope_targets_and_subdomains():
    policy = ScopePolicy(allowed_domains=["app.example.com"])
    with pytest.raises(ScopeViolationError):
        policy.validate_target("https://evil.com/", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        policy.validate_target("https://other.example.com/", resolve_dns=False)


def test_default_deny_when_empty_allowlist():
    policy = ScopePolicy()
    with pytest.raises(ScopeViolationError):
        policy.validate_target("https://example.com", resolve_dns=False)


def test_enforces_excluded_hosts_and_paths():
    policy = ScopePolicy(
        allowed_domains=["*.example.com"],
        excluded_hosts=["prod-db.example.com"],
        excluded_paths=["/logout", "/admin/billing/*"],
    )
    assert policy.validate_target("https://app.example.com/login", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        policy.validate_target("https://prod-db.example.com/", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        policy.validate_target("https://app.example.com/logout", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        policy.validate_target("https://app.example.com/admin/billing/refund", resolve_dns=False)


def test_blocks_private_and_metadata_ips_unless_allowed():
    policy = ScopePolicy(allowed_domains=["rebind.example.com"], allow_private_ips=False)
    with pytest.raises(ScopeViolationError):
        policy.validate_target(
            "https://rebind.example.com/",
            resolve_dns=True,
            dns_resolver=lambda _h: ["169.254.169.254"],
        )
    with pytest.raises(ScopeViolationError):
        policy.validate_target(
            "https://rebind.example.com/",
            resolve_dns=True,
            dns_resolver=lambda _h: ["127.0.0.1"],
        )

    lab_policy = ScopePolicy(allowed_urls=["http://127.0.0.1:3000"], allow_private_ips=True)
    assert lab_policy.validate_target("http://127.0.0.1:3000/rest/products/search?q=test")
    with pytest.raises(ScopeViolationError):
        lab_policy.validate_target("http://127.0.0.1:8080/admin")


def test_blocks_shell_metacharacters_and_non_http_schemes():
    policy = ScopePolicy(allowed_domains=["example.com"])
    with pytest.raises(ScopeViolationError):
        policy.validate_target("https://example.com/;cat /etc/passwd", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        policy.validate_target("file:///etc/passwd", resolve_dns=False)
