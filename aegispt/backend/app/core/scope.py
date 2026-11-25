"""Non-bypassable ScopePolicy engine enforcing allowlist-only target boundaries."""
from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import posixpath
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import unquote, urlparse

from app.core.vault import decrypt_dict


class ScopeViolationError(ValueError):
    """Raised whenever a proposed target or parameter violates the engagement scope."""


# Cloud metadata / link-local sensitive endpoints blocked unless explicitly allowlisted by IP
BLOCKED_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}
BLOCKED_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
}

UNSAFE_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SHELL_INJECTION_RE = re.compile(r"[;&|`$<>\\]")


@dataclass
class ScopePolicy:
    allowed_domains: list[str] = field(default_factory=list)
    allowed_urls: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    excluded_hosts: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    max_rps: int = 15
    max_concurrency: int = 5
    custom_headers: dict[str, str] = field(default_factory=dict)
    auth_cookies: dict[str, str] = field(default_factory=dict)
    secondary_headers: dict[str, str] = field(default_factory=dict)
    secondary_cookies: dict[str, str] = field(default_factory=dict)
    allow_private_ips: bool = False

    def __post_init__(self) -> None:
        self.allowed_domains = [d.strip().lower().rstrip(".") for d in self.allowed_domains if d.strip()]
        self.allowed_urls = [u.strip() for u in self.allowed_urls if u.strip()]
        self.allowed_cidrs = [c.strip() for c in self.allowed_cidrs if c.strip()]
        self.excluded_hosts = [h.strip().lower().rstrip(".") for h in self.excluded_hosts if h.strip()]
        self.excluded_paths = [p.strip() for p in self.excluded_paths if p.strip()]
        self.max_rps = max(1, min(int(self.max_rps), 100))
        self.max_concurrency = max(1, min(int(self.max_concurrency), 30))

        # Validate header and cookie keys/values against CRLF / control-char injection
        for header_map in (self.custom_headers, self.secondary_headers):
            for k, v in header_map.items():
                if UNSAFE_CONTROL_RE.search(k) or UNSAFE_CONTROL_RE.search(str(v)):
                    raise ScopeViolationError(f"Header contains control characters: {k!r}")
        for cookie_map in (self.auth_cookies, self.secondary_cookies):
            for k, v in cookie_map.items():
                if UNSAFE_CONTROL_RE.search(k) or UNSAFE_CONTROL_RE.search(str(v)):
                    raise ScopeViolationError(f"Cookie contains control characters: {k!r}")

    @property
    def has_secondary_auth(self) -> bool:
        return bool(self.secondary_headers or self.secondary_cookies)

    @staticmethod
    def build_cookie_header(cookies: dict[str, str]) -> str:
        return "; ".join(f"{k}={v}" for k, v in cookies.items() if k)

    @classmethod
    def from_orm(cls, model) -> "ScopePolicy":
        return cls(
            allowed_domains=list(model.allowed_domains or []),
            allowed_urls=list(model.allowed_urls or []),
            allowed_cidrs=list(model.allowed_cidrs or []),
            excluded_hosts=list(model.excluded_hosts or []),
            excluded_paths=list(model.excluded_paths or []),
            max_rps=model.max_rps,
            max_concurrency=model.max_concurrency,
            custom_headers=decrypt_dict(model.custom_headers),
            auth_cookies=decrypt_dict(model.auth_cookies),
            secondary_headers=decrypt_dict(getattr(model, "secondary_headers", None)),
            secondary_cookies=decrypt_dict(getattr(model, "secondary_cookies", None)),
            allow_private_ips=bool(model.allow_private_ips),
        )

    def _has_any_allowlist(self) -> bool:
        return bool(self.allowed_domains or self.allowed_urls or self.allowed_cidrs)

    def _parse_ip(self, host: str):
        try:
            return ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return None

    def _ip_in_allowed_cidrs(self, ip_obj) -> bool:
        for cidr in self.allowed_cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if ip_obj in net:
                    return True
            except ValueError:
                continue
        return False

    def _host_matches_pattern(self, host: str, pattern: str) -> bool:
        host = host.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            base = pattern[2:]
            return host == base or host.endswith("." + base)
        return host == pattern

    def _is_host_excluded(self, host: str) -> bool:
        for pat in self.excluded_hosts:
            if self._host_matches_pattern(host, pat):
                return True
        return False

    @staticmethod
    def _unquote_path(path: str) -> str:
        decoded = path or "/"
        for _ in range(3):
            nxt = unquote(decoded)
            if nxt == decoded:
                break
            decoded = nxt
        return decoded.replace("\\", "/")

    def _normalize_path(self, path: str, *, decode: bool = True) -> str:
        raw = self._unquote_path(path) if decode else (path or "/")
        if not raw.startswith("/"):
            raw = "/" + raw
        norm = posixpath.normpath(raw)
        if not norm.startswith("/"):
            norm = "/"
        if raw.endswith("/") and norm != "/":
            norm = norm + "/"
        return norm

    def _is_path_excluded(self, path: str) -> bool:
        candidates = {
            self._normalize_path(path, decode=False),
            self._normalize_path(path, decode=True),
        }
        for norm_path in candidates:
            for pat in self.excluded_paths:
                if not pat:
                    continue
                if "*" in pat or "?" in pat:
                    if fnmatch.fnmatch(norm_path, pat):
                        return True
                else:
                    norm_pat = self._normalize_path(pat, decode=True).rstrip("/")
                    if norm_path.rstrip("/") == norm_pat or norm_path.startswith(norm_pat + "/"):
                        return True
        return False

    @staticmethod
    def _effective_port(scheme: str, port: int | None) -> int:
        if port is not None:
            return port
        return 443 if scheme.lower() == "https" else 80

    def _check_ip_safety(self, ip_obj, explicitly_allowlisted: bool) -> None:
        if ip_obj in BLOCKED_METADATA_IPS and not explicitly_allowlisted:
            raise ScopeViolationError(
                f"Target IP {ip_obj} is a protected metadata address and not explicitly allowlisted."
            )
        is_private_like = (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
        )
        if is_private_like and not (self.allow_private_ips or explicitly_allowlisted):
            raise ScopeViolationError(
                f"Target resolves to private/loopback IP {ip_obj}, which is disabled in scope policy."
            )

    def _validate_target_pre_dns(self, target: str) -> tuple[str, str, Any]:
        if not target or not isinstance(target, str):
            raise ScopeViolationError("Empty target is not allowed.")

        target = target.strip()
        if UNSAFE_CONTROL_RE.search(target):
            raise ScopeViolationError("Target contains disallowed control characters.")
        if SHELL_INJECTION_RE.search(target):
            raise ScopeViolationError(f"Target contains disallowed characters: {target!r}")

        if not self._has_any_allowlist():
            raise ScopeViolationError("Scope policy has no allowlisted targets (default-deny).")

        # Parse as URL or bare host/IP
        has_scheme = "://" in target
        if has_scheme:
            parsed = urlparse(target)
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                raise ScopeViolationError(f"Disallowed URL scheme: {parsed.scheme!r}")
            host = (parsed.hostname or "").lower().rstrip(".")
            path = parsed.path or "/"
            port = parsed.port
        else:
            parsed = urlparse(f"https://{target}")
            scheme = "https"
            host = (parsed.hostname or "").lower().rstrip(".")
            path = parsed.path if "/" in target else "/"
            port = parsed.port

        if not host:
            raise ScopeViolationError(f"Could not extract hostname from target: {target!r}")

        if host in BLOCKED_METADATA_HOSTS:
            raise ScopeViolationError(f"Host {host!r} is a blocked metadata hostname.")

        if self._is_host_excluded(host):
            raise ScopeViolationError(f"Host {host!r} is explicitly excluded by scope policy.")

        if self._is_path_excluded(path):
            raise ScopeViolationError(f"Path {path!r} is explicitly excluded by scope policy.")

        # Check allowlist membership
        ip_obj = self._parse_ip(host)
        explicitly_ip_allowed = False
        allowed = False

        if ip_obj is not None:
            if self._ip_in_allowed_cidrs(ip_obj):
                allowed = True
                explicitly_ip_allowed = True

        # Check allowed_domains
        if not allowed:
            for dom in self.allowed_domains:
                if self._host_matches_pattern(host, dom):
                    allowed = True
                    if ip_obj is not None:
                        explicitly_ip_allowed = True
                    break

        norm_req_path = self._normalize_path(path, decode=True)
        norm_raw_path = self._normalize_path(path, decode=False)

        # Check allowed_urls
        if not allowed:
            for raw_url in self.allowed_urls:
                up = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
                u_host = (up.hostname or "").lower().rstrip(".")
                u_scheme = (up.scheme or "https").lower()
                u_eff_port = self._effective_port(u_scheme, up.port)
                u_path = self._normalize_path(up.path or "/", decode=True).rstrip("/")
                if host == u_host:
                    if has_scheme:
                        t_eff_port = self._effective_port(scheme, port)
                        if u_eff_port != t_eff_port:
                            continue
                    elif port is not None:
                        if u_eff_port != port:
                            continue
                    elif "/" in target or ip_obj is not None:
                        if u_eff_port not in (80, 443):
                            continue
                    path_ok = (
                        not u_path
                        or (
                            (norm_req_path.rstrip("/") == u_path or norm_req_path.startswith(u_path + "/"))
                            and (norm_raw_path.rstrip("/") == u_path or norm_raw_path.startswith(u_path + "/"))
                        )
                    )
                    if path_ok:
                        allowed = True
                        if ip_obj is not None:
                            explicitly_ip_allowed = True
                        break

        if not allowed:
            raise ScopeViolationError(
                f"Target {target!r} (host={host!r}) is outside the engagement allowlist."
            )

        # Direct IP safety check
        if ip_obj is not None:
            self._check_ip_safety(ip_obj, explicitly_ip_allowed)

        return target, host, ip_obj

    def _validate_resolved_ips(self, ips: list[str]) -> None:
        for ip_str in ips:
            resolved_ip = self._parse_ip(ip_str)
            if resolved_ip is not None:
                self._check_ip_safety(
                    resolved_ip,
                    explicitly_allowlisted=self._ip_in_allowed_cidrs(resolved_ip),
                )

    def validate_target(
        self,
        target: str,
        *,
        resolve_dns: bool = True,
        dns_resolver: Callable[[str], list[str]] | None = None,
    ) -> str:
        """Validate a URL, hostname, or IP against the allowlist, exclusions, and DNS boundary.

        Returns the normalized target string if allowed, otherwise raises ScopeViolationError.
        """
        norm_target, host, ip_obj = self._validate_target_pre_dns(target)
        if ip_obj is not None or not resolve_dns:
            return norm_target

        # DNS resolution boundary check (prevents DNS rebinding / accidental pivot to metadata/internal IPs)
        ips: list[str] = []
        if dns_resolver is not None:
            ips = dns_resolver(host)
        else:
            try:
                infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                ips = sorted({str(info[4][0]) for info in infos if isinstance(info[4][0], str)})
            except socket.gaierror:
                # Unresolvable host (e.g. offline/DNS-only recon or synthetic domain); allowlisted domain still passes
                ips = []

        self._validate_resolved_ips(ips)
        return norm_target

    async def validate_target_async(
        self,
        target: str,
        *,
        resolve_dns: bool = True,
        dns_resolver: Callable[[str], list[str]] | None = None,
    ) -> str:
        """Async version of validate_target that performs non-blocking DNS resolution."""
        norm_target, host, ip_obj = self._validate_target_pre_dns(target)
        if ip_obj is not None or not resolve_dns:
            return norm_target

        ips: list[str] = []
        if dns_resolver is not None:
            ips = await asyncio.to_thread(dns_resolver, host)
        else:
            loop = asyncio.get_running_loop()
            try:
                infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                ips = sorted({str(info[4][0]) for info in infos if isinstance(info[4][0], str)})
            except socket.gaierror:
                ips = []

        self._validate_resolved_ips(ips)
        return norm_target

    def primary_seed_urls(self) -> list[str]:
        from app.core.targets import is_ip_literal, preferred_scheme_for_host

        seeds: list[str] = []
        for u in self.allowed_urls:
            if "://" in u:
                seed = u
            else:
                host_part = u.split("/", 1)[0].rsplit(":", 1)[0]
                scheme = preferred_scheme_for_host(host_part)
                seed = f"{scheme}://{u}"
            if seed not in seeds:
                seeds.append(seed)
        for d in self.allowed_domains:
            clean = d.lstrip("*.")
            scheme = preferred_scheme_for_host(clean)
            netloc = f"[{clean}]" if ":" in clean and is_ip_literal(clean) else clean
            url = f"{scheme}://{netloc}"
            if url not in seeds:
                seeds.append(url)
        for c in self.allowed_cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
                if net.num_addresses == 1:
                    addr = str(net.network_address)
                    netloc = f"[{addr}]" if ":" in addr else addr
                    url = f"http://{netloc}"
                    if url not in seeds:
                        seeds.append(url)
                elif net.num_addresses <= 16:
                    for host_ip in list(net.hosts())[:16]:
                        addr = str(host_ip)
                        netloc = f"[{addr}]" if ":" in addr else addr
                        url = f"http://{netloc}"
                        if url not in seeds:
                            seeds.append(url)
            except ValueError:
                pass
        return seeds

    def primary_domains(self) -> list[str]:
        domains: list[str] = []
        for d in self.allowed_domains:
            clean = d.lstrip("*.")
            if self._parse_ip(clean) is None and clean != "localhost" and clean not in domains:
                domains.append(clean)
        for u in self.allowed_urls:
            host = (urlparse(u if "://" in u else f"https://{u}").hostname or "").lower()
            if host and self._parse_ip(host) is None and host != "localhost" and host not in domains:
                domains.append(host)
        return domains
