"""Target normalization and CTF / HTB lab detection helpers (URL, Domain, IP, Port, CIDR)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

LAB_HOST_SUFFIXES: tuple[str, ...] = (
    ".htb",
    ".thm",
    ".local",
    ".internal",
    ".lan",
    ".ctf",
    ".localhost",
)
COMMON_PLAIN_HTTP_PORTS: frozenset[int] = frozenset({80, 3000, 4000, 5000, 7000, 8000, 8008, 8080, 8888, 9000, 9090})
COMMON_HTTPS_PORTS: frozenset[int] = frozenset({443, 8443})
_SPLIT_TARGETS_RE = re.compile(r"[\s,;]+")


@dataclass
class ParsedTargets:
    """Normalized scope lists extracted from mixed URL, domain, IP, IP:port, and CIDR inputs."""

    allowed_urls: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    detected_private_or_lab: bool = False


def is_ip_literal(host: str) -> bool:
    """Return True if *host* parses as an IPv4 or IPv6 address."""
    clean = (host or "").strip().strip("[]")
    if not clean:
        return False
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def is_private_or_lab_ip(ip_str: str) -> bool:
    """Return True for private/loopback/CGNAT lab IPs, excluding cloud metadata ranges."""
    clean = (ip_str or "").strip().strip("[]")
    try:
        ip_obj = ipaddress.ip_address(clean)
    except ValueError:
        return False
    if ip_obj.is_link_local or clean == "100.100.100.200":
        return False
    return bool(ip_obj.is_private or ip_obj.is_loopback)


def is_lab_or_ctf_host(host: str) -> bool:
    """Return True when *host* looks like a CTF, HTB, THM, localhost, or private lab target."""
    clean = (host or "").strip().strip("[]").rstrip(".").lower()
    if not clean:
        return False
    if clean == "localhost" or any(clean.endswith(sfx) for sfx in LAB_HOST_SUFFIXES):
        return True
    return is_private_or_lab_ip(clean)


def preferred_scheme_for_host(host: str, port: int | None = None) -> str:
    """Choose the best initial HTTP scheme for a host/IP and optional port."""
    if port in COMMON_HTTPS_PORTS:
        return "https"
    if port in COMMON_PLAIN_HTTP_PORTS:
        return "http"
    if is_ip_literal(host) or is_lab_or_ctf_host(host):
        return "http"
    return "https"


def _append_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def _split_host_and_port(token: str) -> tuple[str, int | None]:
    """Split ``host``, ``host:port``, or ``[ipv6]:port`` without mis-parsing bare IPv6."""
    clean = token.strip()
    if clean.startswith("["):
        end_idx = clean.find("]")
        if end_idx != -1:
            host_part = clean[1:end_idx]
            rest = clean[end_idx + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                return host_part, int(rest[1:])
            return host_part, None
    if is_ip_literal(clean):
        return clean, None
    if ":" in clean:
        host_part, port_part = clean.rsplit(":", 1)
        if port_part.isdigit():
            port_num = int(port_part)
            if 1 <= port_num <= 65535:
                return host_part.strip("[]"), port_num
    return clean.strip("[]"), None


def parse_target_inputs(raw_targets: list[str] | str) -> ParsedTargets:
    """Classify mixed URL, domain, IP, IP:port, and CIDR inputs into normalized scope lists."""
    tokens: list[str] = []
    raw_items = [raw_targets] if isinstance(raw_targets, str) else list(raw_targets)
    for item in raw_items:
        for tok in _SPLIT_TARGETS_RE.split((item or "").strip()):
            cleaned = tok.strip()
            if cleaned:
                tokens.append(cleaned)

    out = ParsedTargets()
    for token in tokens:
        # 1. CIDR block (e.g. 10.10.11.0/29 or 10.10.11.42/32)
        if "/" in token and "://" not in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
                _append_unique(out.allowed_cidrs, str(net))
                if is_private_or_lab_ip(str(net.network_address)):
                    out.detected_private_or_lab = True
                continue
            except ValueError:
                pass

        # 2. Full URL with explicit scheme
        if "://" in token:
            parsed = urlparse(token)
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            _append_unique(out.allowed_urls, token)
            if is_ip_literal(host):
                net = ipaddress.ip_network(f"{host}/{128 if ':' in host else 32}", strict=False)
                _append_unique(out.allowed_cidrs, str(net))
            else:
                _append_unique(out.allowed_domains, host)
            if is_lab_or_ctf_host(host):
                out.detected_private_or_lab = True
            continue

        # 3. Bare host, host:port, IP, or IP:port (optionally with trailing path like 10.10.11.42/api)
        host_port_part, path_part = (token.split("/", 1)[0], "/" + token.split("/", 1)[1]) if "/" in token else (token, "")
        host, port = _split_host_and_port(host_port_part)
        host_l = host.lower()
        if not host_l:
            continue

        clean_no_wild = host_l.lstrip("*.")
        if is_ip_literal(clean_no_wild):
            net = ipaddress.ip_network(f"{clean_no_wild}/{128 if ':' in clean_no_wild else 32}", strict=False)
            _append_unique(out.allowed_cidrs, str(net))
            scheme = preferred_scheme_for_host(clean_no_wild, port)
            netloc = f"[{clean_no_wild}]" if ":" in clean_no_wild else clean_no_wild
            port_suffix = f":{port}" if port is not None else ""
            _append_unique(out.allowed_urls, f"{scheme}://{netloc}{port_suffix}{path_part}")
            if is_private_or_lab_ip(clean_no_wild):
                out.detected_private_or_lab = True
        else:
            _append_unique(out.allowed_domains, host_l)
            if not host_l.startswith("*.") and (port is not None or path_part):
                scheme = preferred_scheme_for_host(clean_no_wild, port)
                port_suffix = f":{port}" if port is not None else ""
                _append_unique(out.allowed_urls, f"{scheme}://{clean_no_wild}{port_suffix}{path_part}")
            if is_lab_or_ctf_host(clean_no_wild):
                out.detected_private_or_lab = True

    return out
