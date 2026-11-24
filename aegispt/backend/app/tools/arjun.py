"""Arjun HTTP parameter discovery adapter (Tier 2)."""
from __future__ import annotations

import html
import json
import os
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy, ScopeViolationError
from app.tools.base import (
    BaseToolAdapter,
    DiscoveredEndpoint,
    ToolResult,
    resolve_binary,
)


def _cdata_safe(value: str) -> str:
    return value.replace("]]>", "]]]]><![CDATA[>")


def _write_arjun_request_file(work_dir: Path, target: str, method: str, scope: ScopePolicy) -> Path:
    """Write a 0o600 Burp-XML request file carrying multi-header/cookie auth for Arjun `-i`."""
    parsed = urlparse(target)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    host_header = parsed.netloc or host
    req_path = parsed.path or "/"
    if parsed.query:
        req_path = f"{req_path}?{parsed.query}"

    header_lines = [f"Host: {host_header}"]
    for k, v in scope.custom_headers.items():
        if k.lower() == "host":
            continue
        header_lines.append(f"{k}: {v}")
    if scope.auth_cookies and not any(k.lower() == "cookie" for k in scope.custom_headers):
        header_lines.append(f"Cookie: {scope.build_cookie_header(scope.auth_cookies)}")

    http_method = "POST" if method in {"JSON", "XML"} else method
    raw_req = f"{http_method} {req_path} HTTP/1.1\n" + "\n".join(header_lines) + "\n\n"

    xml_doc = (
        '<?xml version="1.0"?>\n'
        "<items>\n"
        "  <item>\n"
        f"    <url><![CDATA[{_cdata_safe(target)}]]></url>\n"
        f'    <host ip="">{html.escape(host)}</host>\n'
        f"    <port>{port}</port>\n"
        f"    <protocol>{html.escape(scheme)}</protocol>\n"
        f"    <method><![CDATA[{_cdata_safe(method)}]]></method>\n"
        f"    <path>{html.escape(req_path)}</path>\n"
        "    <extension></extension>\n"
        f'    <request base64="false"><![CDATA[{_cdata_safe(raw_req)}]]></request>\n'
        "    <status>200</status>\n"
        "    <responselength>0</responselength>\n"
        "    <mimetype>JSON</mimetype>\n"
        "  </item>\n"
        "</items>\n"
    )

    req_file = work_dir / ".arjun_request.xml"
    fd = os.open(req_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.chmod(req_file, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(xml_doc)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return req_file


class ArjunArgs(BaseModel):
    method: Literal["GET", "POST", "JSON", "XML"] = "GET"
    timeout_seconds: int = Field(default=120, ge=15, le=240)


class ArjunAdapter(BaseToolAdapter):
    name = "arjun"
    description = "Discovers hidden HTTP query, form, and JSON parameters using arjun."
    tier = 2
    binary_name = "arjun"
    args_schema = ArjunArgs

    @staticmethod
    def _request_file_path(work_dir: Path) -> Path:
        return work_dir / ".arjun_request.xml"

    async def pre_execute(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        target: str,
        args: BaseModel,
        scope: ScopePolicy,
        work_dir: Path,
    ) -> dict[str, Any]:
        assert isinstance(args, ArjunArgs)
        if scope.custom_headers or scope.auth_cookies:
            req_file = _write_arjun_request_file(work_dir, target, args.method, scope)
            return {"request_file": str(req_file)}
        return {}

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, ArjunArgs)
        bin_path = resolve_binary("arjun") or "arjun"
        out_file = work_dir / "arjun.json"
        argv = [bin_path]
        if scope.custom_headers or scope.auth_cookies:
            req_file = self._request_file_path(work_dir)
            argv.extend(["-i", str(req_file)])
        else:
            argv.extend(["-u", target])
        argv.extend(
            [
                "-m",
                args.method,
                "-oJ",
                str(out_file),
                "-t",
                str(min(scope.max_concurrency, 5)),
                "--rate-limit",
                str(scope.max_rps),
                "-q",
            ]
        )
        return argv

    async def post_execute(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        target: str,
        args: BaseModel,
        scope: ScopePolicy,
        work_dir: Path,
        context: dict[str, Any],
        result: ToolResult | None,
    ) -> None:
        req_file = self._request_file_path(work_dir)
        try:
            req_file.unlink(missing_ok=True)
        except OSError:
            pass

    def parse_output(
        self,
        *,
        target: str,
        args: BaseModel,
        stdout: str,
        stderr: str,
        work_dir: Path,
        scope: ScopePolicy | None = None,
    ) -> ToolResult:
        out_file = work_dir / "arjun.json"
        endpoints: list[DiscoveredEndpoint] = []
        param_summary: dict[str, list[str]] = {}
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict):
                    for url, info in data.items():
                        if scope is not None:
                            try:
                                scope.validate_target(url, resolve_dns=False)
                            except ScopeViolationError:
                                continue
                        params: list[str] = []
                        method = getattr(args, "method", "GET")
                        if isinstance(info, dict):
                            params = [str(p) for p in (info.get("params") or [])]
                            method = str(info.get("method") or method).upper()
                        elif isinstance(info, list):
                            params = [str(p) for p in info]
                        param_summary[url] = params
                        p = urlparse(url)
                        endpoints.append(
                            DiscoveredEndpoint(
                                method="POST" if method == "JSON" else method,
                                url=url,
                                path=p.path or "/",
                                query_params=params if method == "GET" else [],
                                body_params=params if method != "GET" else [],
                                source=self.name,
                            )
                        )
            except json.JSONDecodeError:
                pass
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            endpoints=endpoints,
            summary={"parameterized_urls": len(endpoints), "params": param_summary},
        )
