"""Base typed tool adapter enforcing scope, shell=False execution, bounds, and artifact capture."""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import os
import re
import shutil
import signal
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Type

from pydantic import BaseModel

from app.config import get_settings
from app.core.events import event_bus
from app.core.redactor import SecretRedactor
from app.core.scope import ScopePolicy, ScopeViolationError

CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def resolve_binary(name: str, extra_dirs: list[Path] | None = None) -> str | None:
    """Resolve binary path, checking user Go/PDTM/local bins before system PATH."""
    home = Path.home()
    candidates = [
        *(extra_dirs or []),
        home / ".pdtm" / "go" / "bin",
        home / "go" / "bin",
        home / ".local" / "bin",
    ]
    for folder in candidates:
        candidate = folder / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(name)


def sanitize_argv(argv: list[str]) -> list[str]:
    cleaned: list[str] = []
    for item in argv:
        s = str(item)
        if CONTROL_CHAR_RE.search(s):
            raise ScopeViolationError(f"Disallowed control characters in argument: {s!r}")
        cleaned.append(s)
    return cleaned


def fingerprint_finding(tool_source: str, title: str, target_url: str, parameter: str | None) -> str:
    raw = f"{tool_source}|{title.strip().lower()}|{target_url.strip()}|{(parameter or '').strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


@dataclass
class DiscoveredAsset:
    asset_type: str  # domain|subdomain|host|ip|api
    value: str
    ip_address: str | None = None
    status_code: int | None = None
    title: str | None = None
    waf: str | None = None
    technologies: list[str] = field(default_factory=list)
    headers: dict[str, Any] = field(default_factory=dict)
    discovered_by: str = "tool"


@dataclass
class DiscoveredEndpoint:
    method: str
    url: str
    path: str = "/"
    query_params: list[str] = field(default_factory=list)
    body_params: list[str] = field(default_factory=list)
    status_code: int | None = None
    content_type: str | None = None
    source: str = "tool"


@dataclass
class DiscoveredFinding:
    title: str
    severity: str  # critical|high|medium|low|info
    target_url: str
    description: str = ""
    parameter: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    poc_command: str | None = None
    remediation: str = ""
    tool_source: str = "aegispt"


@dataclass
class ToolResult:
    tool_name: str
    exit_code: int
    duration_ms: int
    stdout: str = ""
    stderr: str = ""
    raw_log_path: str | None = None
    assets: list[DiscoveredAsset] = field(default_factory=list)
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    findings: list[DiscoveredFinding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class BaseToolAdapter(ABC):
    name: str
    description: str
    tier: int = 1  # 1=Passive/Recon, 2=Bounded Scan, 3=Approval-Gated Active Verification
    binary_name: str | None = None
    args_schema: Type[BaseModel]
    default_timeout: int = 180

    def is_available(self) -> tuple[bool, str | None]:
        if self.binary_name is None:
            return True, "native-python"
        path = resolve_binary(self.binary_name)
        return (path is not None), path

    def validate_args(self, raw_args: dict[str, Any]) -> BaseModel:
        return self.args_schema.model_validate(raw_args or {})

    def effective_tier(self, args: BaseModel) -> int:
        return self.tier

    def validate_scope(self, target: str, args: BaseModel, scope: ScopePolicy) -> str:
        return scope.validate_target(target)

    @abstractmethod
    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        ...

    def parse_output(
        self,
        *,
        target: str,
        args: BaseModel,
        stdout: str,
        stderr: str,
        work_dir: Path,
    ) -> ToolResult:
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            stdout=stdout,
            stderr=stderr,
        )

    def _subprocess_env(self) -> dict[str, str]:
        settings = get_settings()
        tool_home = settings.resolved_data_dir / "tool_home"
        (tool_home / ".config").mkdir(parents=True, exist_ok=True)
        (tool_home / ".cache").mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["HOME"] = str(tool_home)
        env["XDG_CONFIG_HOME"] = str(tool_home / ".config")
        env["XDG_CACHE_HOME"] = str(tool_home / ".cache")
        env["NO_COLOR"] = "1"
        return env

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
        """Optional async setup hook executed before subprocess/native invocation."""
        return {}

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
        """Optional async cleanup/enrichment hook always executed in a finally block."""
        return None

    @staticmethod
    def _terminate_process_group(proc: asyncio.subprocess.Process) -> None:
        """Terminate a subprocess and its entire process group safely."""
        if proc.returncode is not None:
            return
        if hasattr(os, "killpg") and proc.pid:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
                return
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            proc.kill()
        except ProcessLookupError:
            pass

    async def execute(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        target: str,
        raw_args: dict[str, Any],
        scope: ScopePolicy,
    ) -> ToolResult:
        args = self.validate_args(raw_args)
        norm_target = self.validate_scope(target, args, scope)
        settings = get_settings()

        run_dir = settings.artifacts_dir / engagement_id / tool_run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        log_path = run_dir / f"{self.name}.log"

        start = time.monotonic()
        context: dict[str, Any] = {}
        final_result: ToolResult | None = None
        try:
            context = await self.pre_execute(
                engagement_id=engagement_id,
                tool_run_id=tool_run_id,
                target=norm_target,
                args=args,
                scope=scope,
                work_dir=run_dir,
            )

            if self.binary_name is None:
                result = await self.execute_native(
                    engagement_id=engagement_id,
                    tool_run_id=tool_run_id,
                    target=norm_target,
                    args=args,
                    scope=scope,
                    work_dir=run_dir,
                )
                result.duration_ms = int((time.monotonic() - start) * 1000)
                scrubbed = SecretRedactor().redact(result.stdout or "")
                log_path.write_text(scrubbed, encoding="utf-8", errors="replace")
                result.raw_log_path = str(log_path)
                final_result = result
                return result

            argv = sanitize_argv(self.build_argv(norm_target, args, scope, run_dir))
            timeout = min(
                int(getattr(args, "timeout_seconds", self.default_timeout) or self.default_timeout),
                settings.default_tool_timeout * 2,
            )

            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(run_dir),
                env=self._subprocess_env(),
                start_new_session=True,
            )

            stdout_chunks: list[bytes] = []
            stderr_chunks: list[bytes] = []
            max_bytes = settings.max_output_bytes
            total_bytes = 0
            line_count = 0

            async def _read_stream(stream: asyncio.StreamReader | None, sink: list[bytes], label: str) -> None:
                nonlocal total_bytes, line_count
                if stream is None:
                    return
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    if total_bytes < max_bytes:
                        sink.append(line)
                        total_bytes += len(line)
                    line_count += 1
                    if line_count <= 200 or line_count % 25 == 0:
                        text_line = line.decode("utf-8", errors="replace").rstrip()
                        if text_line:
                            await event_bus.publish(
                                engagement_id=engagement_id,
                                event_type="tool_output",
                                agent_name=self.name,
                                message=text_line[:500],
                                payload={"tool_run_id": tool_run_id, "stream": label},
                                persist=False,
                            )

            timed_out = False
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        _read_stream(proc.stdout, stdout_chunks, "stdout"),
                        _read_stream(proc.stderr, stderr_chunks, "stderr"),
                        proc.wait(),
                    ),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                timed_out = True
                self._terminate_process_group(proc)
                try:
                    await proc.wait()
                except ProcessLookupError:
                    pass
            except asyncio.CancelledError:
                self._terminate_process_group(proc)
                try:
                    await proc.wait()
                except ProcessLookupError:
                    pass
                raise

            duration_ms = int((time.monotonic() - start) * 1000)
            stdout_str = b"".join(stdout_chunks).decode("utf-8", errors="replace")
            stderr_str = b"".join(stderr_chunks).decode("utf-8", errors="replace")
            redactor = SecretRedactor()
            safe_argv = redactor.redact(" ".join(argv))
            safe_stdout = redactor.redact(stdout_str)
            safe_stderr = redactor.redact(stderr_str)
            log_path.write_text(
                f"# ARGV: {safe_argv}\n\n# STDOUT\n{safe_stdout}\n\n# STDERR\n{safe_stderr}\n",
                encoding="utf-8",
                errors="replace",
            )

            parse_kwargs: dict[str, Any] = {
                "target": norm_target,
                "args": args,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "work_dir": run_dir,
            }
            if "scope" in inspect.signature(self.parse_output).parameters:
                parse_kwargs["scope"] = scope
            parsed = self.parse_output(**parse_kwargs)
            parsed.exit_code = proc.returncode if proc.returncode is not None else -1
            parsed.duration_ms = duration_ms
            parsed.stdout = stdout_str
            parsed.stderr = stderr_str
            parsed.raw_log_path = str(log_path)
            if timed_out:
                parsed.error = f"Tool timed out after {timeout}s (partial results preserved)."
            final_result = parsed
            return parsed
        finally:
            await self.post_execute(
                engagement_id=engagement_id,
                tool_run_id=tool_run_id,
                target=norm_target,
                args=args,
                scope=scope,
                work_dir=run_dir,
                context=context,
                result=final_result,
            )

    async def execute_native(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        target: str,
        args: BaseModel,
        scope: ScopePolicy,
        work_dir: Path,
    ) -> ToolResult:
        raise NotImplementedError
