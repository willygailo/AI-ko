"""LLM Router & SecretRedactor tests using local mock HTTP server."""
from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from app.core.redactor import SecretRedactor
from app.llm.router import LLMProfileConfig, LLMRouter
from app.llm.schemas import parse_json_object


def test_secret_redactor_roundtrip():
    r = SecretRedactor()
    sample = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.signature12345 and Cookie: session=supersecretvalue99"
    redacted = r.redact(sample)
    assert "supersecretvalue99" not in redacted
    assert "eyJhbGciOiJIUzI1NiJ9" not in redacted
    restored = r.restore(redacted)
    assert restored == sample


def test_parse_json_object_handles_markdown_fences():
    raw = """Here is the plan:\n```json\n{"thought": "probe", "phase": "recon", "should_stop": false}\n```"""
    parsed = parse_json_object(raw)
    assert parsed["phase"] == "recon"


def test_llm_router_ollama_and_openai_compat_mock():
    captured_bodies = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            captured_bodies.append((self.path, body))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if self.path == "/api/chat":
                self.wfile.write(
                    json.dumps({"model": body["model"], "message": {"content": '{"ok": true}'}}).encode()
                )
            else:
                self.wfile.write(
                    json.dumps(
                        {
                            "model": body["model"],
                            "choices": [{"message": {"content": '{"ok": "openai"}'}}],
                        }
                    ).encode()
                )

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        async def _run():
            router = LLMRouter(timeout=5.0)
            ollama_cfg = LLMProfileConfig(
                name="test-ollama",
                provider="ollama",
                base_url=f"http://127.0.0.1:{port}",
                fast_model="qwen2.5:3b",
                reasoning_model="qwen2.5-coder:7b",
            )
            res1 = await router.complete_json(
                profile=ollama_cfg,
                tier="fast",
                messages=[{"role": "user", "content": "hi"}],
            )
            assert res1 == {"ok": True}

            compat_cfg = LLMProfileConfig(
                name="test-vllm",
                provider="openai_compat",
                base_url=f"http://127.0.0.1:{port}",
                api_key="testkey",
                fast_model="qwen-3b",
                reasoning_model="qwen-32b",
            )
            res2 = await router.complete_json(
                profile=compat_cfg,
                tier="reasoning",
                messages=[{"role": "user", "content": "hi"}],
            )
            assert res2 == {"ok": "openai"}

        asyncio.run(_run())
        assert captured_bodies[0][0] == "/api/chat"
        assert captured_bodies[0][1]["model"] == "qwen2.5:3b"
        assert captured_bodies[1][0] == "/v1/chat/completions"
        assert captured_bodies[1][1]["model"] == "qwen-32b"
    finally:
        server.shutdown()
        server.server_close()
