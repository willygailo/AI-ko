"""Tests for CLI setup (.env wizard) and tools reference catalog."""
from __future__ import annotations

import json
import os
from pathlib import Path

from typer.testing import CliRunner

from aegispt_cli.main import HTTP_PROBE_MODES, TOOL_ARG_EXAMPLES, _write_env_config, app

runner = CliRunner()


def test_write_env_config_sanitizes_newlines_quotes_and_sets_0600(tmp_path: Path):
    template = tmp_path / ".env.example"
    template.write_text(
        "# Header\nAEGISPT_HOST=127.0.0.1\nAEGISPT_OLLAMA_URL=http://127.0.0.1:11434\nAEGISPT_OLLAMA_API_KEY=\n",
        encoding="utf-8",
    )
    out_env = tmp_path / ".env"
    _write_env_config(
        out_env,
        {
            "AEGISPT_OLLAMA_URL": "https://ollama.com\nMALICIOUS=1",
            "AEGISPT_OLLAMA_API_KEY": "test_key_123",
            "AEGISPT_OLLAMA_FAST_MODEL": "qwen3-next:80b",
            "AEGISPT_CUSTOM_NOTE": "value with # hash and space",
        },
        template_path=template,
    )
    content = out_env.read_text(encoding="utf-8")
    assert "\nMALICIOUS=" not in content
    assert "AEGISPT_OLLAMA_URL=https://ollama.comMALICIOUS=1" in content
    assert "AEGISPT_OLLAMA_API_KEY=test_key_123" in content
    assert "AEGISPT_OLLAMA_FAST_MODEL=qwen3-next:80b" in content
    assert 'AEGISPT_CUSTOM_NOTE="value with # hash and space"' in content
    assert (os.stat(out_env).st_mode & 0o777) == 0o600


def test_cli_setup_offline_api_key_stdin_and_tools_commands(tmp_path: Path):
    env_dest = tmp_path / ".env"
    res_setup = runner.invoke(
        app,
        ["setup", "--provider", "offline", "--env-path", str(env_dest), "--no-verify"],
    )
    assert res_setup.exit_code == 0, res_setup.output
    assert env_dest.is_file()
    offline_content = env_dest.read_text(encoding="utf-8")
    assert "AEGISPT_LLM_MODE=offline" in offline_content
    assert "AEGISPT_OLLAMA_FAST_MODEL=qwen2.5:1.5b" in offline_content

    cloud_env = tmp_path / ".env.cloud"
    res_cloud = runner.invoke(
        app,
        [
            "setup",
            "--provider",
            "cloud",
            "--api-key-stdin",
            "--env-path",
            str(cloud_env),
            "--no-verify",
        ],
        input="secret-from-stdin-token\n",
    )
    assert res_cloud.exit_code == 0, res_cloud.output
    cloud_content = cloud_env.read_text(encoding="utf-8")
    assert "AEGISPT_LLM_MODE=auto" in cloud_content
    assert "AEGISPT_OLLAMA_API_KEY=secret-from-stdin-token" in cloud_content
    assert (os.stat(cloud_env).st_mode & 0o777) == 0o600

    res_tools = runner.invoke(app, ["tools", "--json"])
    assert res_tools.exit_code == 0, res_tools.output
    data = json.loads(res_tools.output)
    assert len(data["tools"]) == 24
    assert len(data["http_probe_modes"]) == len(HTTP_PROBE_MODES) == 12
    for tool in data["tools"]:
        assert tool["name"] in TOOL_ARG_EXAMPLES, f"Missing TOOL_ARG_EXAMPLES for {tool['name']}"

    res_t3 = runner.invoke(app, ["tools", "--tier", "3"])
    assert res_t3.exit_code == 0, res_t3.output
    assert "sqlmap" in res_t3.output
    assert "race_burst_probe" in res_t3.output

    res_bad_tier = runner.invoke(app, ["tools", "--tier", "4"])
    assert res_bad_tier.exit_code != 0

    # Pasting an API key directly into the initial 'Choose mode' prompt auto-selects cloud mode
    direct_key_env = tmp_path / ".env.direct_key"
    res_direct = runner.invoke(
        app,
        ["setup", "--env-path", str(direct_key_env), "--no-verify"],
        input="my_ollama_cloud_api_key_1234567890\n",
    )
    assert res_direct.exit_code == 0, res_direct.output
    direct_content = direct_key_env.read_text(encoding="utf-8")
    assert "AEGISPT_OLLAMA_URL=https://ollama.com" in direct_content
    assert "AEGISPT_OLLAMA_API_KEY=my_ollama_cloud_api_key_1234567890" in direct_content

    # Typing numeric '2' selects local mode
    num_local_env = tmp_path / ".env.num_local"
    res_num = runner.invoke(
        app,
        ["setup", "--env-path", str(num_local_env), "--no-verify"],
        input="2\n",
    )
    assert res_num.exit_code == 0, res_num.output
    assert "AEGISPT_OLLAMA_URL=http://127.0.0.1:11434" in num_local_env.read_text(encoding="utf-8")
