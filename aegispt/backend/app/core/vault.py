"""Local Fernet credential encryption vault with backward-compatible plaintext passthrough."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


ENC_PREFIX = "enc:fernet:"


def _key_path() -> Path:
    return get_settings().resolved_data_dir / ".master.key"


def _get_fernet() -> Fernet:
    kp = _key_path()
    if kp.is_file():
        key = kp.read_bytes().strip()
        if key:
            return Fernet(key)
    key = Fernet.generate_key()
    kp.write_bytes(key + b"\n")
    try:
        os.chmod(kp, 0o600)
    except OSError:
        pass
    return Fernet(key)


def encrypt_str(value: str) -> str:
    if not value:
        return ""
    if value.startswith(ENC_PREFIX):
        return value
    token = _get_fernet().encrypt(value.encode("utf-8")).decode("ascii")
    return f"{ENC_PREFIX}{token}"


def decrypt_or_passthrough(value: str | None) -> str:
    if not value:
        return ""
    if not value.startswith(ENC_PREFIX):
        return value
    raw = value[len(ENC_PREFIX) :]
    try:
        return _get_fernet().decrypt(raw.encode("ascii")).decode("utf-8")
    except InvalidToken:
        return ""


def encrypt_dict(data: dict[str, str] | None) -> dict[str, str]:
    if not data:
        return {}
    return {str(k): encrypt_str(str(v)) for k, v in data.items()}


def decrypt_dict(data: dict[str, Any] | None) -> dict[str, str]:
    if not data:
        return {}
    return {str(k): decrypt_or_passthrough(str(v)) for k, v in data.items()}


def encrypt_json_blob(obj: Any) -> str:
    return encrypt_str(json.dumps(obj))
