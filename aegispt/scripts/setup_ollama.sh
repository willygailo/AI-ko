#!/usr/bin/env bash
# Optional helper for configuring local Ollama with lightweight models suited for 7.5-8 GB RAM hosts.
set -euo pipefail

PROFILE="light"
for arg in "$@"; do
  case "$arg" in
    --light) PROFILE="light" ;;
    --coder) PROFILE="coder" ;;
    -h|--help)
      echo "Usage: $0 [--light | --coder]"
      echo "  --light  Pull qwen2.5:1.5b + qwen2.5:3b (~2.5 GB total, ideal for 7.5-8 GB RAM hosts)"
      echo "  --coder  Pull qwen2.5:3b + qwen2.5-coder:7b (~6.5 GB total, best with 12+ GB RAM)"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg (use --help)" >&2
      exit 1
      ;;
  esac
done

if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama is NOT installed (this is optional — AegisPT also supports Ollama Cloud or Offline Fallback)."
  echo "  Install locally: curl -fsSL https://ollama.com/install.sh | sh"
  echo "  Or configure Ollama Cloud without installing locally: ./aegispt setup --provider cloud"
  exit 1
fi

echo "[*] Checking Ollama service on http://127.0.0.1:11434 ..."
if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  echo "Start Ollama first with: ollama serve"
  exit 1
fi

if [ "$PROFILE" = "coder" ]; then
  echo "[*] Pulling standard coder profile (qwen2.5:3b + qwen2.5-coder:7b)..."
  ollama pull qwen2.5:3b
  ollama pull qwen2.5-coder:7b
else
  echo "[*] Pulling lightweight profile for 7.5-8 GB RAM hosts (qwen2.5:1.5b + qwen2.5:3b)..."
  ollama pull qwen2.5:1.5b
  ollama pull qwen2.5:3b
fi

echo "[+] Local Ollama models ready. Run './aegispt setup --provider local --no-verify' to link .env."
