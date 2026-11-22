#!/usr/bin/env bash
# Optional helper for configuring local Ollama with lightweight models suited for 7.5-8 GB RAM hosts.
set -euo pipefail

if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama is not installed."
  echo "Install from https://ollama.com/download (or run: curl -fsSL https://ollama.com/install.sh | sh)"
  exit 1
fi

echo "[*] Checking Ollama service..."
if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  echo "Start Ollama first with: ollama serve"
  exit 1
fi

echo "[*] Pulling compact models tuned for CPU / 8GB RAM..."
ollama pull qwen2.5:3b
ollama pull qwen2.5-coder:7b
echo "[+] Ollama local models ready for AegisPT."
