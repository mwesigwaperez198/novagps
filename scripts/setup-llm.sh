#!/bin/sh
# setup-llm.sh — one-shot Ollama install for macOS/Linux so LAU can reason with a real LLM.
# Run from the repo root:  ./scripts/setup-llm.sh
set -e

MODEL="${OLLAMA_MODEL:-llama3.2:3b}"

if command -v ollama >/dev/null 2>&1; then
    echo "ollama already installed."
else
    case "$(uname -s)" in
        Darwin)
            if ! command -v brew >/dev/null 2>&1; then
                echo "Homebrew missing. Install it first:  https://brew.sh"
                exit 1
            fi
            echo "Installing ollama via Homebrew..."
            brew install ollama
            ;;
        Linux)
            echo "Installing ollama via the official script..."
            curl -fsSL https://ollama.com/install.sh | sh
            ;;
        *)
            echo "Unsupported OS: $(uname -s)"
            exit 1
            ;;
    esac
fi

if ! curl -fsS --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    echo "Starting ollama serve..."
    if [ "$(uname -s)" = "Darwin" ]; then
        brew services start ollama || nohup ollama serve >/dev/null 2>&1 &
    else
        nohup ollama serve >/dev/null 2>&1 &
    fi
    sleep 3
fi

echo "Pulling ${MODEL} (may take a few minutes on first run)..."
ollama pull "$MODEL"

echo
echo "Done. LAU will auto-detect Ollama within ~20s of startup."
echo "Run:  ./lau.sh"
echo "Tip:  OLLAMA_MODEL=${MODEL} ./lau.sh"