#!/usr/bin/env bash
# demo-launcher.sh — detecta Java portable (Homebrew / SDKMAN / JAVA_HOME) y
# lanza el jar ejecutable con la muestra sintética en modo headless-smoke.
#
# Uso:
#   ./scripts/demo-launcher.sh [--port=8787] [--output=output/dashboard-demo.png]
#
# Sin --demo --headless-smoke abre la ventana Swing. La salida por consola es
# mínima; cualquier error se imprime por stderr.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
JAR="${ROOT}/target/dashboard-wazuh.jar"

PORT=8787
OUTPUT="output/dashboard-demo.png"
ARGS=()

for a in "$@"; do
    case "$a" in
        --port=*) PORT="${a#--port=}" ;;
        --output=*) OUTPUT="${a#--output=}" ;;
        --ui) ARGS=("--demo") ;;
        --help|-h)
            echo "Uso: $0 [--port=N] [--output=PATH] [--ui]" >&2
            exit 0
            ;;
        *) ARGS+=("$a") ;;
    esac
done

detect_java() {
    if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
        echo "${JAVA_HOME}/bin/java"
        return 0
    fi
    if command -v /opt/homebrew/opt/openjdk/bin/java >/dev/null 2>&1; then
        echo "/opt/homebrew/opt/openjdk/bin/java"
        return 0
    fi
    if command -v /usr/local/opt/openjdk/bin/java >/dev/null 2>&1; then
        echo "/usr/local/opt/openjdk/bin/java"
        return 0
    fi
    if command -v java >/dev/null 2>&1; then
        command -v java
        return 0
    fi
    return 1
}

JAVA_BIN="$(detect_java || true)"
if [[ -z "${JAVA_BIN}" ]]; then
    echo "[demo-launcher] ERROR: no se encontró un binario de Java." >&2
    echo "[demo-launcher] Instala OpenJDK (brew install openjdk) o fija JAVA_HOME." >&2
    exit 1
fi

if [[ ! -f "${JAR}" ]]; then
    echo "[demo-launcher] No existe ${JAR}; ejecuta 'mvn package' primero." >&2
    exit 1
fi

mkdir -p "$(dirname "${OUTPUT}")"

if [[ ${#ARGS[@]} -gt 0 && "${ARGS[0]}" == "--demo" ]]; then
    echo "[demo-launcher] Modo UI (Swing). El receptor escucha en 127.0.0.1:${PORT}." >&2
    exec "${JAVA_BIN}" -jar "${JAR}" "${ARGS[@]}" "--port=${PORT}"
fi

echo "[demo-launcher] Lanzando smoke headless: receptor + render PNG." >&2
exec "${JAVA_BIN}" -Djava.awt.headless=true -jar "${JAR}" "--demo" "--headless-smoke" \
    "--port=${PORT}" "--output=${OUTPUT}"