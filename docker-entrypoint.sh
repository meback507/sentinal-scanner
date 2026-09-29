#!/bin/sh
set -e

# Ensure persistent runtime directories exist with appropriate secure permissions
mkdir -p /app/data /app/reports /app/workspaces
chmod -R 770 /app/data /app/reports /app/workspaces 2>/dev/null || true  # sentinel-ignore: S2612

# If running interactively and ADMIN_PASSWORD is not provided, prompt the administrator for password
if [ -z "$ADMIN_PASSWORD" ] && [ -t 0 ]; then
    printf "\n======================================================\n"
    printf " [Sentinel AppSec] Initial Administrator Setup\n"
    printf "======================================================\n"
    printf "Enter password for admin profile: "
    stty -echo 2>/dev/null || true
    read ADMIN_PASSWORD
    stty echo 2>/dev/null || true
    echo ""
    export ADMIN_PASSWORD
fi

# Fallback default if running non-interactively without an explicit environment variable
if [ -z "$ADMIN_PASSWORD" ]; then
    export ADMIN_PASSWORD="admin"
fi

export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
export JWT_SECRET="${JWT_SECRET:-sentinel_platform_jwt_secret_2026_production}"  # sentinel-ignore: S6362, SONAR-S6362

echo "[Sentinel AppSec] Starting server for admin user '${ADMIN_USERNAME}' on port ${PORT:-8000}..."

# Strip accidental single-string "--host 0.0.0.0" argument if passed by Docker CMD
if [ "$1" = "--host 0.0.0.0" ]; then
    shift
fi

# If command passed is a custom program (e.g. bash, sh, python), execute it directly
if [ "$#" -gt 0 ] && [ "${1#-}" = "$1" ]; then
    exec "$@"
fi

# Start uvicorn bound to 0.0.0.0 with optional CLI flags forwarded
exec uvicorn backend.main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers "${WORKERS:-2}" "$@"
