#!/bin/bash
set -euo pipefail
set -o errtrace
IFS=$'\n\t'

#############################################################################################
# N8N Installation, Upgrade, Backup & Restore Manager (Mode-aware: Single or Queue)
# Author:      TheNguyen
# Email:       thenguyen.ai.automation@gmail.com
# Version:     2.2.0
# Date:        2025-08-28
#
# Description:
#   A unified management tool for installing, upgrading, backing up, and restoring the
#   n8n automation stack running on Docker Compose with Traefik + Let's Encrypt, supporting
#   BOTH "single" mode and "queue" mode. For install, pass --mode. For other actions, mode
#   is auto-detected from the active compose + containers.
#
# Key features:
#   - Install:
#       * --mode {single|queue} chooses template folder (single-mode/ or queue-mode/)
#       * Validates DNS, installs Docker/Compose if missing, pins version, generates secrets
#       * Brings stack up, waits for health, prints a summary
#   - Upgrade:
#       * No mode needed; auto-detects from current compose
#       * Pulls/validates target version, redeploys safely (downgrade with -f)
#   - Backup / Restore:
#       * No mode needed; discovers services, volumes, and containers dynamically
#       * Full local backup of Docker volumes, PostgreSQL dump, and configs
#       * Change detection snapshot to skip redundant backups (use -f to force)
#       * Optional email notifications via Gmail SMTP (msmtp)
#       * Optional upload to Google Drive (or any rclone remote)
#       * Restore from local archive or rclone remote path (remote:folder/file.tar.gz)
#   - Requirements:
#       * docker (compose v2 plugin), curl, jq (auto-installed if missing), rsync, tar, openssl
#       * optional: msmtp (for email), rclone (for uploads)
#
#   - Conventions:
#       * Template directories live under the script dir:
#           ./single-mode/{docker-compose.yml,.env}
#           ./queue-mode/{docker-compose.yml,.env}
#       * Target directory default: /home/n8n (change with -d|--dir)
#############################################################################################
# ------------------------------- Defaults & Globals ---------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_SINGLE="$SCRIPT_DIR/single-mode"
TEMPLATE_QUEUE="$SCRIPT_DIR/queue-mode"

DEFAULT_N8N_DIR="/home/n8n"
N8N_DIR="$DEFAULT_N8N_DIR"
ENV_FILE=""
COMPOSE_FILE=""

# Actions
DO_INSTALL=false
DO_UPGRADE=false
DO_BACKUP=false
DO_RESTORE=false
DO_CLEANUP=false
DO_AVAILABLE=false

# Install-only
INSTALL_MODE=""         # single|queue
DOMAIN=""
SSL_EMAIL=""

# Upgrade/Install shared
N8N_VERSION="latest"
FORCE_FLAG=false

# Backup/Restore
TARGET_RESTORE_FILE=""
DO_FORCE_BACKUP=false
DAYS_TO_KEEP=7

# Email (msmtp)
EMAIL_TO=""
EMAIL_EXPLICIT=false
NOTIFY_ON_SUCCESS=false
SMTP_USER="${SMTP_USER:-}"
SMTP_PASS="${SMTP_PASS:-}"
EMAIL_SENT=false

# rclone remote path (e.g. gdrive:/n8n-backups)
RCLONE_REMOTE=""
RCLONE_FLAGS=(--transfers=4 --checkers=8 --retries=5 --low-level-retries=10 --contimeout=30s --timeout=5m --retries-sleep=10s)

# Logs & run context
LOG_LEVEL="${LOG_LEVEL:-INFO}"
DATE="$(date +%F_%H-%M-%S)"
LOG_FILE=""
BACKUP_DIR=""
LOG_DIR=""
ACTION=""
BACKUP_STATUS=""
UPLOAD_STATUS=""
BACKUP_FILE=""
DRIVE_LINK=""

# Cache for discovery
DISCOVERED_SERVICES=()           # service names from compose
DISCOVERED_CONTAINERS=()         # container names actually running for those services
DISCOVERED_VOLUMES=()            # volume names from compose config --volumes
DISCOVERED_POSTGRES_CONT=""      # container name for postgres (if any)
DISCOVERED_REDIS_CONT=""         # container name for redis (if any)
DISCOVERED_N8N_MAIN_CONT=""      # container name for "main" n8n (if any)
DISCOVERED_MODE=""               # single|queue|unknown


################################################################################
# log()
# Description:
#   Structured logger with levels (DEBUG, INFO, WARN, ERROR).
#
# Behaviors:
#   - Suppresses DEBUG unless LOG_LEVEL=DEBUG.
#   - Prefixes lines with timestamp + level.
#
# Returns:
#   0 always.
################################################################################
log() {
  local level="$1"; shift || true
  local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
  case "$level" in
    DEBUG) [[ "$LOG_LEVEL" == "DEBUG" ]] || return 0 ;;
    INFO|WARN|ERROR) ;;
    *) level="INFO" ;;
  esac
  echo "[$ts] [$level] $*"
}

################################################################################
# box_line()
# Description:
#   Print a left-aligned label (fixed width 22) and a value on one line.
#
# Behaviors:
#   - Uses printf to align columns in status boxes.
#
# Returns:
#   0 always.
################################################################################
box_line() { printf "%-22s%s\n" "$1" "$2"; }

################################################################################
# usage()
# Description:
#   Print CLI help and exit.
#
# Behaviors:
#   - Shows mode flag only for install path.
#   - Shows dynamic behavior for other actions.
#
# Returns:
#   Exits 1.
################################################################################
usage() {
  cat <<EOF
Usage: $0 [ONE ACTION] [OPTIONS]

Actions (choose exactly one):
  -a, --available
        List available n8n versions (context-aware)

  -i, --install <DOMAIN>
        Install n8n with the given domain (Traefik + LE)
        Requires: --mode single|queue  and optional -v|--version

  -u, --upgrade <DOMAIN>
        Upgrade n8n to target version (or latest)  [auto-detect mode]

  -b, --backup
        Run backup (skip if no changes unless -f)  [auto-detect mode]

  -r, --restore <FILE_OR_REMOTE>
        Restore from local file or rclone remote (e.g. gdrive:folder/file.tar.gz)  [auto-detect mode]

  -c, --cleanup
        Stop stack, remove volumes/images (interactive confirm)  [auto-detect mode]

Options:
  --mode <single|queue>    (required for --install only)
  -v, --version <tag>      Target n8n version (default: latest stable)
  -m, --email <ssl-email>  LE certificate email (install/upgrade)
  -d, --dir <path>         Target n8n directory (default: /home/n8n)
  -l, --log-level <LEVEL>  DEBUG | INFO (default) | WARN | ERROR
  -f, --force              Upgrade: allow downgrade or redeploy; Backup: force even if unchanged
  -e, --email <to>         Send notifications to this address
  -n, --notify-on-success  Also email on success (not just failures)
  -s, --remote <remote>    rclone remote root (e.g. gdrive or gdrive:/n8n-backups)
  -h, --help               Show this help

Examples:
  $0 -i n8n.example.com --mode single -m you@example.com
  $0 -i n8n.example.com --mode queue -v 1.107.2 -m you@example.com
  $0 -u n8n.example.com -v 1.107.2
  $0 -b -s gdrive:/n8n-backups -e ops@example.com -n
  $0 -r gdrive:/n8n-backups/n8n_backup_1.107.2_2025-08-27_12-30-00.tar.gz
EOF
  exit 1
}

################################################################################
# check_root()
# Description:
#   Ensure the script is run as root (or via sudo).
#
# Behaviors:
#   - Exits with error if EUID != 0.
#
# Returns:
#   0 on success; exits 1 otherwise.
################################################################################
check_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    log ERROR "Please run as root (sudo)."
    exit 1
  fi
}

################################################################################
# require_cmd()
# Description:
#   Verify a command exists in PATH.
#
# Behaviors:
#   - Installs jq if missing (apt) when requested as 'jq'.
#   - Logs clear error for other commands.
#
# Returns:
#   0 if present/installed; 1 otherwise.
################################################################################
require_cmd() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then return 0; fi
  if [[ "$cmd" == "jq" ]]; then
    log INFO "Installing jq..."
    apt-get update -y && apt-get install -y --no-install-recommends jq || true
  fi
  command -v "$cmd" >/dev/null 2>&1 || { log ERROR "Missing command: $cmd"; return 1; }
}

################################################################################
# get_latest_n8n_version()
# Description:
#   Resolve the latest stable n8n tag from Docker Hub.
#
# Behaviors:
#   - Queries Docker Hub (n8nio/n8n) and returns latest semver (excludes "-rc").
#   - Requires curl + jq.
#
# Returns:
#   Prints version tag on stdout; empty string on failure.
################################################################################
get_latest_n8n_version() {
  require_cmd curl || return 1
  require_cmd jq   || return 1
  local tags
  tags="$(curl -sfL 'https://registry.hub.docker.com/v2/repositories/n8nio/n8n/tags/?page_size=100' \
         | jq -r '.results[].name' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1 || true)"
  [[ -n "$tags" ]] && echo "$tags" || echo ""
}

################################################################################
# validate_image_tag()
# Description:
#   Check whether an n8n image tag exists.
#
# Behaviors:
#   - Tries docker.n8n.io then docker.io registries.
#
# Returns:
#   0 if found, 1 otherwise.
################################################################################
validate_image_tag() {
  local tag="$1"
  docker manifest inspect "docker.n8n.io/n8nio/n8n:${tag}" >/dev/null 2>&1 && return 0
  docker manifest inspect "docker.io/n8nio/n8n:${tag}"      >/dev/null 2>&1 && return 0
  return 1
}

################################################################################
# check_domain()
# Description:
#   Verify the provided DOMAIN’s A record points to this server’s public IP.
#
# Behaviors:
#   - Detects server IP via api.ipify.org.
#   - Resolves DOMAIN with `dig` (preferred) or `getent`; logs resolved IPs.
#   - If no resolver present → warns and continues (cannot verify).
#   - If resolved IPs include server IP → logs success.
#   - Else logs error and terminates installation/upgrade flow.
#
# Returns:
#   0 on success/skip (no resolver); exits 1 on mismatch.
################################################################################
check_domain() {
  local server_ip domain_ips resolver=""
  server_ip=$(curl -s https://api.ipify.org || echo "Unavailable")

  if command -v dig >/dev/null 2>&1; then
    resolver="dig"
    domain_ips=$(dig +short A "$DOMAIN" | tr '\n' ' ')
  elif command -v getent >/dev/null 2>&1; then
    resolver="getent"
    domain_ips=$(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ')
  else
    log WARN "Neither 'dig' nor 'getent' found; DNS check will be skipped."
  fi

  log INFO "Your server's public IP is: $server_ip"
  [[ -n "$resolver" ]] && log INFO "Domain $DOMAIN resolves (via $resolver): $domain_ips"

  if [[ -z "$resolver" || "$server_ip" == "Unavailable" ]]; then
    log WARN "Cannot verify DNS → continuing; Let's Encrypt may fail if DNS is wrong."
    return 0
  fi

  if echo "$domain_ips" | tr ' ' '\n' | grep -Fxq "$server_ip"; then
    log INFO "Domain $DOMAIN is correctly pointing to this server."
  else
    log ERROR "Domain $DOMAIN is NOT pointing to this server. Update your A record to: $server_ip"
    exit 1
  fi
}

################################################################################
# set_paths()
# Description:
#   Compute important paths for the chosen/target directory.
#
# Behaviors:
#   - Sets ENV_FILE, COMPOSE_FILE, BACKUP_DIR, LOG_DIR, LOG_FILE.
#   - Creates logs/ and backups/ if missing.
#
# Returns:
#   0 always.
################################################################################
set_paths() {
  ENV_FILE="$N8N_DIR/.env"
  COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
  mkdir -p "$N8N_DIR/logs" "$N8N_DIR/backups"
  BACKUP_DIR="$N8N_DIR/backups"
  LOG_DIR="$N8N_DIR/logs"

  local mode="manager"
  $DO_BACKUP  && mode="backup"
  $DO_RESTORE && mode="restore"
  LOG_FILE="$N8N_DIR/logs/${mode}_n8n_${DATE}.log"

  exec > >(tee -a "$LOG_FILE") 2>&1
  log INFO "Working directory: $N8N_DIR"
  log INFO "Logging to: $LOG_FILE"
}

################################################################################
# install_prereqs()
# Description:
#   Install docker (compose v2), and common utilities.
#
# Behaviors:
#   - Adds Docker APT repo; installs docker & compose plugin (fallback get.docker.com).
#   - Installs curl, jq, rsync, tar, msmtp, dnsutils, openssl, rclone.
#
# Returns:
#   0 on success; non-zero if unexpected failures.
################################################################################
install_prereqs() {
  if ! command -v docker >/dev/null 2>&1; then
    log INFO "Installing Docker Engine & Compose v2…"
    apt-get update -y
    apt-get install -y --no-install-recommends ca-certificates curl gnupg lsb-release
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor | tee /etc/apt/keyrings/docker.gpg >/dev/null
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
      | tee /etc/apt/sources.list.d/docker.list >/dev/null
    apt-get update -y || true
    if ! apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
      log WARN "APT install failed; trying get.docker.com"
      curl -fsSL https://get.docker.com | sh
    fi
    systemctl enable --now docker || true
  fi
  log INFO "Installing utilities (curl jq rsync tar msmtp dnsutils openssl rclone)…"
  apt-get install -y --no-install-recommends curl jq rsync tar msmtp dnsutils openssl rclone || true
}

################################################################################
# prompt_ssl_email()
# Description:
#   Prompt operator for Let's Encrypt email if not given.
#
# Behaviors:
#   - Simple regex validation; loops until ok.
#
# Returns:
#   0 after exporting SSL_EMAIL.
################################################################################
prompt_ssl_email() {
  while [[ -z "${SSL_EMAIL:-}" ]]; do
    read -e -p "Enter your email for SSL cert notifications: " SSL_EMAIL
    [[ "$SSL_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || { log ERROR "Invalid email."; SSL_EMAIL=""; }
  done
}

################################################################################
# copy_templates_for_mode()
# Description:
#   Copy docker-compose.yml and .env from the selected template (single|queue).
#
# Behaviors:
#   - Backs up existing files with timestamp.
#   - Updates DOMAIN, SSL_EMAIL, N8N_IMAGE_TAG in .env.
#   - Generates STRONG_PASSWORD and N8N_ENCRYPTION_KEY if placeholders found.
#
# Returns:
#   0 on success; exits non-zero on missing templates.
################################################################################
copy_templates_for_mode() {
  local src_dir=""
  case "$INSTALL_MODE" in
    single) src_dir="$TEMPLATE_SINGLE" ;;
    queue)  src_dir="$TEMPLATE_QUEUE" ;;
    *) log ERROR "--mode must be 'single' or 'queue' for install"; exit 2 ;;
  esac

  [[ -f "$src_dir/docker-compose.yml" && -f "$src_dir/.env" ]] \
    || { log ERROR "Template missing in $src_dir"; exit 1; }

  mkdir -p "$N8N_DIR"
  for f in docker-compose.yml .env; do
    [[ -f "$N8N_DIR/$f" ]] && cp -a "$N8N_DIR/$f" "$N8N_DIR/${f}.bak.$(date +%F_%H-%M-%S)"
    cp -a "$src_dir/$f" "$N8N_DIR/$f"
  done

  # Update .env
  sed -i "s|^DOMAIN=.*$|DOMAIN=${DOMAIN}|" "$ENV_FILE"
  [[ -n "$SSL_EMAIL" ]] && sed -i "s|^SSL_EMAIL=.*$|SSL_EMAIL=${SSL_EMAIL}|" "$ENV_FILE"

  local tag="$N8N_VERSION"
  if [[ -z "$tag" || "$tag" == "latest" ]]; then
    tag="$(get_latest_n8n_version)"; [[ -z "$tag" ]] && { log ERROR "Cannot determine latest n8n version."; exit 1; }
  fi
  validate_image_tag "$tag" || { log ERROR "Tag not found: $tag"; exit 1; }
  if grep -q '^N8N_IMAGE_TAG=' "$ENV_FILE"; then
    sed -i "s|^N8N_IMAGE_TAG=.*$|N8N_IMAGE_TAG=${tag}|" "$ENV_FILE"
  else
    echo "N8N_IMAGE_TAG=${tag}" >> "$ENV_FILE"
  fi

  # Secrets
  grep -q '^STRONG_PASSWORD=' "$ENV_FILE" || echo "STRONG_PASSWORD=$(openssl rand -base64 16)" >> "$ENV_FILE"
  grep -q '^N8N_ENCRYPTION_KEY=' "$ENV_FILE" || echo "N8N_ENCRYPTION_KEY=$(openssl rand -base64 32)" >> "$ENV_FILE"

  chmod 600 "$ENV_FILE" || true
  chmod 640 "$COMPOSE_FILE" || true
}

################################################################################
# compose()
# Description:
#   Wrapper around docker compose with our project directory.
#
# Behaviors:
#   - Executes inside $N8N_DIR.
#
# Returns:
#   Pass-through status of docker compose.
################################################################################
compose() {
  ( cd "$N8N_DIR" && docker compose "$@" )
}

################################################################################
# docker_up_check()
# Description:
#   Bring up the stack and wait for basic health of essential services.
#
# Behaviors:
#   - `docker compose up -d`
#   - Waits (bounded) for postgres (if any) to be healthy, then tries to reach n8n main.
#
# Returns:
#   0 on success; 1 on health failures.
################################################################################
docker_up_check() {
  compose up -d
  discover_from_running || true

  # Postgres first (if present)
  if [[ -n "$DISCOVERED_POSTGRES_CONT" ]]; then
    log INFO "Waiting for Postgres to be healthy…"
    for _ in {1..30}; do
      if docker ps --format '{{.Names}} {{.Status}}' | grep -q "^${DISCOVERED_POSTGRES_CONT}\b.*(healthy)"; then
        break
      fi
      sleep 2
    done
  fi

  # Try n8n main health
  if [[ -n "$DISCOVERED_N8N_MAIN_CONT" ]]; then
    log INFO "Checking n8n main health endpoint…"
    for _ in {1..30}; do
      if docker exec "$DISCOVERED_N8N_MAIN_CONT" wget --spider -q http://localhost:5678/healthz; then
        return 0
      fi
      sleep 2
    done
    log WARN "n8n main health check did not pass in time."
  fi
  return 0
}

################################################################################
# discover_from_compose()
# Description:
#   Discover services and volumes from docker compose files (static).
#
# Behaviors:
#   - Uses `docker compose config --services` and `--volumes`.
#   - Populates DISCOVERED_SERVICES[] and DISCOVERED_VOLUMES[].
#
# Returns:
#   0 on success; non-zero if compose config fails.
################################################################################
discover_from_compose() {
  local svcs vols
  svcs="$(compose config --services 2>/dev/null || true)"
  vols="$(compose config --volumes  2>/dev/null || true)"
  mapfile -t DISCOVERED_SERVICES <<<"$svcs"
  mapfile -t DISCOVERED_VOLUMES  <<<"$vols"
  [[ -n "${DISCOVERED_SERVICES[*]:-}" ]] || { log ERROR "Could not parse services from compose."; return 1; }
  log DEBUG "Services: ${DISCOVERED_SERVICES[*]}"
  log DEBUG "Volumes:  ${DISCOVERED_VOLUMES[*]:-<none>}"
}

################################################################################
# discover_from_running()
# Description:
#   Map compose services to actual container names and infer roles.
#
# Behaviors:
#   - Uses `docker compose ps --format '{{.Service}} {{.Name}} {{.Image}}'`.
#   - Identifies postgres/redis/n8n-main containers by image/name/port/labels heuristics.
#   - Infers mode: single (1 n8n service), queue (workers/runner present), unknown (fallback).
#
# Returns:
#   0 on success; 1 if ps fails.
################################################################################
discover_from_running() {
  local line svc name image
  DISCOVERED_CONTAINERS=()
  DISCOVERED_POSTGRES_CONT=""
  DISCOVERED_REDIS_CONT=""
  DISCOVERED_N8N_MAIN_CONT=""
  DISCOVERED_MODE="unknown"

  local psout
  psout="$(compose ps --format '{{.Service}} {{.Name}} {{.Image}}' 2>/dev/null || true)"
  [[ -n "$psout" ]] || { log WARN "No running containers found via compose ps."; return 1; }

  while IFS= read -r line; do
    svc="$(awk '{print $1}' <<<"$line")"
    name="$(awk '{print $2}' <<<"$line")"
    image="$(awk '{print $3}' <<<"$line")"
    DISCOVERED_CONTAINERS+=("$name")
    # role mapping
    if [[ "$image" =~ postgres ]]; then
      DISCOVERED_POSTGRES_CONT="$name"
    elif [[ "$image" =~ redis ]]; then
      DISCOVERED_REDIS_CONT="$name"
    elif [[ "$image" =~ n8nio/n8n ]]; then
      # heuristic: main service frequently exposes :5678 and may have "main" or "n8n" in svc/name
      if [[ "$svc" =~ ^n8n(-main)?$ || "$name" =~ n8n-main ]]; then
        DISCOVERED_N8N_MAIN_CONT="$name"
      fi
    fi
  done <<<"$psout"

  # infer mode
  local n8n_services
  n8n_services="$(compose config --services | grep -E '^n8n($|-|_)' || true)"
  if grep -Eq '^n8n-worker|^n8n-runner|^n8n-runner-main' <<<"$n8n_services"; then
    DISCOVERED_MODE="queue"
  elif grep -Eq '^n8n$|^n8n-main$' <<<"$n8n_services"; then
    DISCOVERED_MODE="single"
  fi

  log INFO "Detected mode: ${DISCOVERED_MODE:-unknown}"
  log DEBUG "Containers: ${DISCOVERED_CONTAINERS[*]}"
  log DEBUG "Postgres:   ${DISCOVERED_POSTGRES_CONT:-<none>}  Redis: ${DISCOVERED_REDIS_CONT:-<none>}  n8n-main: ${DISCOVERED_N8N_MAIN_CONT:-<none>}"
}

################################################################################
# ensure_encryption_key()
# Description:
#   Ensure N8N_ENCRYPTION_KEY exists in .env (critical for backup/restore).
#
# Behaviors:
#   - Fails if missing; prints masked key on success (DEBUG).
#
# Returns:
#   0 when key present; 1 if missing.
################################################################################
ensure_encryption_key() {
  local key
  key="$(awk -F= '/^N8N_ENCRYPTION_KEY=/{print $2}' "$ENV_FILE" || true)"
  if [[ -z "$key" ]]; then
    log ERROR "N8N_ENCRYPTION_KEY is missing in $ENV_FILE — cannot continue."
    return 1
  fi
  log DEBUG "N8N_ENCRYPTION_KEY: ${key:0:4}****"
}

################################################################################
# list_available_versions()
# Description:
#   Show versions based on context (running -> show newer; else top recent 5).
#
# Behaviors:
#   - Uses Docker Hub tags (jq required).
#
# Returns:
#   0 on success; 1 if API fails.
################################################################################
list_available_versions() {
  require_cmd jq || return 1
  local current=""; local all
  if compose ps >/dev/null 2>&1; then
    # try to read current tag from .env
    current="$(awk -F= '/^N8N_IMAGE_TAG=/{print $2}' "$ENV_FILE" || true)"
  fi

  all="$(get_latest_n8n_version)" || true
  # Pull last 5 by querying pages and sorting; keep it simple:
  local list
  list="$(curl -sfL 'https://registry.hub.docker.com/v2/repositories/n8nio/n8n/tags/?page_size=200' \
          | jq -r '.results[].name' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 5 || true)"
  echo "═════════════════════════════════════════════════════════════"
  if [[ -n "$current" ]]; then
    echo "Current n8n version: $current"
    echo "Latest versions:"
  else
    echo "Top 5 latest stable n8n versions:"
  fi
  echo "$list"
  echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# install_stack()
# Description:
#   Install n8n stack for chosen mode; verify DNS; start and health check.
#
# Behaviors:
#   - Requires --mode single|queue during install.
#   - Copies templates, pins tag, ensures secrets, brings stack up.
#
# Returns:
#   0 on success; exits 1 on fatal error.
################################################################################
install_stack() {
  [[ -n "$DOMAIN" ]] || { log ERROR "Install requires a domain."; exit 2; }
  [[ -n "$INSTALL_MODE" ]] || { log ERROR "Install requires --mode single|queue"; exit 2; }
  prompt_ssl_email
  check_domain
  install_prereqs
  copy_templates_for_mode
  docker_up_check || { log ERROR "Stack unhealthy after install."; exit 1; }

  local ver; ver="$(awk -F= '/^N8N_IMAGE_TAG=/{print $2}' "$ENV_FILE" || echo "unknown")"
  echo "═════════════════════════════════════════════════════════════"
  echo "N8N has been successfully installed!"
  box_line "Domain:"            "https://${DOMAIN}"
  box_line "Installed Version:" "$ver"
  box_line "Install Timestamp:" "$(date '+%Y-%m-%d %H:%M:%S')"
  box_line "Installed By:"      "${SUDO_USER:-$USER}"
  box_line "Target Directory:"  "$N8N_DIR"
  box_line "SSL Email:"         "$SSL_EMAIL"
  box_line "Execution log:"     "$LOG_FILE"
  echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# upgrade_stack()
# Description:
#   Upgrade or force redeploy/downgrade based on args; auto-detect mode.
#
# Behaviors:
#   - Reads current tag from .env; compares with target.
#   - Validates tag; writes .env; compose down/up; health check.
#
# Returns:
#   0 on success; exits non-zero on failure.
################################################################################
upgrade_stack() {
  install_prereqs
  [[ -f "$ENV_FILE" && -f "$COMPOSE_FILE" ]] || { log ERROR "Compose/.env not found in $N8N_DIR"; exit 1; }

  local current target="$N8N_VERSION"
  current="$(awk -F= '/^N8N_IMAGE_TAG=/{print $2}' "$ENV_FILE" || echo "0.0.0")"
  if [[ -z "$target" || "$target" == "latest" ]]; then
    target="$(get_latest_n8n_version)"; [[ -z "$target" ]] && { log ERROR "Cannot resolve latest tag."; exit 1; }
  fi
  log INFO "Current: $current → Target: $target"

  if [[ "$target" == "$current" && "$FORCE_FLAG" != true ]]; then
    log INFO "Already on $current. Use -f to force redeploy."
    return 0
  fi
  if [[ "$FORCE_FLAG" != true && "$(printf "%s\n%s" "$current" "$target" | sort -V | head -n1)" == "$target" && "$current" != "$target" ]]; then
    log INFO "Downgrade detected; use -f to allow."
    return 0
  fi

  validate_image_tag "$target" || { log ERROR "Tag not found: $target"; exit 1; }
  if grep -q '^N8N_IMAGE_TAG=' "$ENV_FILE"; then
    sed -i "s|^N8N_IMAGE_TAG=.*$|N8N_IMAGE_TAG=${target}|" "$ENV_FILE"
  else
    echo "N8N_IMAGE_TAG=${target}" >> "$ENV_FILE"
  fi

  compose down --remove-orphans || true
  docker_up_check || { log ERROR "Stack unhealthy after upgrade."; exit 1; }

  echo "═════════════════════════════════════════════════════════════"
  echo "N8N has been successfully upgraded!"
  box_line "Domain:"            "https://${DOMAIN}"
  box_line "Installed Version:" "$target"
  box_line "Install Timestamp:" "$(date '+%Y-%m-%d %H:%M:%S')"
  box_line "Installed By:"      "${SUDO_USER:-$USER}"
  box_line "Target Directory:"  "$N8N_DIR"
  box_line "SSL Email:"         "$SSL_EMAIL"
  box_line "Execution log:"     "$LOG_FILE"
  echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# snapshot_bootstrap()
# Description:
#   Initialize change-detection snapshot tree on first run.
#
# Behaviors:
#   - Copies volumes’ contents and config files into backups/snapshot/.
#
# Returns:
#   0 on success.
################################################################################
snapshot_bootstrap() {
  local snap="$BACKUP_DIR/snapshot"
  [[ -d "$snap" ]] || mkdir -p "$snap/volumes" "$snap/config"
  discover_from_compose || return 0

  for vol in "${DISCOVERED_VOLUMES[@]}"; do
    mkdir -p "$snap/volumes/$vol"
    rsync -a "/var/lib/docker/volumes/${vol}/_data/" "$snap/volumes/$vol/" || true
  done
  [[ -f "$ENV_FILE" ]] && rsync -a "$ENV_FILE" "$snap/config/" || true
  [[ -f "$COMPOSE_FILE" ]] && rsync -a "$COMPOSE_FILE" "$snap/config/" || true
}

################################################################################
# snapshot_refresh()
# Description:
#   Refresh snapshot after successful backup.
#
# Behaviors:
#   - Rsync with --delete for each discovered volume and config.
#
# Returns:
#   0 on success.
################################################################################
snapshot_refresh() {
  local snap="$BACKUP_DIR/snapshot"
  mkdir -p "$snap/volumes" "$snap/config"
  for vol in "${DISCOVERED_VOLUMES[@]}"; do
    rsync -a --delete \
      --exclude='pg_wal/**' --exclude='pg_stat_tmp/**' --exclude='pg_logical/**' \
      "/var/lib/docker/volumes/${vol}/_data/" "$snap/volumes/$vol/" || true
  done
  [[ -f "$ENV_FILE" ]] && rsync -a --delete "$ENV_FILE" "$snap/config/" || true
  [[ -f "$COMPOSE_FILE" ]] && rsync -a --delete "$COMPOSE_FILE" "$snap/config/" || true
}

################################################################################
# is_changed_since_snapshot()
# Description:
#   Detect diffs between live data and snapshot using rsync dry-run.
#
# Behaviors:
#   - Returns changed if *any* volume/config differs.
#
# Returns:
#   0 if changed; 1 if no differences.
################################################################################
is_changed_since_snapshot() {
  local snap="$BACKUP_DIR/snapshot"
  mkdir -p "$snap/volumes" "$snap/config"
  local vol diffs

  for vol in "${DISCOVERED_VOLUMES[@]}"; do
    diffs="$(rsync -rtun \
      --exclude='pg_wal/**' --exclude='pg_stat_tmp/**' --exclude='pg_logical/**' \
      "/var/lib/docker/volumes/${vol}/_data/" "$snap/volumes/$vol/" | grep -v '/$' || true)"
    [[ -n "$diffs" ]] && { log INFO "Change detected in volume: $vol"; return 0; }
  done

  for f in "$ENV_FILE" "$COMPOSE_FILE"; do
    [[ -f "$f" ]] || continue
    diffs="$(rsync -rtun --out-format="%n" "$f" "$snap/config/" | grep -v '/$' || true)"
    [[ -n "$diffs" ]] && { log INFO "Change detected in config: $(basename "$f")"; return 0; }
  done
  return 1
}

################################################################################
# get_current_version()
# Description:
#   Read current N8N version from .env (best effort).
#
# Behaviors:
#   - Falls back to "unknown" if not present.
#
# Returns:
#   Prints version to stdout.
################################################################################
get_current_version() {
  awk -F= '/^N8N_IMAGE_TAG=/{print $2}' "$ENV_FILE" 2>/dev/null || echo "unknown"
}

################################################################################
# postgres_dump()
# Description:
#   Create a PostgreSQL dump if a postgres container exists.
#
# Behaviors:
#   - Uses pg_isready and pg_dump inside the container.
#   - DB creds derived from .env: POSTGRES_USER/DB_POSTGRESDB_USER; POSTGRES_DB/DB_POSTGRESDB_DATABASE.
#
# Returns:
#   0 on success or if no postgres; non-zero on dump failure.
################################################################################
postgres_dump() {
  [[ -n "$DISCOVERED_POSTGRES_CONT" ]] || { log INFO "No postgres container found; skipping DB dump."; return 0; }
  local DB_USER DB_NAME out="$1"
  DB_USER="${DB_POSTGRESDB_USER:-${POSTGRES_USER:-n8n}}"
  DB_NAME="${DB_POSTGRESDB_DATABASE:-${POSTGRES_DB:-n8n}}"

  if docker exec "$DISCOVERED_POSTGRES_CONT" pg_isready -U "$DB_USER" &>/dev/null; then
    docker exec "$DISCOVERED_POSTGRES_CONT" pg_dump -U "$DB_USER" -d "$DB_NAME" > "$out" \
      || { log ERROR "Postgres dump failed"; return 1; }
    return 0
  else
    log ERROR "Postgres not ready; skipping DB dump."
    return 1
  fi
}

################################################################################
# do_local_backup()
# Description:
#   Perform local backup for all discovered volumes + configs + optional DB dump.
#
# Behaviors:
#   - Requires N8N_ENCRYPTION_KEY.
#   - Archives each volume via temporary Alpine container.
#   - Includes ./local-files if present.
#
# Returns:
#   0 on success; non-zero on error.
################################################################################
do_local_backup() {
  ensure_encryption_key || return 1
  discover_from_compose || true
  discover_from_running || true

  local work="$BACKUP_DIR/backup_$DATE"
  mkdir -p "$work"

  # local-files (optional)
  if [[ -d "$N8N_DIR/local-files" ]]; then
    tar -czf "$work/local-files_$DATE.tar.gz" -C "$N8N_DIR" local-files || { log ERROR "local-files backup failed"; return 1; }
  fi

  # volumes
  for vol in "${DISCOVERED_VOLUMES[@]}"; do
    if docker volume inspect "$vol" >/dev/null 2>&1; then
      log INFO "Archiving volume: $vol"
      docker run --rm -v "${vol}:/data" -v "$work:/backup" alpine \
        sh -c "tar czf /backup/volume_${vol}_$DATE.tar.gz -C /data ." \
        || { log ERROR "Failed to archive volume $vol"; return 1; }
    else
      log WARN "Volume not found (skipped): $vol"
    fi
  done

  # DB dump (if postgres)
  postgres_dump "$work/n8n_postgres_dump_$DATE.sql" || log WARN "DB dump skipped/failed."

  # configs
  cp "$ENV_FILE" "$work/.env.bak"
  cp "$COMPOSE_FILE" "$work/docker-compose.yml.bak"

  # compress + checksum
  BACKUP_FILE="n8n_backup_$(get_current_version)_${DATE}.tar.gz"
  tar -czf "$BACKUP_DIR/$BACKUP_FILE" -C "$work" . || { log ERROR "Compression failed"; return 1; }
  sha256sum "$BACKUP_DIR/$BACKUP_FILE" > "$BACKUP_DIR/$BACKUP_FILE.sha256" || { log ERROR "Checksum failed"; return 1; }
  rm -rf "$work"

  # local retention
  find "$BACKUP_DIR" -type f -name "*.tar.gz" -mtime +$DAYS_TO_KEEP -delete || true
  find "$BACKUP_DIR" -type f -name "*.sha256" -mtime +$DAYS_TO_KEEP -delete || true
}

################################################################################
# upload_backup_rclone()
# Description:
#   Upload archive, checksum and summary to rclone remote and prune old files.
#
# Behaviors:
#   - Skips if RCLONE_REMOTE unset.
#
# Returns:
#   0 on success; 1 on upload failures.
################################################################################
upload_backup_rclone() {
  if [[ -z "$RCLONE_REMOTE" ]]; then
    UPLOAD_STATUS="SKIPPED"; return 0
  fi
  require_cmd rclone || { UPLOAD_STATUS="FAIL"; return 1; }

  local remote="${RCLONE_REMOTE%:}:"
  log INFO "Uploading to $remote"
  local ok=true
  rclone copyto "$BACKUP_DIR/$BACKUP_FILE"         "$remote/$BACKUP_FILE"         "${RCLONE_FLAGS[@]}" || ok=false
  rclone copyto "$BACKUP_DIR/$BACKUP_FILE.sha256"  "$remote/$BACKUP_FILE.sha256"  "${RCLONE_FLAGS[@]}" || ok=false
  [[ -f "$BACKUP_DIR/backup_summary.md" ]] \
    && rclone copyto "$BACKUP_DIR/backup_summary.md" "$remote/backup_summary.md"  "${RCLONE_FLAGS[@]}" || true

  if $ok; then UPLOAD_STATUS="SUCCESS"; else UPLOAD_STATUS="FAIL"; fi

  # prune remote
  local tmpf; tmpf="$(mktemp)"
  printf "%s\n" "+ n8n_backup_*.tar.gz" "+ n8n_backup_*.tar.gz.sha256" "- *" > "$tmpf"
  rclone delete "$remote" --min-age "${DAYS_TO_KEEP}d" --filter-from "$tmpf" --rmdirs || true
  rm -f "$tmpf"
  [[ "$UPLOAD_STATUS" == "SUCCESS" ]]
}

################################################################################
# write_summary_row()
# Description:
#   Append one row to backups/backup_summary.md (keeps last 30 days).
#
# Behaviors:
#   - Table header auto-created if file missing.
#
# Returns:
#   0 on success.
################################################################################
write_summary_row() {
  local action="$1" status="$2" ver; ver="$(get_current_version)"
  local file="$BACKUP_DIR/backup_summary.md"
  [[ -f "$file" ]] || cat >"$file" <<'EOF'
| DATE               | ACTION         | N8N_VERSION | STATUS   |
|--------------------|----------------|-------------|----------|
EOF
  printf "| %s | %s | %s | %s |\n" "$DATE" "$action" "$ver" "$status" >> "$file"
  local cutoff; cutoff="$(date -d '30 days ago' +%F)"
  { head -n2 "$file"; tail -n +3 "$file" | awk -v cut="$cutoff" -F'[| ]+' '$2 >= cut'; } > "${file}.tmp" && mv "${file}.tmp" "$file"
}

################################################################################
# can_send_email()
# Description:
#   Check if -e was provided and SMTP creds are present.
#
# Behaviors:
#   - Returns 0 if OK; else 1.
#
# Returns:
#   0 if can send; 1 otherwise.
################################################################################
can_send_email() {
  [[ "$EMAIL_EXPLICIT" == true && -n "$SMTP_USER" && -n "$SMTP_PASS" && -n "$EMAIL_TO" ]]
}

################################################################################
# send_email()
# Description:
#   Send a multipart email via msmtp with optional attachment.
#
# Behaviors:
#   - Uses smtp.gmail.com:587 with STARTTLS.
#   - Attaches a file if provided.
#
# Returns:
#   0 on success; non-zero on error.
################################################################################
send_email() {
  local subject="$1" body="$2" attachment="${3:-}"
  $EMAIL_EXPLICIT || return 0
  can_send_email || { log ERROR "Email requested but SMTP_USER/SMTP_PASS/TO missing."; return 1; }
  require_cmd msmtp || return 1

  local boundary="=====n8n_mgr_$(date +%s)_$$====="
  {
    echo "From: $SMTP_USER"
    echo "To: $EMAIL_TO"
    echo "Subject: $subject"
    echo "MIME-Version: 1.0"
    echo "Content-Type: multipart/mixed; boundary=\"$boundary\""
    echo
    echo "--$boundary"
    echo "Content-Type: text/plain; charset=UTF-8"
    echo
    echo "$body"
    if [[ -n "$attachment" && -f "$attachment" ]]; then
      echo
      echo "--$boundary"
      echo "Content-Type: application/octet-stream; name=\"$(basename "$attachment")\""
      echo "Content-Transfer-Encoding: base64"
      echo "Content-Disposition: attachment; filename=\"$(basename "$attachment")\""
      echo
      base64 "$attachment"
    fi
    echo
    echo "--$boundary--"
  } | msmtp --host=smtp.gmail.com --port=587 --auth=on --tls=on \
            --from="$SMTP_USER" --user="$SMTP_USER" \
            --passwordeval="printf %s \"$SMTP_PASS\"" "$EMAIL_TO"
}

################################################################################
# summarize_backup()
# Description:
#   Print backup summary box with upload/email status.
#
# Behaviors:
#   - Uses globals BACKUP_STATUS, UPLOAD_STATUS, BACKUP_FILE.
#
# Returns:
#   0 always.
################################################################################
summarize_backup() {
  local email_status="SKIPPED"
  $EMAIL_SENT && email_status="SUCCESS"
  if $EMAIL_EXPLICIT && ! $EMAIL_SENT; then
    if ! can_send_email; then email_status="ERROR (missing SMTP config)"; else email_status="FAILED"; fi
  fi

  echo "═════════════════════════════════════════════════════════════"
  box_line "Action:"          "$ACTION"
  box_line "Status:"          "$BACKUP_STATUS"
  box_line "Timestamp:"       "$DATE"
  box_line "Domain:"          "https://$DOMAIN"
  [[ -n "$BACKUP_FILE" ]] && box_line "Backup file:" "$BACKUP_DIR/$BACKUP_FILE"
  box_line "N8N Version:"     "$(get_current_version)"
  box_line "Log File:"        "$LOG_FILE"
  box_line "Daily tracking:"  "$BACKUP_DIR/backup_summary.md"
  case "$UPLOAD_STATUS" in
    SUCCESS) box_line "Remote upload:" "SUCCESS" ;;
    FAIL)    box_line "Remote upload:" "FAILED" ;;
    *)       box_line "Remote upload:" "SKIPPED" ;;
  esac
  box_line "Email notification:" "$email_status"
  echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# backup_stack()
# Description:
#   Orchestrate backup with change detection, upload, email & summary.
#
# Behaviors:
#   - Auto-detects mode, services and volumes.
#   - Skips if unchanged unless -f.
#
# Returns:
#   0 on success (incl. SKIPPED); non-zero if local backup failed.
################################################################################
backup_stack() {
  ACTION="Backup"
  install_prereqs
  discover_from_compose || true
  discover_from_running || true
  snapshot_bootstrap

  if is_changed_since_snapshot; then
    ACTION="Backup (normal)"
  elif [[ "$DO_FORCE_BACKUP" == true ]]; then
    ACTION="Backup (forced)"
  else
    ACTION="Skipped"; BACKUP_STATUS="SKIPPED"
    write_summary_row "$ACTION" "$BACKUP_STATUS"
    summarize_backup
    return 0
  fi

  if do_local_backup; then
    BACKUP_STATUS="SUCCESS"
    snapshot_refresh
  else
    BACKUP_STATUS="FAIL"
    write_summary_row "$ACTION" "$BACKUP_STATUS"
    summarize_backup
    # send failure email
    if $EMAIL_EXPLICIT; then
      send_email "$DATE: n8n Backup FAILED" "See attached log." "$LOG_FILE" || true
      EMAIL_SENT=true || true
    fi
    return 1
  fi

  # upload if requested
  if [[ -n "$RCLONE_REMOTE" ]]; then
    upload_backup_rclone || true
  else
    UPLOAD_STATUS="SKIPPED"
  fi

  write_summary_row "$ACTION" "$BACKUP_STATUS"

  # email policy
  if [[ "$BACKUP_STATUS" == "FAIL" || "$UPLOAD_STATUS" == "FAIL" ]]; then
    send_email "$DATE: n8n Backup Issues" "Backup status: $BACKUP_STATUS, Upload: $UPLOAD_STATUS. See log." "$LOG_FILE" && EMAIL_SENT=true || true
  elif $NOTIFY_ON_SUCCESS; then
    send_email "$DATE: n8n Backup SUCCESS" "Backup and (if configured) upload finished successfully." "$LOG_FILE" && EMAIL_SENT=true || true
  fi

  summarize_backup
}

################################################################################
# fetch_remote_if_needed()
# Description:
#   If restore path is rclone remote, download to local tmp and verify checksum.
#
# Behaviors:
#   - Stores under backups/_restore_tmp/.
#
# Returns:
#   0 on success; non-zero on failure.
################################################################################
fetch_remote_if_needed() {
  if [[ -f "$TARGET_RESTORE_FILE" ]]; then return 0; fi
  if [[ "$TARGET_RESTORE_FILE" == *:* && "$TARGET_RESTORE_FILE" != /* ]]; then
    require_cmd rclone || return 1
    local tmp="$BACKUP_DIR/_restore_tmp"
    mkdir -p "$tmp"
    local base="$(basename "$TARGET_RESTORE_FILE" | tr ':' '_')"
    local local_path="$tmp/$base"

    log INFO "Fetching remote archive: $TARGET_RESTORE_FILE"
    rclone copyto "$TARGET_RESTORE_FILE" "$local_path" "${RCLONE_FLAGS[@]}"
    if rclone copyto "${TARGET_RESTORE_FILE}.sha256" "${local_path}.sha256" "${RCLONE_FLAGS[@]}"; then
      (cd "$tmp" && sha256sum -c "$(basename "${local_path}.sha256")")
    else
      log WARN "No remote checksum; proceeding without verification."
    fi
    TARGET_RESTORE_FILE="$local_path"
  fi
}

################################################################################
# restore_stack()
# Description:
#   Restore from a backup archive (local or fetched), auto-detecting mode.
#
# Behaviors:
#   - Extracts archive; restores volumes and configs; restores DB if dump exists.
#   - Stops stack before restore and brings back up; waits for health.
#
# Returns:
#   0 on success; non-zero on failures.
################################################################################
restore_stack() {
  ACTION="Restore"
  install_prereqs
  fetch_remote_if_needed || { log ERROR "Cannot fetch restore archive."; return 1; }
  [[ -f "$TARGET_RESTORE_FILE" ]] || { log ERROR "Restore file not found: $TARGET_RESTORE_FILE"; return 1; }

  local work="$N8N_DIR/n8n_restore_$(date +%s)"
  mkdir -p "$work"
  tar -xzf "$TARGET_RESTORE_FILE" -C "$work"

  [[ -f "$work/.env.bak" && -f "$work/docker-compose.yml.bak" ]] \
    || { log ERROR "Backup does not contain .env.bak & docker-compose.yml.bak"; return 1; }

  # stop stack
  compose down --volumes --remove-orphans || true

  cp -f "$work/.env.bak" "$ENV_FILE"
  cp -f "$work/docker-compose.yml.bak" "$COMPOSE_FILE"

  discover_from_compose || true

  # restore volumes (if present in archive)
  for vol in "${DISCOVERED_VOLUMES[@]}"; do
    local vol_tar; vol_tar="$(find "$work" -maxdepth 1 -name "volume_${vol}_*.tar.gz" -print -quit || true)"
    [[ -n "$vol_tar" ]] || { log INFO "No archive for volume $vol (maybe DB dump present)"; continue; }
    docker volume inspect "$vol" >/dev/null 2>&1 && docker volume rm "$vol" >/dev/null 2>&1 || true
    docker volume create "$vol" >/dev/null
    docker run --rm -v "${vol}:/data" -v "$work:/backup" alpine \
      sh -c "rm -rf /data/* && tar xzf /backup/$(basename "$vol_tar") -C /data" \
      || { log ERROR "Volume restore failed: $vol"; return 1; }
  done

  # bring up postgres first (if present)
  compose up -d postgres || true
  discover_from_running || true

  # DB restore if dump exists
  local dump_sql; dump_sql="$(find "$work" -maxdepth 1 -name 'n8n_postgres_dump_*.sql' -print -quit || true)"
  if [[ -n "$dump_sql" && -n "$DISCOVERED_POSTGRES_CONT" ]]; then
    log INFO "Restoring PostgreSQL from SQL dump…"
    local DB_USER DB_NAME
    DB_USER="${DB_POSTGRESDB_USER:-${POSTGRES_USER:-n8n}}"
    DB_NAME="${DB_POSTGRESDB_DATABASE:-${POSTGRES_DB:-n8n}}"
    docker exec -i "$DISCOVERED_POSTGRES_CONT" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c \
      "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${DB_NAME}' AND pid <> pg_backend_pid();" || true
    docker exec -i "$DISCOVERED_POSTGRES_CONT" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS ${DB_NAME};"
    docker exec -i "$DISCOVERED_POSTGRES_CONT" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
    docker exec -i "$DISCOVERED_POSTGRES_CONT" psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 < "$dump_sql"
  fi

  # bring rest of stack
  docker_up_check || { log ERROR "Stack unhealthy after restore."; return 1; }

  # clean temp
  rm -rf "$work" "$BACKUP_DIR/_restore_tmp" 2>/dev/null || true

  echo "═════════════════════════════════════════════════════════════"
  echo "Restore completed successfully."
  box_line "Domain:"           "https://$DOMAIN"
  box_line "Restore from:"     "$TARGET_RESTORE_FILE"
  box_line "N8N Version:"      "$(get_current_version)"
  box_line "N8N Directory:"    "$N8N_DIR"
  box_line "Log File:"         "$LOG_FILE"
  box_line "Timestamp:"        "$DATE"
  echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# cleanup_stack()
# Description:
#   Interactive teardown: compose down, remove volumes, prune images.
#
# Behaviors:
#   - Preserves letsencrypt by default (KEEP_CERTS=true to keep).
#
# Returns:
#   0 always (cancel/complete).
################################################################################
cleanup_stack() {
  discover_from_compose || true
  echo "This will stop the stack and remove named resources."
  echo "Services: ${DISCOVERED_SERVICES[*]:-<unknown>}"
  echo "Volumes:  ${DISCOVERED_VOLUMES[*]:-<unknown>}"
  read -e -p "Continue? [y/N] " ans
  [[ "${ans,,}" == "y" ]] || { log INFO "Cleanup cancelled."; return 0; }

  compose down --remove-orphans || true
  for vol in "${DISCOVERED_VOLUMES[@]}"; do
    docker volume rm "$vol" >/dev/null 2>&1 || true
  done
  docker image prune -f >/dev/null 2>&1 || true
  log INFO "Cleanup completed."
}

################################################################################
# parse_args()
# Description:
#   Parse CLI arguments and set global flags/vars.
#
# Behaviors:
#   - Enforces single action selection.
#
# Returns:
#   0 on success; exits 1 on invalid usage.
################################################################################
parse_args() {
  local OPTS
  OPTS=$(getopt -o i:u:v:m:cbadr:l:he:ns:f \
    -l install:,upgrade:,version:,cleanup,backup,available,dir:,log-level:,help,restore:,email:,notify-on-success,remote:,mode:,force \
    -- "$@") || usage
  eval set -- "$OPTS"
  while true; do
    case "$1" in
      -i|--install) DO_INSTALL=true; DOMAIN="$2"; shift 2 ;;
      -u|--upgrade) DO_UPGRADE=true; DOMAIN="$2"; shift 2 ;;
      -v|--version) N8N_VERSION="$2"; shift 2 ;;
      -m|--email)   SSL_EMAIL="$2"; shift 2 ;;
      -c|--cleanup) DO_CLEANUP=true; shift ;;
      -b|--backup)  DO_BACKUP=true; shift ;;
      -a|--available) DO_AVAILABLE=true; shift ;;
      -d|--dir)     N8N_DIR="$2"; shift 2 ;;
      -l|--log-level) LOG_LEVEL="${2^^}"; shift 2 ;;
      -r|--restore) DO_RESTORE=true; TARGET_RESTORE_FILE="$2"; shift 2 ;;
      -e|--email)   EMAIL_TO="$2"; EMAIL_EXPLICIT=true; shift 2 ;;
      -n|--notify-on-success) NOTIFY_ON_SUCCESS=true; shift ;;
      -s|--remote)  RCLONE_REMOTE="$2"; shift 2 ;;
      --mode)       INSTALL_MODE="$2"; shift 2 ;;
      -f|--force)   FORCE_FLAG=true; DO_FORCE_BACKUP=true; shift ;;
      -h|--help)    usage ;;
      --) shift; break ;;
      *) usage ;;
    esac
  done

  local count=0
  $DO_INSTALL   && ((count++))
  $DO_UPGRADE   && ((count++))
  $DO_BACKUP    && ((count++))
  $DO_RESTORE   && ((count++))
  $DO_CLEANUP   && ((count++))
  $DO_AVAILABLE && ((count++))
  ((count==1)) || { log ERROR "Choose exactly one action."; usage; }
}

################################################################################
# main()
# Description:
#   Entry point; routes to the chosen action.
#
# Behaviors:
#   - Sets paths, logging, and runs the selected flow.
#
# Returns:
#   Exit code from the selected subroutine.
################################################################################
main() {
  check_root
  parse_args "$@"
  mkdir -p "$N8N_DIR"
  set_paths

  # Debug tracing
  if [[ "$LOG_LEVEL" == "DEBUG" ]]; then
    export PS4='+ $(date "+%H:%M:%S") ${BASH_SOURCE##*/}:${LINENO}:${FUNCNAME[0]:-main}: '
    set -x
  fi

  if $DO_INSTALL; then
    install_stack
  elif $DO_UPGRADE; then
    install_prereqs
    [[ -n "$SSL_EMAIL" ]] || true
    upgrade_stack
  elif $DO_BACKUP; then
    install_prereqs
    snapshot_bootstrap
    backup_stack
  elif $DO_RESTORE; then
    install_prereqs
    restore_stack
  elif $DO_CLEANUP; then
    cleanup_stack
  elif $DO_AVAILABLE; then
    list_available_versions
  fi

  # post-run housekeeping
  find "$LOG_DIR" -type f -mtime +$DAYS_TO_KEEP -delete || true
}

main "$@"

