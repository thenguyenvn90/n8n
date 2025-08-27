#!/bin/bash
set -euo pipefail
set -o errtrace
IFS=$'\n\t'

#############################################################################################
# N8N Installation, Upgrade, Backup & Restore Manager (with Google Drive upload via rclone)
# Author:      TheNguyen
# Email:       thenguyen.ai.automation@gmail.com
# Version:     2.1.0
# Date:        2025-08-27
#
# Description:
#   A unified management tool for installing, upgrading, backing up, and restoring the
#   n8n automation stack running on Docker Compose with Traefik + Let's Encrypt.
#
# Key features:
#   - Install / Upgrade:
#       * Validates domain DNS resolution
#       * Installs Docker & Compose v2 if missing
#       * Creates persistent Docker volumes
#       * Starts stack and checks container health + TLS certificate (Traefik/LE)
#       * Forces upgrade/downgrade with -f
#       * Cleanup (optional) of containers/volumes
#   - Backup / Restore:
#       * Full local backup of Docker volumes, PostgreSQL dump, and configs
#       * Change detection snapshot to skip redundant backups (use -f to force)
#       * Rolling 30-day Markdown summary (backup_summary.md)
#       * Optional email notifications via Gmail SMTP (msmtp)
#       * Optional upload to Google Drive (or any rclone remote)
#       * Restore from local archive or rclone remote path (remote:folder/file.tar.gz)
#############################################################################################

# Load common helpers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/n8n_common.sh"

trap 'on_interrupt' INT TERM HUP
trap 'log INFO "Exiting (code $?)"' EXIT
trap 'on_error' ERR

# ------------------------------- Globals -------------------------------------
INSTALL=false
UPGRADE=false
CLEANUP=false
LIST_VERSIONS=false

# Backup/Restore actions
DO_BACKUP=false
DO_RESTORE=false
DO_FORCE=false
TARGET_RESTORE_FILE=""

FORCE_UPGRADE=false
LOG_LEVEL="${LOG_LEVEL:-INFO}"
TARGET_DIR=""
N8N_VERSION="latest"
DOMAIN=""
VOLUMES=("n8n-data" "postgres-data" "letsencrypt")

# Email options (msmtp)
NOTIFY_ON_SUCCESS=false
SMTP_USER="${SMTP_USER:-}"
SMTP_PASS="${SMTP_PASS:-}"
EMAIL_TO=""
EMAIL_EXPLICIT=false
EMAIL_SENT=false

# rclone (Google Drive) – optional
RCLONE_REMOTE=""   # e.g., gdrive-user:/n8n-backups  OR gdrive-user:
RCLONE_FLAGS=(--transfers=4 --checkers=8 --retries=5 --low-level-retries=10 --contimeout=30s --timeout=5m --retries-sleep=10s)

# Paths & context (set later)
DEFAULT_N8N_DIR="/home/n8n"
N8N_DIR=""
ENV_FILE=""
COMPOSE_FILE=""
LOG_FILE=""
BACKUP_DIR=""
LOG_DIR=""
DATE=""
ACTION=""
BACKUP_STATUS=""
UPLOAD_STATUS=""
BACKUP_FILE=""
DRIVE_LINK=""

# Retention
DAYS_TO_KEEP=7

################################################################################
# usage()
# Description:
#   Displays script usage/help information when incorrect or no arguments are passed.
#
# Behaviors:
#   - Includes Install/Upgrade actions and Backup/Restore actions in one guide.
#
# Returns:
#   Exits 1.
################################################################################
usage() {
    cat <<EOF
Usage: $0 [ONE ACTION] [OPTIONS]

Actions (choose exactly one):
  -a, --available
        List available n8n versions

  -i, --install <DOMAIN>
        Install n8n stack to given domain (Traefik + Let's Encrypt)
        Use -v|--version to specify an n8n version

  -u, --upgrade <DOMAIN>
        Upgrade (or force redeploy/downgrade with -f) the n8n stack
        Use -v|--version to specify an n8n version

  -c, --cleanup
        Tear down the stack and remove named resources (volumes, etc.)

  -b, --backup
        Perform a local backup (volumes + Postgres dump + configs)
        Skips if no changes since last snapshot unless -f is provided

  -r, --restore <FILE_OR_REMOTE>
        Restore from local archive (.tar.gz) or rclone remote (e.g. gdrive:folder/file.tar.gz)

General Options:
  -v, --version <N8N_VERSION>
        Version to install/upgrade (default: latest stable)

  -m, --email <SSL_EMAIL>
        Email address for Let's Encrypt registration (install/upgrade)

  -d, --dir <TARGET_DIR>
        n8n project directory (default: /home/n8n)

  -l, --log-level <LEVEL>
        DEBUG, INFO (default), WARN, ERROR

Backup/Restore Options:
  -e, --email <TO_ADDRESS>
        Send email notifications (requires SMTP_USER/SMTP_PASS env)

  -n, --notify-on-success
        Also email on successful backup/restore (by default only failures email)

  -s, --remote-name <RCLONE_REMOTE>
        rclone remote root (e.g. gdrive-user or gdrive-user:/n8n-backups)
        If set, uploads backup + checksum + backup_summary.md and prunes old remote files

  -f, --force
        Backup: force even if no changes
        Upgrade: allow downgrade or same-version redeploy

  -h, --help
        Show this help

Examples:
  $0 -a
  $0 -i n8n.example.com -m you@example.com
  $0 -u n8n.example.com -f -v 1.107.2
  $0 -b -d /home/n8n -s gdrive-user:/n8n-backups -e ops@example.com --notify-on-success
  $0 -r gdrive-user:/n8n-backups/n8n_backup_1.107.2_2025-08-27_12-30-00.tar.gz
EOF
    exit 1
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

    if [[ -z "$resolver" ]]; then
        log WARN "Cannot verify DNS -> continuing; Let's Encrypt may fail if DNS is wrong."
        return 0
    fi

    if echo "$domain_ips" | tr ' ' '\n' | grep -Fxq "$server_ip"; then
        log INFO "Domain $DOMAIN is correctly pointing to this server."
    else
        log ERROR "Domain $DOMAIN is NOT pointing to this server."
        log INFO  "Please update your DNS A record to: $server_ip"
        exit 1
    fi
}

################################################################################
# get_user_email()
# Description:
#   Prompt the operator for a valid email for Let's Encrypt registration.
#
# Behaviors:
#   - Re-prompts until input matches a simple RFC-ish email regex.
#   - Exports SSL_EMAIL on success.
#
# Returns:
#   0 when SSL_EMAIL exported.
################################################################################
get_user_email() {
    while true; do
        read -e -p "Enter your email address (used for SSL cert): " SSL_EMAIL
        if [[ "$SSL_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            export SSL_EMAIL
            break
        else
            log ERROR "Invalid email. Please try again."
        fi
    done
}

################################################################################
# list_available_versions()
# Description:
#   Context-aware listing of n8n versions from Docker Hub.
#
# Behaviors:
#   - If n8n is running: lists versions newer than current.
#   - If not running: lists top 5 latest stable versions.
#   - Uses fetch_all_stable_versions() from n8n_common.sh.
#
# Returns:
#   0 on success; 1 if tags cannot be fetched.
################################################################################
list_available_versions() {
    if ! command -v jq >/dev/null 2>&1; then
        log INFO "jq not found; installing..."
        apt-get update -y && apt-get install -y --no-install-recommends jq
    fi

    local current_version has_running=false
    current_version="$(get_current_n8n_version 2>/dev/null || true)"
    [[ "$current_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && has_running=true

    log INFO "Fetching tags from Docker Hub…"
    local all_versions
    all_versions="$(fetch_all_stable_versions)"

    if [[ -z "$all_versions" ]]; then
        log ERROR "Could not fetch version list."
        return 1
    fi

    if $has_running; then
        log INFO "Current n8n version: $current_version"
        echo "═════════════════════════════════════════════════════════════"
        local newer
        newer="$(printf "%s\n%s\n" "$all_versions" "$current_version" \
                 | sort -V | awk -v c="$current_version" '$0==c{seen=1;next} seen')"
        if [[ -z "$newer" ]]; then
            echo "You are already on the latest detected version ($current_version)."
        else
            echo "Newer n8n versions than $current_version:"
            echo "$newer"
        fi
        echo "═════════════════════════════════════════════════════════════"
    else
        local top5
        top5="$(printf "%s\n" "$all_versions" | tail -n 5)"
        echo "═════════════════════════════════════════════════════════════"
        echo "Top 5 latest stable n8n versions:"
        echo "$top5"
        echo "═════════════════════════════════════════════════════════════"
    fi
}

################################################################################
# validate_image_tag()
# Description:
#   Check whether a given n8n tag exists in docker.n8n.io or docker.io.
#
# Behaviors:
#   - Uses `docker manifest inspect` against both registries.
#   - Logs INFO about the tag being validated.
#
# Returns:
#   0 if tag exists in either registry; 1 otherwise.
################################################################################
validate_image_tag() {
    local tag="$1"
    log INFO "Validate if n8n version '$tag' is available."
    docker manifest inspect "docker.n8n.io/n8nio/n8n:${tag}" >/dev/null 2>&1 && return 0
    docker manifest inspect "docker.io/n8nio/n8n:${tag}"  >/dev/null 2>&1 && return 0
    return 1
}

################################################################################
# create_volumes()
# Description:
#   Ensure required named Docker volumes exist.
#
# Behaviors:
#   - Creates any missing volumes listed in global VOLUMES[].
#   - Prints a `docker volume ls` summary.
#
# Returns:
#   0 always.
################################################################################
create_volumes() {
    log INFO "Creating Docker volumes..."
    for vol in "${VOLUMES[@]}"; do
        if docker volume inspect "$vol" >/dev/null 2>&1; then
            log INFO "Volume '$vol' already exists."
        else
            docker volume create "$vol" >/dev/null && log INFO "Created volume: $vol"
        fi
    done
    log INFO "Current Docker volumes:"; docker volume ls
}

################################################################################
# prepare_compose_file()
# Description:
#   Populate $N8N_DIR with compose/env, pin version, rotate secrets if needed.
#
# Behaviors:
#   - Copies docker-compose.yml and .env templates to $N8N_DIR (backups old).
#   - Sets DOMAIN, SSL_EMAIL in .env.
#   - Resolves target version (explicit or latest stable).
#   - Validates image tag and writes N8N_IMAGE_TAG.
#   - Ensures STRONG_PASSWORD and N8N_ENCRYPTION_KEY exist (rotate if defaults).
#   - Secures file permissions.
#
# Returns:
#   0 on success; exits non-zero on fatal validation errors.
################################################################################
prepare_compose_file() {
    local compose_template="$PWD/docker-compose.yml"
    local env_template="$PWD/.env"
    local compose_file="$COMPOSE_FILE"
    local env_file="$ENV_FILE"

    [[ -f "$compose_template" ]] || { log ERROR "docker-compose.yml not found at $compose_template"; exit 1; }
    [[ -f "$env_template"     ]] || { log ERROR ".env not found at $env_template"; exit 1; }

    if [[ "$compose_template" != "$compose_file" ]]; then
        [[ -f "$compose_file" ]] && cp -a "$compose_file" "${compose_file}.bak.$(date +%F_%H-%M-%S)"
        cp -a "$compose_template" "$compose_file"
    fi
    if [[ "$env_template" != "$env_file" ]]; then
        [[ -f "$env_file" ]] && cp -a "$env_file" "${env_file}.bak.$(date +%F_%H-%M-%S)"
        cp -a "$env_template" "$env_file"
    fi

    log INFO "Updating .env with DOMAIN, SSL_EMAIL and N8N_IMAGE_TAG…"
    upsert_env_var "DOMAIN" "$DOMAIN" "$env_file"
    [[ -n "${SSL_EMAIL:-}" ]] && upsert_env_var "SSL_EMAIL" "$SSL_EMAIL" "$env_file"

    local target_version="${N8N_VERSION}"
    if [[ -z "$target_version" || "$target_version" == "latest" ]]; then
        target_version="$(get_latest_n8n_version)"
        [[ -z "$target_version" ]] && { log ERROR "Could not determine latest n8n tag."; exit 1; }
    fi

    validate_image_tag "$target_version" || { log ERROR "Image tag not found: $target_version"; exit 1; }
    upsert_env_var "N8N_IMAGE_TAG" "$target_version" "$env_file"

    local pw; pw=$(awk -F= '/^STRONG_PASSWORD=/{print $2; found=1} END{if(!found) print ""}' "$env_file")
    if [[ -z "$pw" || "$pw" == "CHANGE_ME_BASE64_16_BYTES" ]]; then
        upsert_env_var "STRONG_PASSWORD" "$(openssl rand -base64 16)" "$env_file"
    fi

    local ek; ek=$(awk -F= '/^N8N_ENCRYPTION_KEY=/{print $2; found=1} END{if(!found) print ""}' "$env_file")
    if [[ -z "$ek" || "$ek" == "CHANGE_ME_BASE64_32_BYTES" ]]; then
        upsert_env_var "N8N_ENCRYPTION_KEY" "$(openssl rand -base64 32)" "$env_file"
    fi

    chmod 600 "$env_file" 2>/dev/null || true
    chmod 640 "$compose_file" 2>/dev/null || true
}

################################################################################
# install_docker()
# Description:
#   Install Docker Engine and Compose v2 on Ubuntu with safe fallbacks.
#
# Behaviors:
#   - Installs Docker from Docker repo (fallback: get.docker.com).
#   - Installs jq, rsync, tar, msmtp, dnsutils, openssl, rclone, etc.
#   - Enables docker via systemd and adds user to docker group.
#
# Returns:
#   0 on success; non-zero on unexpected failures.
################################################################################
install_docker() {
    if command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1; then
        log INFO "Docker already installed."
    else
        log INFO "Installing prerequisites (curl, ca-certificates, gpg, lsb-release)..."
        apt-get update -y
        apt-get install -y --no-install-recommends ca-certificates curl gnupg lsb-release
        log INFO "Adding Docker repo..."
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor | tee /etc/apt/keyrings/docker.gpg >/dev/null
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
          | tee /etc/apt/sources.list.d/docker.list >/dev/null
        apt-get update -y
        if ! apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
            log WARN "APT install failed; using get.docker.com script…"
            curl -fsSL https://get.docker.com | sh
        fi
    fi
    log INFO "Installing utilities (jq vim rsync tar msmtp dnsutils openssl rclone)…"
    apt-get install -y --no-install-recommends jq vim rsync tar msmtp dnsutils openssl rclone
    command -v systemctl >/dev/null 2>&1 && systemctl enable --now docker || true
    local CURRENT_USER=${SUDO_USER:-$(whoami)}
    usermod -aG docker "$CURRENT_USER" || true
}

################################################################################
# print_summary_message()
# Description:
#   Print a human-friendly final summary after install/upgrade.
#
# Behaviors:
#   - Shows domain URL, version, timestamp, user, target dir, and log path.
#
# Returns:
#   0 always.
################################################################################
print_summary_message() {
    load_env_file
    echo "═════════════════════════════════════════════════════════════"
    if [[ "$INSTALL" == true ]]; then
        echo "N8N has been successfully installed!"
    elif [[ "$UPGRADE" == true ]]; then
        echo "N8N has been successfully upgraded!"
    fi
    echo "Domain:             https://${DOMAIN}"
    echo "Installed Version:  $(get_current_n8n_version)"
    echo "Install Timestamp:  $(date "+%Y-%m-%d %H:%M:%S")"
    echo "Installed By:       ${USER:-unknown}"
    echo "Target Directory:   $N8N_DIR"
    echo "SSL Email:          ${SSL_EMAIL:-N/A}"
    echo "Execution log:      ${LOG_FILE}"
    echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# install_n8n()
# Description:
#   Orchestrate a fresh installation of the n8n stack.
#
# Behaviors:
#   - Prompts for SSL_EMAIL; validates DNS; installs Docker.
#   - Prepares compose/env; validates; creates volumes; starts stack.
#   - Health-checks containers and TLS; prints summary.
#
# Returns:
#   0 on success; exits non-zero on failures.
################################################################################
install_n8n() {
    log INFO "Starting N8N installation for domain: $DOMAIN"
    [[ -z "${SSL_EMAIL:-}" ]] && get_user_email
    check_domain
    install_docker
    prepare_compose_file
    validate_compose_and_env
    create_volumes
    docker_compose_up
    check_services_up_running || { log ERROR "Stack unhealthy after install."; exit 1; }
    print_summary_message
}

################################################################################
# upgrade_n8n()
# Description:
#   Upgrade (or force redeploy/downgrade with -f) the running n8n stack.
#
# Behaviors:
#   - Computes target version (explicit or latest); prevents downgrade unless -f.
#   - Validates image tag; updates .env; brings stack down, then up.
#   - Health-checks containers and TLS; prints summary.
#
# Returns:
#   0 on success; exits non-zero on failures.
################################################################################
upgrade_n8n() {
    log INFO "Checking current and target n8n versions..."
    cd "$N8N_DIR"
    load_env_file

    if ! command -v jq >/dev/null 2>&1; then
        apt-get update -y && apt-get install -y --no-install-recommends jq
    fi

    local current_version target_version
    current_version=$(get_current_n8n_version || echo "0.0.0")
    target_version="$N8N_VERSION"
    if [[ -z "$target_version" || "$target_version" == "latest" ]]; then
        target_version=$(get_latest_n8n_version)
        [[ -z "$target_version" ]] && { log ERROR "Could not determine latest n8n tag."; exit 1; }
    fi

    log INFO "Current: $current_version -> Target: $target_version"
    if [[ "$(printf "%s\n%s" "$target_version" "$current_version" | sort -V | head -n1)" == "$target_version" \
          && "$target_version" != "$current_version" \
          && "$FORCE_UPGRADE" != true ]]; then
        log INFO "Target <= current. Use -f to force downgrade."
        exit 0
    fi
    if [[ "$target_version" == "$current_version" && "$FORCE_UPGRADE" != true ]]; then
        log INFO "Already on $current_version. Use -f to force redeploy."
        exit 0
    fi

    validate_image_tag "$target_version" || { log ERROR "Image tag not found: $target_version"; exit 1; }
    upsert_env_var "N8N_IMAGE_TAG" "$target_version" "$N8N_DIR/.env"

    log INFO "Stopping and removing existing containers..."
    compose down

    validate_compose_and_env
    docker_compose_up
    check_services_up_running || { log ERROR "Stack unhealthy after upgrade."; exit 1; }
    print_summary_message
}

################################################################################
# cleanup_n8n()
# Description:
#   Interactively tear down the stack and remove named resources.
#
# Behaviors:
#   - Stops compose stack; removes volumes (keeps letsencrypt if KEEP_CERTS=true).
#   - Prunes images; optionally removes base images (REMOVE_IMAGES=true).
#
# Returns:
#   0 on completion/cancel; non-zero on unexpected errors.
################################################################################
cleanup_n8n() {
    local NETWORK_NAME="${NETWORK_NAME:-n8n-network}"
    local KEEP_CERTS="${KEEP_CERTS:-true}"
    local REMOVE_IMAGES="${REMOVE_IMAGES:-false}"

    log WARN "This will stop containers, remove the compose stack, and delete named resources."
    echo "Planned actions:"
    echo "  - docker compose down --remove-orphans"
    echo "  - Remove external volumes: ${VOLUMES[*]}  (letsencrypt kept: ${KEEP_CERTS})"
    echo "  - Remove docker network: ${NETWORK_NAME}"
    echo "  - Remove dangling images (docker image prune -f)"
    echo "  - Remove base images (n8nio/n8n, postgres): ${REMOVE_IMAGES}"
    echo
    read -e -p "Continue? [y/N] " ans
    [[ "${ans,,}" == "y" ]] || { log INFO "Cleanup cancelled."; return 0; }

    if [[ -f "$N8N_DIR/docker-compose.yml" ]]; then
        compose down --remove-orphans || true
    else
        docker compose down --remove-orphans || true
    fi

    log INFO "Removing related volumes..."
    for vol in "${VOLUMES[@]}"; do
        if [[ "$KEEP_CERTS" == "true" && "$vol" == "letsencrypt" ]]; then
            log INFO "Skipping volume '$vol' (KEEP_CERTS=true)"
            continue
        fi
        docker volume inspect "$vol" >/dev/null 2>&1 && docker volume rm "$vol" >/dev/null 2>&1 && log INFO "Removed: $vol" || true
    done

    log INFO "Pruning dangling images…"; docker image prune -f >/dev/null 2>&1 || true
    if [[ "$REMOVE_IMAGES" == "true" ]]; then
        log WARN "Removing base images (explicit request)"
        docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' \
          | grep -E '^(n8nio/n8n|docker\.n8n\.io/n8nio/n8n|postgres):' \
          | awk '{print $2}' | xargs -r docker rmi -f || true
    fi

    log INFO "Cleanup completed."
    [[ "$KEEP_CERTS" == "true" ]] && log INFO "Note: kept 'letsencrypt' volume."
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
# can_send_email()
# Description:
#   Check whether SMTP config is sufficient to send email.
#
# Behaviors:
#   - Verifies EMAIL_TO, SMTP_USER, SMTP_PASS are all non-empty.
#
# Returns:
#   0 if ok; 1 otherwise.
################################################################################
can_send_email() {
    [[ -n "$EMAIL_TO" && -n "$SMTP_USER" && -n "$SMTP_PASS" ]]
}

################################################################################
# send_email()
# Description:
#   Send a multipart email via Gmail SMTP (msmtp), optional attachment.
#
# Behaviors:
#   - No-op if -e/--email not provided.
#   - Uses STARTTLS to smtp.gmail.com:587.
#   - Attaches a file when path given and exists.
#
# Returns:
#   0 on success; non-zero if send fails.
################################################################################
send_email() {
    local subject="$1"
    local body="$2"
    local attachment="${3:-}"

    if ! $EMAIL_EXPLICIT; then return 0; fi
    if ! can_send_email; then
        log ERROR "Email requested (-e) but SMTP_USER/SMTP_PASS/EMAIL_TO not set."
        return 1
    fi

    log INFO "Sending email to: $EMAIL_TO"
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
      echo
      if [[ -n "$attachment" && -f "$attachment" ]]; then
        local filename; filename=$(basename "$attachment")
        echo "--$boundary"
        echo "Content-Type: application/octet-stream; name=\"$filename\""
        echo "Content-Transfer-Encoding: base64"
        echo "Content-Disposition: attachment; filename=\"$filename\""
        echo
        base64 "$attachment"
        echo
      fi
      echo "--$boundary--"
      local pass_tmp; pass_tmp="$(mktemp)"; printf '%s' "$SMTP_PASS" > "$pass_tmp"; chmod 600 "$pass_tmp"
    } | msmtp --host=smtp.gmail.com --port=587 --auth=on --tls=on \
              --from="$SMTP_USER" --user="$SMTP_USER" \
              --passwordeval="cat $pass_tmp" "$EMAIL_TO"
    local rc=$?; rm -f "$pass_tmp"
    if [[ $rc -eq 0 ]]; then EMAIL_SENT=true; log INFO "Email sent."; else log WARN "Email send failed."; fi
}

################################################################################
# handle_error_backup()
# Description:
#   Backup/restore ERR handler to write summary and notify.
#
# Behaviors:
#   - Writes a FAIL entry to backup_summary.md (best-effort).
#   - Emails a failure notification with log attached (best-effort).
#
# Returns:
#   Never returns (exits 1).
################################################################################
handle_error_backup() {
  write_summary "${ACTION:-Unknown}" "FAIL" || true
  log ERROR "Unhandled error. See ${LOG_FILE:-"(no log)"}"
  local attach=""; [[ -n "${LOG_FILE:-}" && -f "$LOG_FILE" ]] && attach="$LOG_FILE"
  send_email "${DATE:-$(date +%F_%H-%M-%S)}: n8n ${ACTION:-Backup} FAILED" \
             "An error occurred. See attached log." "$attach" || true
  exit 1
}

################################################################################
# initialize_snapshot()
# Description:
#   Create the initial snapshot tree for change detection.
#
# Behaviors:
#   - Rsyncs volumes and config files into BACKUP_DIR/snapshot/* on first run.
#
# Returns:
#   0 on success; non-zero on failure.
################################################################################
initialize_snapshot() {
    if [[ ! -d "$BACKUP_DIR/snapshot" ]]; then
        log INFO "Bootstrapping snapshot (first run)…"
        for vol in "${VOLUMES[@]}"; do
            mkdir -p "$BACKUP_DIR/snapshot/volumes/$vol"
            rsync -a "/var/lib/docker/volumes/${vol}/_data/" \
                  "$BACKUP_DIR/snapshot/volumes/$vol/"
        done
        mkdir -p "$BACKUP_DIR/snapshot/config"
        [[ -f "$N8N_DIR/.env" ]] && rsync -a "$N8N_DIR/.env" "$BACKUP_DIR/snapshot/config/"
        [[ -f "$N8N_DIR/docker-compose.yml" ]] && rsync -a "$N8N_DIR/docker-compose.yml" "$BACKUP_DIR/snapshot/config/"
        log INFO "Snapshot bootstrapped."
    fi
}

################################################################################
# refresh_snapshot()
# Description:
#   Update snapshot after a successful backup.
#
# Behaviors:
#   - Rsyncs (with --delete) live volumes into snapshot (excludes PG transient dirs).
#   - Rsyncs current .env and docker-compose.yml into snapshot/config.
#
# Returns:
#   0 on success; non-zero on failure.
################################################################################
refresh_snapshot() {
    log INFO "Updating snapshot to current state"
    for vol in "${VOLUMES[@]}"; do
        rsync -a --delete \
          --exclude='pg_wal/**' \
          --exclude='pg_stat_tmp/**' \
          --exclude='pg_logical/**' \
          "/var/lib/docker/volumes/${vol}/_data/" \
          "$BACKUP_DIR/snapshot/volumes/$vol/"
    done
    [[ -f "$N8N_DIR/.env" ]] && rsync -a --delete "$N8N_DIR/.env" "$BACKUP_DIR/snapshot/config/"
    [[ -f "$N8N_DIR/docker-compose.yml" ]] && rsync -a --delete "$N8N_DIR/docker-compose.yml" "$BACKUP_DIR/snapshot/config/"
    log INFO "Snapshot refreshed."
}

################################################################################
# is_system_changed()
# Description:
#   Determine if live data differs from the snapshot.
#
# Behaviors:
#   - Uses rsync dry-run on volumes and configs; any differences → "changed".
#
# Returns:
#   0 if changed; 1 if no differences.
################################################################################
is_system_changed() {
    local src dest diffs file vol
    for vol in "${VOLUMES[@]}"; do
        src="/var/lib/docker/volumes/${vol}/_data/"
        dest="$BACKUP_DIR/snapshot/volumes/${vol}/"
        mkdir -p "$dest"
        diffs=$(rsync -rtun \
                --exclude='pg_wal/**' \
                --exclude='pg_stat_tmp/**' \
                --exclude='pg_logical/**' \
                --out-format="%n" "$src" "$dest" | grep -v '/$') || true
        [[ -n "$diffs" ]] && { log INFO "Change detected in volume: $vol"; return 0; }
    done
    dest="$BACKUP_DIR/snapshot/config/"; mkdir -p "$dest"
    for file in .env docker-compose.yml; do
        if [[ -f "$N8N_DIR/$file" ]]; then
            diffs=$(rsync -rtun --out-format="%n" "$N8N_DIR/$file" "$dest" | grep -v '/$') || true
            [[ -n "$diffs" ]] && { log INFO "Change detected in config: $file"; return 0; }
        fi
    done
    return 1
}

################################################################################
# get_google_drive_link()
# Description:
#   Produce Google Drive folder URL for the configured rclone remote.
#
# Behaviors:
#   - Reads root_folder_id from `rclone config show <remote>`.
#   - Returns a folder URL if found; else empty string.
#
# Returns:
#   Prints the URL or empty string.
################################################################################
get_google_drive_link() {
    if [[ -z "$RCLONE_REMOTE" ]]; then
        echo ""; return
    fi
    local remote_only
    remote_only="${RCLONE_REMOTE%:*}"      # e.g. gdrive-user from gdrive-user:/path
    local folder_id
    folder_id=$(rclone config show "$remote_only" 2>/dev/null | awk -F '=' '$1 ~ /root_folder_id/ { gsub(/[[:space:]]/, "", $2); print $2 }')
    if [[ -n "$folder_id" ]]; then
        echo "https://drive.google.com/drive/folders/$folder_id"
    else
        log WARN "Could not find root_folder_id for remote '$remote_only'"
        echo ""
    fi
}

################################################################################
# upload_backup_rclone()
# Description:
#   Upload the archive, its checksum, and backup_summary.md to rclone remote,
#   then prune remote old files.
#
# Behaviors:
#   - Skips when RCLONE_REMOTE is empty.
#   - Uses robust rclone copyto flags and deletes remote objects older than retention.
#
# Returns:
#   0 on success; non-zero if upload failed (prune still attempted).
################################################################################
upload_backup_rclone() {
