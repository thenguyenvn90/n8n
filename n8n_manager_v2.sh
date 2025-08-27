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

# ------------------------------- Usage ---------------------------------------
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

# --------------------------- Install/Upgrade helpers -------------------------
################################################################################
# check_domain()
# Description:
#   Verify the provided DOMAIN’s A record points to this server’s public IP.
#
# Behaviors:
#   - Detects server IP via api.ipify.org.
#   - Resolves DOMAIN with dig/getent.
#   - Continues with warning if no resolver; aborts on mismatch.
#
# Returns:
#   0 or exits 1 on mismatch.
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
#   Populate \$N8N_DIR with compose/env, pin version, rotate secrets if needed.
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

    # Rotate STRONG_PASSWORD if missing/default
    local pw; pw=$(awk -F= '/^STRONG_PASSWORD=/{print $2; found=1} END{if(!found) print ""}' "$env_file")
    if [[ -z "$pw" || "$pw" == "CHANGE_ME_BASE64_16_BYTES" ]]; then
        upsert_env_var "STRONG_PASSWORD" "$(openssl rand -base64 16)" "$env_file"
    fi

    # Rotate N8N_ENCRYPTION_KEY if missing/default
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

# --------------------------- Backup/Restore section ---------------------------

################################################################################
# box_line()
# Description:
#   Print a left-aligned label (fixed width 22) and a value on one line.
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
# Returns:
#   Exits 1.
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
#
# Returns:
#   Prints the URL or empty string.
################################################################################
get_google_drive_link() {
    if [[ -z "$RCLONE_REMOTE" ]]; then
        echo ""; return
    fi
    # Normalize remote name (strip path and colon for config show)
    local remote_name remote_only
    remote_only="${RCLONE_REMOTE%:*}"      # gdrive-user
    remote_name="${remote_only}"           # may already be bare
    local folder_id
    folder_id=$(rclone config show "$remote_name" 2>/dev/null | awk -F '=' '$1 ~ /root_folder_id/ { gsub(/[[:space:]]/, "", $2); print $2 }')
    if [[ -n "$folder_id" ]]; then
        echo "https://drive.google.com/drive/folders/$folder_id"
    else
        log WARN "Could not find root_folder_id for remote '$remote_name'"
        echo ""
    fi
}

################################################################################
# upload_backup_rclone()
# Description:
#   Upload the archive, its checksum, and backup_summary.md to rclone remote,
#   then prune remote old files.
#
# Returns:
#   0 on success; non-zero if upload failed (prune still attempted).
################################################################################
upload_backup_rclone() {
    require_cmd rclone || { log ERROR "rclone is required for uploads"; return 1; }
    local ret=0
    if [[ -z "${RCLONE_REMOTE:-}" ]]; then
        UPLOAD_STATUS="SKIPPED"
        log INFO "Rclone remote not set; skipping upload."
        return 0
    fi

    # Ensure one trailing colon
    local REMOTE="${RCLONE_REMOTE%:}:"
    log INFO "Uploading backup files to: $REMOTE"

    if  rclone copyto "$BACKUP_DIR/$BACKUP_FILE" "$REMOTE/$BACKUP_FILE" "${RCLONE_FLAGS[@]}" \
        && rclone copyto "$BACKUP_DIR/$BACKUP_FILE.sha256" "$REMOTE/$BACKUP_FILE.sha256" "${RCLONE_FLAGS[@]}" \
        && rclone copyto "$BACKUP_DIR/backup_summary.md" "$REMOTE/backup_summary.md" "${RCLONE_FLAGS[@]}"; then
        UPLOAD_STATUS="SUCCESS"
        log INFO "Uploaded archive, checksum and summary successfully."
        ret=0
    else
        UPLOAD_STATUS="FAIL"
        log ERROR "One or more uploads failed."
        ret=1
    fi

    # Prune older than retention window (only .tar.gz and .sha256)
    log INFO "Pruning remote archives older than ${DAYS_TO_KEEP} days"
    local tmpfilter; tmpfilter="$(mktemp)"
    printf "%s\n" "+ n8n_backup_*.tar.gz" "+ n8n_backup_*.tar.gz.sha256" "- *" > "$tmpfilter"
    rclone delete "$REMOTE" --min-age "${DAYS_TO_KEEP}d" --filter-from "$tmpfilter" --rmdirs \
        || log WARN "Remote prune returned non-zero (continuing)."
    rm -f "$tmpfilter"
    return $ret
}

################################################################################
# write_summary()
# Description:
#   Append action/status to backup_summary.md and prune entries >30 days old.
################################################################################
write_summary() {
    local action="$1" status="$2"
    local file="$BACKUP_DIR/backup_summary.md"
    local now="$DATE"
    local cutoff; cutoff=$(date -d '30 days ago' '+%F')
    if [[ ! -f "$file" ]]; then
        cat >> "$file" <<'EOF'
| DATE               | ACTION         | N8N_VERSION | STATUS   |
|--------------------|----------------|-------------|----------|
EOF
    fi
    printf "| %s | %s | %s | %s |\n" "$now" "$action" "$N8N_VERSION" "$status" >> "$file"
    { head -n2 "$file"; tail -n +3 "$file" | awk -v cut="$cutoff" -F'[| ]+' '$2 >= cut'; } > "${file}.tmp" && mv "${file}.tmp" "$file"
}

################################################################################
# do_local_backup()
# Description:
#   Execute local backup: volumes, Postgres dump, configs, tar+checksum.
################################################################################
do_local_backup() {
    ensure_encryption_key_exists "$N8N_DIR/.env" || { BACKUP_STATUS="FAIL"; return 1; }

    local BACKUP_PATH="$BACKUP_DIR/backup_$DATE"
    mkdir -p "$BACKUP_PATH" || { log ERROR "Failed to create $BACKUP_PATH"; return 1; }

    log INFO "Checking services running and healthy before backup…"
    check_services_up_running || { log ERROR "Services unhealthy; aborting backup."; return 1; }

    log INFO "Backing up ./local-files (if present)…"
    if [[ -d "$N8N_DIR/local-files" ]]; then
        tar -czf "$BACKUP_PATH/local-files_$DATE.tar.gz" -C "$N8N_DIR" local-files || { log ERROR "local-files backup failed"; return 1; }
    else
        log INFO "No local-files directory; skipping."
    fi

    log INFO "Backing up Docker volumes…"
    for vol in "${VOLUMES[@]}"; do
        docker volume inspect "$vol" >/dev/null 2>&1 || { log ERROR "Volume $vol not found"; return 1; }
        local vol_backup="volume_${vol}_$DATE.tar.gz"
        docker run --rm -v "${vol}:/data" -v "$BACKUP_PATH:/backup" alpine \
          sh -c "tar czf /backup/$vol_backup -C /data ." || { log ERROR "Failed to archive volume $vol"; return 1; }
    done

    log INFO "Dumping PostgreSQL database…"
    local DB_USER="${DB_POSTGRESDB_USER:-${POSTGRES_USER:-n8n}}"
    local DB_NAME="${DB_POSTGRESDB_DATABASE:-${POSTGRES_DB:-n8n}}"
    if docker exec postgres sh -c "pg_isready" &>/dev/null; then
        docker exec postgres pg_dump -U "$DB_USER" -d "$DB_NAME" > "$BACKUP_PATH/n8n_postgres_dump_$DATE.sql" \
          || { log ERROR "Postgres dump failed"; return 1; }
    else
        log ERROR "Postgres not ready"; return 1
    fi

    log INFO "Backing up .env and docker-compose.yml…"
    cp "$N8N_DIR/.env" "$BACKUP_PATH/.env.bak"
    cp "$N8N_DIR/docker-compose.yml" "$BACKUP_PATH/docker-compose.yml.bak"

    log INFO "Compressing backup folder…"
    BACKUP_FILE="n8n_backup_${N8N_VERSION}_${DATE}.tar.gz"
    if command -v pigz >/dev/null 2>&1; then
        tar -C "$BACKUP_PATH" -cf - . | pigz > "$BACKUP_DIR/$BACKUP_FILE" || { log ERROR "pigz compression failed"; return 1; }
    else
        tar -czf "$BACKUP_DIR/$BACKUP_FILE" -C "$BACKUP_PATH" . || { log ERROR "gzip compression failed"; return 1; }
    fi
    sha256sum "$BACKUP_DIR/$BACKUP_FILE" > "$BACKUP_DIR/$BACKUP_FILE.sha256" || { log ERROR "Checksum write failed"; return 1; }

    rm -rf "$BACKUP_PATH"
    find "$BACKUP_DIR" -type f -name "*.tar.gz" -mtime +$DAYS_TO_KEEP -delete
    find "$BACKUP_DIR" -type f -name "*.sha256" -mtime +$DAYS_TO_KEEP -delete
    find "$BACKUP_DIR" -maxdepth 1 -type d -name 'backup_*' -empty -exec rmdir {} \; || true
    return 0
}

################################################################################
# send_mail_on_action()
# Description:
#   Decide whether and what to email based on BACKUP_STATUS/UPLOAD_STATUS.
################################################################################
send_mail_on_action() {
    local subject body

    if [[ "$ACTION" == "Restore" ]]; then
        if [[ "$BACKUP_STATUS" == "FAIL" ]]; then
            subject="$DATE: n8n Restore FAILED"
            body="An error occurred during restore. See attached log.

Log File: $LOG_FILE"
            send_email "$subject" "$body" "$LOG_FILE"
        elif [[ "$BACKUP_STATUS" == "SUCCESS" && "$NOTIFY_ON_SUCCESS" == true ]]; then
            subject="$DATE: n8n Restore SUCCESS"
            body="Restore completed successfully.

Log File: $LOG_FILE"
            send_email "$subject" "$body" "$LOG_FILE"
        fi
        return 0
    fi

    # Backup email decisions (with upload status)
    if [[ "$BACKUP_STATUS" == "FAIL" ]]; then
        subject="$DATE: n8n Backup FAILED locally"
        body="An error occurred during the local backup step. See attached log.

Log File: $LOG_FILE"
        send_email "$subject" "$body" "$LOG_FILE"

    elif [[ "$BACKUP_STATUS" == "SKIPPED" ]]; then
        if [[ "$NOTIFY_ON_SUCCESS" == true ]]; then
            subject="$DATE: n8n Backup SKIPPED: no changes"
            body="No changes detected since the last backup; nothing to do."
            send_email "$subject" "$body"
        fi

    elif [[ "$BACKUP_STATUS" == "SUCCESS" ]]; then
        # Upload-dependent subject/body
        if [[ "$UPLOAD_STATUS" == "FAIL" ]]; then
            subject="$DATE: n8n Backup Succeeded; upload FAILED"
            body="Local backup succeeded as:

  File: $BACKUP_FILE

But the upload to ${RCLONE_REMOTE:-<unset>} failed.
See log for details:

  Log File: $LOG_FILE"
            send_email "$subject" "$body" "$LOG_FILE"

        elif [[ "$UPLOAD_STATUS" == "SUCCESS" ]]; then
            if [[ "$NOTIFY_ON_SUCCESS" == true ]]; then
                subject="$DATE: n8n Backup SUCCESS"
                body="Backup and upload completed successfully.

  File: $BACKUP_FILE
  Remote: ${RCLONE_REMOTE:-<unset>}
  Drive Link: ${DRIVE_LINK:-N/A}"
                send_email "$subject" "$body" "$LOG_FILE"
            fi

        else # SKIPPED
            if [[ "$NOTIFY_ON_SUCCESS" == true ]]; then
                subject="$DATE: n8n Backup SUCCESS (upload skipped)"
                body="Local backup completed successfully.

  File: $BACKUP_FILE
  Remote upload: SKIPPED (no rclone remote configured)

  Log File: $LOG_FILE"
                send_email "$subject" "$body" "$LOG_FILE"
            fi
        fi
    fi
}

################################################################################
# print_backup_summary()
# Description:
#   Print a human-readable summary of the latest backup/restore action.
################################################################################
print_backup_summary() {
    local summary_file="$BACKUP_DIR/backup_summary.md"
    local email_status email_reason

    if ! $EMAIL_EXPLICIT; then
        email_status="SKIPPED"; email_reason="(not requested)"
    elif $EMAIL_SENT; then
        email_status="SUCCESS"; email_reason=""
    else
        if [[ -z "$SMTP_USER" || -z "$SMTP_PASS" || -z "$EMAIL_TO" ]]; then
            email_status="ERROR"; email_reason="(missing SMTP config)"
        else
            email_status="FAILED"; email_reason="(send failed)"
        fi
    fi

    echo "═════════════════════════════════════════════════════════════"
    box_line "Action:"          "$ACTION"
    box_line "Status:"          "$BACKUP_STATUS"
    box_line "Timestamp:"       "$DATE"
    box_line "Domain:"          "https://$DOMAIN"
    [[ -n "$BACKUP_FILE" ]] && box_line "Backup file:" "$BACKUP_DIR/$BACKUP_FILE"
    box_line "N8N Version:"     "$N8N_VERSION"
    box_line "Log File:"        "$LOG_FILE"
    box_line "Daily tracking:"  "$summary_file"
    case "$UPLOAD_STATUS" in
        "SUCCESS")
            box_line "Google Drive upload:" "SUCCESS"
            box_line "Folder link:"         "${DRIVE_LINK:-N/A}"
            ;;
        "SKIPPED")
            box_line "Google Drive upload:" "SKIPPED"
            ;;
        "FAIL"|*)
            [[ -n "$UPLOAD_STATUS" ]] && box_line "Google Drive upload:" "FAILED"
            ;;
    esac
    if [[ -n "$email_reason" ]]; then
        box_line "Email notification:" "$email_status $email_reason"
    else
        box_line "Email notification:" "$email_status"
    fi
    echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# backup_n8n()
# Description:
#   Orchestrate a full backup: change check → local backup → upload → email/summary.
################################################################################
backup_n8n() {
    ACTION="Backup"
    N8N_VERSION="$(get_current_n8n_version)"
    BACKUP_STATUS=""; UPLOAD_STATUS="SKIPPED"; BACKUP_FILE=""; DRIVE_LINK=""

    if is_system_changed; then
        ACTION="Backup (normal)"
    elif [[ "$DO_FORCE" == true ]]; then
        ACTION="Backup (forced)"
    else
        ACTION="Skipped"
        BACKUP_STATUS="SKIPPED"
        log INFO "No changes detected; skipping backup."
        write_summary "$ACTION" "$BACKUP_STATUS"
        send_mail_on_action
        print_backup_summary
        return 0
    fi

    # Local backup
    if do_local_backup; then
        BACKUP_STATUS="SUCCESS"
        log INFO "Local backup succeeded: $BACKUP_FILE"
        refresh_snapshot
    else
        BACKUP_STATUS="FAIL"
        log ERROR "Local backup failed."
        UPLOAD_STATUS="SKIPPED"
        write_summary "$ACTION" "$BACKUP_STATUS"
        send_mail_on_action
        print_backup_summary
        return 1
    fi

    # Remote upload (if configured)
    if [[ -n "$RCLONE_REMOTE" ]]; then
        if upload_backup_rclone; then
            DRIVE_LINK="$(get_google_drive_link)"
        fi
    else
        UPLOAD_STATUS="SKIPPED"
    fi

    # Record in rolling summary
    write_summary "$ACTION" "$BACKUP_STATUS"
    # Final notifications & console box
    send_mail_on_action
    print_backup_summary
}

################################################################################
# fetch_restore_archive_if_remote()
# Description:
#   If TARGET_RESTORE_FILE is an rclone path, download it locally and verify checksum.
#
# Returns:
#   0 on success; non-zero on download/verification failure.
################################################################################
fetch_restore_archive_if_remote() {
    if [[ -f "$TARGET_RESTORE_FILE" ]]; then
        return 0
    fi
    # Heuristic: contains ':' and not an absolute path -> treat as remote:path
    if [[ "$TARGET_RESTORE_FILE" == *:* && "$TARGET_RESTORE_FILE" != /* ]]; then
        require_cmd rclone || { log ERROR "rclone required to fetch remote backup."; return 1; }
        local tmp_dir="$BACKUP_DIR/_restore_tmp"
        mkdir -p "$tmp_dir"
        local base; base="$(basename "$TARGET_RESTORE_FILE" | tr ':' '_')"
        local local_path="$tmp_dir/$base"

        log INFO "Fetching backup from remote: $TARGET_RESTORE_FILE"
        if rclone copyto "$TARGET_RESTORE_FILE" "$local_path" "${RCLONE_FLAGS[@]}"; then
            log INFO "Downloaded to: $local_path"
            log INFO "Verifying checksum (if present)…"
            if rclone copyto "${TARGET_RESTORE_FILE}.sha256" "${local_path}.sha256" "${RCLONE_FLAGS[@]}"; then
                (cd "$tmp_dir" && sha256sum -c "$(basename "${local_path}.sha256")") \
                    || { log ERROR "Checksum verification failed for $local_path"; return 1; }
                log INFO "Checksum verified."
            else
                log WARN "No remote checksum found; skipping verification."
            fi
            TARGET_RESTORE_FILE="$local_path"
            echo "$TARGET_RESTORE_FILE" > "$tmp_dir/.last_fetched"
        else
            log ERROR "Failed to fetch remote backup."
            return 1
        fi
    fi
}

################################################################################
# restore_n8n()
# Description:
#   Restore the n8n stack from a (local or remote-fetched) backup archive.
################################################################################
restore_n8n() {
    ACTION="Restore"
    # If remote, fetch locally first
    fetch_restore_archive_if_remote || { log ERROR "Failed to fetch restore archive."; return 1; }

    [[ -f "$TARGET_RESTORE_FILE" ]] || { log ERROR "Restore file not found: $TARGET_RESTORE_FILE"; return 1; }

    log INFO "Starting restore at $DATE…"
    local restore_dir="$N8N_DIR/n8n_restore_$(date +%s)"
    mkdir -p "$restore_dir" || { log ERROR "Cannot create $restore_dir"; return 1; }

    log INFO "Extracting archive to $restore_dir"
    tar -xzf "$TARGET_RESTORE_FILE" -C "$restore_dir" || { log ERROR "Failed to extract archive"; return 1; }

    local backup_env_path="$restore_dir/.env.bak"
    local current_env_path="$N8N_DIR/.env"
    local backup_compose_path="$restore_dir/docker-compose.yml.bak"
    local current_compose_path="$N8N_DIR/docker-compose.yml"

    [[ -f "$backup_env_path"     ]] || { log ERROR "Missing $backup_env_path"; return 1; }
    [[ -f "$backup_compose_path" ]] || { log ERROR "Missing $backup_compose_path"; return 1; }

    local n8n_encryption_key
    n8n_encryption_key="$(read_env_var "$backup_env_path" N8N_ENCRYPTION_KEY || true)"
    [[ -n "$n8n_encryption_key" ]] || { log ERROR "Backup .env has no N8N_ENCRYPTION_KEY"; return 1; }
    ! looks_like_b64 "$n8n_encryption_key" && log WARN "N8N_ENCRYPTION_KEY not base64-like."
    log INFO "N8N_ENCRYPTION_KEY (masked): $(mask_secret "$n8n_encryption_key")"

    log INFO "Restoring local-files (if present)…"
    if compgen -G "$restore_dir/local-files_*.tar.gz" >/dev/null; then
        tar -xzf "$restore_dir"/local-files_*.tar.gz -C "$N8N_DIR" || { log ERROR "local-files restore failed"; return 1; }
    fi

    cp -f "$backup_env_path" "$current_env_path"
    cp -f "$backup_compose_path" "$current_compose_path"
    load_env_file "$current_env_path"

    log INFO "Stopping and removing containers before restore…"
    compose down --volumes --remove-orphans || { log ERROR "compose down failed"; return 1; }

    local dump_file sql_file
    dump_file="$(find "$restore_dir" -name "n8n_postgres_dump_*.dump" -print -quit || true)"
    sql_file="$(find "$restore_dir" -name "n8n_postgres_dump_*.sql" -print -quit || true)"

    local RESTORE_VOLUMES=("${VOLUMES[@]}")
    if [[ -n "$dump_file" || -n "$sql_file" ]]; then
        log INFO "SQL dump present. Skipping postgres-data volume restore…"
        local filtered=()
        for v in "${RESTORE_VOLUMES[@]}"; do [[ "$v" != "postgres-data" ]] && filtered+=("$v"); done
        RESTORE_VOLUMES=("${filtered[@]}")
    fi

    log INFO "Cleaning existing Docker volumes before restore…"
    for vol in "${RESTORE_VOLUMES[@]}"; do
        docker volume inspect "$vol" >/dev/null 2>&1 && docker volume rm "$vol" >/dev/null 2>&1 && log INFO "Removed: $vol" || true
    done

    log INFO "Restoring volumes…"
    for vol in "${RESTORE_VOLUMES[@]}"; do
        local vol_file; vol_file="$(find "$restore_dir" -name "*${vol}_*.tar.gz" -print -quit || true)"
        [[ -n "$vol_file" ]] || { log ERROR "No backup found for volume $vol"; return 1; }
        docker volume create "$vol" >/dev/null
        docker run --rm -v "${vol}:/data" -v "$restore_dir:/backup" alpine \
          sh -c "rm -rf /data/* && tar xzf /backup/$(basename "$vol_file") -C /data" || { log ERROR "Restore failed for $vol"; return 1; }
    done

    log INFO "Starting PostgreSQL first…"
    compose up -d postgres || { log ERROR "Failed to start postgres"; return 1; }
    check_container_healthy "postgres" || return 1

    local PG_CONT="postgres"
    local DB_USER="${DB_POSTGRESDB_USER:-${POSTGRES_USER:-n8n}}"
    local DB_NAME="${DB_POSTGRESDB_DATABASE:-${POSTGRES_DB:-n8n}}"
    local POSTGRES_RESTORE_MODE="volume"

    if [[ -n "$dump_file" ]]; then
        POSTGRES_RESTORE_MODE="dump"
        log INFO "Restoring DB via pg_restore…"
        docker exec -i "$PG_CONT" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c \
          "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${DB_NAME}' AND pid <> pg_backend_pid();" || true
        docker exec -i "$PG_CONT" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS ${DB_NAME};"
        docker exec -i "$PG_CONT" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
        docker exec -i "$PG_CONT" pg_restore -U "$DB_USER" -d "${DB_NAME}" -c -v < "$dump_file"
    elif [[ -n "$sql_file" ]]; then
        POSTGRES_RESTORE_MODE="dump"
        log INFO "Restoring DB via psql (SQL dump)…"
        docker exec -i "$PG_CONT" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c \
          "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${DB_NAME}' AND pid <> pg_backend_pid();" || true
        docker exec -i "$PG_CONT" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS ${DB_NAME};"
        docker exec -i "$PG_CONT" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
        docker exec -i "$PG_CONT" psql -U "$DB_USER" -d "${DB_NAME}" -v ON_ERROR_STOP=1 < "$sql_file"
    else
        log INFO "No SQL dump found; assuming DB is in postgres-data volume."
    fi

    log INFO "Starting the rest of the stack…"
    compose up -d || { log ERROR "compose up failed"; return 1; }

    log INFO "Checking services after restore…"
    check_services_up_running || { log ERROR "Stack unhealthy after restore"; return 1; }

    rm -rf "$restore_dir"
    if [[ -d "$BACKUP_DIR/_restore_tmp" ]]; then
        find "$BACKUP_DIR/_restore_tmp" -type f -name '*n8n_backup_*.tar.gz' -delete || true
        rmdir "$BACKUP_DIR/_restore_tmp" 2>/dev/null || true
    fi

    N8N_VERSION="$(get_current_n8n_version)"
    local restored_list=""
    if ((${#RESTORE_VOLUMES[@]})); then
        restored_list=$(printf '%s, ' "${RESTORE_VOLUMES[@]}"); restored_list=${restored_list%, }
    else
        restored_list="(none)"
    fi

    BACKUP_STATUS="SUCCESS"
    echo "═════════════════════════════════════════════════════════════"
    echo "Restore completed successfully."
    box_line "Domain:"              "https://$DOMAIN"
    box_line "Restore from file:"   "$TARGET_RESTORE_FILE"
    box_line "N8N Version:"         "$N8N_VERSION"
    box_line "N8N Directory:"       "$N8N_DIR"
    box_line "Log File:"            "$LOG_FILE"
    box_line "Timestamp:"           "$DATE"
    box_line "Volumes restored:"    "$restored_list"
    if [[ "$POSTGRES_RESTORE_MODE" == "dump" ]]; then
        box_line "PostgreSQL:"       "Restored from SQL dump"
    else
        box_line "PostgreSQL:"       "Restored from volume"
    fi
    echo "═════════════════════════════════════════════════════════════"

    write_summary "$ACTION" "$BACKUP_STATUS"
    send_mail_on_action
}

# ------------------------------ Arg parsing ----------------------------------
################################################################################
# Parse command-line arguments
################################################################################
SHORT="i:u:v:m:fcabd:l:her:n"
LONG="install:,upgrade:,version:,email:,force,cleanup,available,backup,dir:,log-level:,help,restore:,notify-on-success,remote-name:"
PARSED=$(getopt --options="$SHORT" --longoptions="$LONG" --name "$0" -- "$@") || usage
eval set -- "$PARSED"

while true; do
    case "$1" in
        -i|--install)  INSTALL=true; DOMAIN="$(parse_domain_arg "$2")"; shift 2;;
        -u|--upgrade)  UPGRADE=true; DOMAIN="$(parse_domain_arg "$2")"; shift 2;;
        -v|--version)  N8N_VERSION="$2"; shift 2;;
        -m|--email)    SSL_EMAIL="$2"; shift 2;;
        -f|--force)    FORCE_UPGRADE=true; DO_FORCE=true; shift;;
        -c|--cleanup)  CLEANUP=true; shift;;
        -a|--available) LIST_VERSIONS=true; shift;;
        -b|--backup)   DO_BACKUP=true; shift;;
        -r|--restore)  DO_RESTORE=true; TARGET_RESTORE_FILE="$2"; shift 2;;
        -d|--dir)      TARGET_DIR="$2"; shift 2;;
        -l|--log-level) LOG_LEVEL="${2^^}"; shift 2;;
        -e|--email)    EMAIL_TO="$2"; EMAIL_EXPLICIT=true; shift 2;;
        -n|--notify-on-success) NOTIFY_ON_SUCCESS=true; shift;;
        -s|--remote-name) RCLONE_REMOTE="$2"; shift 2;;
        -h|--help)     usage;;
        --) shift; break;;
        *) usage;;
    esac
done

# Validate single action
_actions=0
$INSTALL && _actions=$((_actions+1))
$UPGRADE && _actions=$((_actions+1))
$CLEANUP && _actions=$((_actions+1))
$LIST_VERSIONS && _actions=$((_actions+1))
$DO_BACKUP && _actions=$((_actions+1))
$DO_RESTORE && _actions=$((_actions+1))

if (( _actions == 0 )); then
    log ERROR "No action specified. Choose one of: --install/--upgrade/--cleanup/--available/--backup/--restore"
    usage
fi
if (( _actions > 1 )); then
    log ERROR "Choose exactly one action."
    usage
fi

# Domain required for install/upgrade
if $INSTALL || $UPGRADE; then
    [[ -n "${DOMAIN:-}" ]] || { log ERROR "Domain required for install/upgrade."; exit 2; }
fi

# ------------------------------ Main -----------------------------------------
check_root || { log ERROR "Please run as root."; exit 1; }
mkdir -p "$DEFAULT_N8N_DIR"
N8N_DIR="${TARGET_DIR:-$DEFAULT_N8N_DIR}"

ENV_FILE="$N8N_DIR/.env"
COMPOSE_FILE="$N8N_DIR/docker-compose.yml"

# Logs
mkdir -p "$N8N_DIR/logs"
DATE=$(date +%F_%H-%M-%S)
mode="manager"
$DO_BACKUP  && mode="backup"
$DO_RESTORE && mode="restore"
LOG_FILE="$N8N_DIR/logs/${mode}_n8n_$DATE.log"
exec > >(tee "$LOG_FILE") 2>&1
log INFO "Working on directory: $N8N_DIR"
log INFO "Logging to $LOG_FILE"

# Backup/restore directories
BACKUP_DIR="$N8N_DIR/backups"
LOG_DIR="$N8N_DIR/logs"
mkdir -p "$BACKUP_DIR" "$LOG_DIR" "$BACKUP_DIR/snapshot/volumes" "$BACKUP_DIR/snapshot/config"

# Email config hints
if $EMAIL_EXPLICIT; then
    missing=()
    [[ -z "${SMTP_USER:-}" ]] && missing+=("SMTP_USER")
    [[ -z "${SMTP_PASS:-}" ]] && missing+=("SMTP_PASS")
    [[ -z "${EMAIL_TO:-}"  ]] && missing+=("EMAIL_TO/-e")
    if ((${#missing[@]})); then
        log WARN "Email requested (-e) but missing: ${missing[*]} — emails will NOT be sent."
    else
        if [[ "$NOTIFY_ON_SUCCESS" == true ]]; then
            log INFO "Emails enabled → will notify on success and failure: $EMAIL_TO"
        else
            log INFO "Emails enabled → will notify on failure only: $EMAIL_TO"
        fi
    fi
elif [[ "$NOTIFY_ON_SUCCESS" == true ]]; then
    log WARN "--notify-on-success was set, but no -e/--email provided. No email will be sent."
fi

# Debug tracing
if [[ "$LOG_LEVEL" == "DEBUG" ]]; then
    export PS4='+ $(date "+%H:%M:%S") ${BASH_SOURCE##*/}:${LINENO}:${FUNCNAME[0]:-main}: '
    set -x
fi

# Run selected action
if [[ $INSTALL == true ]]; then
    install_n8n
elif [[ $UPGRADE == true ]]; then
    upgrade_n8n
elif [[ $CLEANUP == true ]]; then
    cleanup_n8n
elif [[ $LIST_VERSIONS == true ]]; then
    list_available_versions
elif [[ $DO_BACKUP == true ]]; then
    trap 'handle_error_backup' ERR
    load_env_file
    initialize_snapshot
    require_cmd docker || exit 1
    require_cmd rsync  || exit 1
    require_cmd tar    || exit 1
    require_cmd curl   || exit 1
    require_cmd openssl|| exit 1
    require_cmd base64 || exit 1
    require_cmd awk    || exit 1
    require_cmd sha256sum || exit 1
    $EMAIL_EXPLICIT && require_cmd msmtp || true
    [[ -n "$RCLONE_REMOTE" ]] && require_cmd rclone || true
    backup_n8n || exit 1
    # local cleanups
    find "$BACKUP_DIR/snapshot/volumes" -type d -empty -delete || true
    find "$BACKUP_DIR/snapshot/config" -type f -empty -delete || true
    find "$BACKUP_DIR" -maxdepth 1 -type d -name 'backup_*' -empty -delete || true
    find "$LOG_DIR" -type f -mtime +$DAYS_TO_KEEP -delete || true
elif [[ $DO_RESTORE == true ]]; then
    trap 'handle_error_backup' ERR
    load_env_file
    require_cmd docker || exit 1
    require_cmd tar    || exit 1
    require_cmd curl   || exit 1
    require_cmd openssl|| exit 1
    require_cmd awk    || exit 1
    # Require rclone if TARGET_RESTORE_FILE looks like remote:path
    if [[ "$TARGET_RESTORE_FILE" == *:* && "$TARGET_RESTORE_FILE" != /* ]]; then
        require_cmd rclone || exit 1
    fi
    $EMAIL_EXPLICIT && require_cmd msmtp || true
    restore_n8n || exit 1
else
    usage
fi
