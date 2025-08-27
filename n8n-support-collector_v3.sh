#!/usr/bin/env bash
# n8n Support Collector v3 (refactor)
# Full-stack diagnostics for n8n on Docker with:
#  - Categorized outputs: system/, docker/, network/, n8n/, config/, summary/
#  - Aligned container report (TXT table, not CSV)
#  - HTTPS checks for n8n/grafana/prometheus
#  - ACME/Traefik certificate presence
#  - Config lint (insecure/missing values)
#  - Queue-mode sanity (EXECUTIONS_MODE=queue but no workers)
#  - VPS context (timezone, public IP)
#  - Health summary + recommendations
#
# Reuses ./n8n_common.sh if available (logging, env helpers, compose wrapper).
# Unofficial community script — review outputs before sharing.
set -euo pipefail

# ------------------------ Try to reuse your common helpers ------------------------
if [[ -f "./n8n_common.sh" ]]; then
  # shellcheck disable=SC1091
  source "./n8n_common.sh"
else
  # Minimal fallbacks (kept lightweight)
  LOG_LEVEL="${LOG_LEVEL:-INFO}"; LOG_LEVEL="${LOG_LEVEL^^}"
  log() {
    local level="$1"; shift
    local show=1
    case "$LOG_LEVEL" in
      DEBUG) show=0;;
      INFO) [[ "$level" != "DEBUG" ]] && show=0;;
      WARN) [[ "$level" == "WARN" || "$level" == "ERROR" ]] && show=0;;
      ERROR) [[ "$level" == "ERROR" ]] && show=0;;
    esac
    if [[ $show -eq 0 ]]; then
      local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
      if [[ "$level" == "WARN" || "$level" == "ERROR" ]]; then
        echo "[$ts] [$level] $*" >&2
      else
        echo "[$ts] [$level] $*"
      fi
    fi
  }
  compose() { docker compose "$@"; }
  mask_secret() {
    local s="${1:-}"; local n=${#s}
    (( n<=8 )) && { printf '%s\n' "$s"; return; }
    printf '%s\n' "${s:0:4}***${s: -4}"
  }
  looks_like_b64(){ [[ "${1:-}" =~ ^[A-Za-z0-9+/=]+$ ]]; }
  read_env_var(){ awk -v k="^$2=" 'BEGIN{FS="="} $0 ~ k {sub("^"k,"");print;exit}' "$1" 2>/dev/null; }
fi

# ------------------------ Defaults & CLI ------------------------
SINCE_HUMAN="24h"
TAIL_LINES=""
OUTPUT_DIR="n8n_support_$(date +%F_%H%M%S)"
REDACT=false
KEEP_TMP=false
CREATE_TAR=true
ENV_FILE="${ENV_FILE:-.env}"     # can override via ENV_FILE=...
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"

usage() {
  cat <<EOF
n8n Support Collector v3

Usage:
  $0 [options]

Options:
  -s, --since <dur>        Log window: 24h, 2h, 30m, 300s (default: 24h)
  --tail <n>               Limit docker logs to last N lines
  -o, --output <dir>       Output directory (default: ${OUTPUT_DIR})
  --env-file <path>        Path to .env (default: ${ENV_FILE})
  --compose-file <path>    Path to docker-compose.yml (default: ${COMPOSE_FILE})
  --redact                 Redact common secrets in env/logs
  --no-tar                 Do NOT compress results
  --keep-tmp               Keep working dir (don’t delete after tar)
  -h, --help               Show this help

Examples:
  $0 --redact
  $0 -s 2h --tail 400
EOF
  exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -s|--since) SINCE_HUMAN="$2"; shift;;
      --tail) TAIL_LINES="$2"; shift;;
      -o|--output) OUTPUT_DIR="$2"; shift;;
      --env-file) ENV_FILE="$2"; shift;;
      --compose-file) COMPOSE_FILE="$2"; shift;;
      --redact) REDACT=true;;
      --no-tar) CREATE_TAR=false;;
      --keep-tmp) KEEP_TMP=true;;
      -h|--help) usage;;
      *) log ERROR "Unknown option: $1"; usage;;
    esac
    shift
  done
}
parse_args "$@"

# ------------------------ Redaction helpers ------------------------
redact_stream() {
  if ! $REDACT; then cat; return; fi
  sed -E "
    s/(Authorization:[[:space:]]*Bearer[[:space:]]+)[A-Za-z0-9\.\-_]+/\1REDACTED/Ig;
    s/([?&](token|key|apikey|api_key|password)=[^&[:space:]]+)/\1_REDACTED/Ig;
    s/(\"?(password|secret|token|key)\"?[[:space:]]*[:=][[:space:]]*\")([^\"]+)/\1REDACTED/Ig;
    s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/REDACTED_IP/g;
  "
}
redact_env_stream() {
  if ! $REDACT; then cat; return; fi
  sed -E "
    s/\b(PASSWORD|SECRET|TOKEN|KEY)\b=.*/\1=REDACTED/g;
    s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/REDACTED_IP/g;
  "
}

# ------------------------ Dir layout ------------------------
DIR_SYS="${OUTPUT_DIR}/system"
DIR_DKR="${OUTPUT_DIR}/docker"
DIR_NET="${OUTPUT_DIR}/network"
DIR_N8N="${OUTPUT_DIR}/n8n"
DIR_CFG="${OUTPUT_DIR}/config"
DIR_SUM="${OUTPUT_DIR}/summary"
mkdir -p "$DIR_SYS" "$DIR_DKR" "$DIR_NET" "$DIR_N8N" "$DIR_CFG" "$DIR_SUM"

SUMMARY_TXT="${DIR_SUM}/final_summary.txt"

# ------------------------ Small utils ------------------------
have(){ command -v "$1" >/dev/null 2>&1; }
http_code(){ curl -fsS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 "$1"; }

public_ip() {
  local ip
  ip=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
  [[ -z "$ip" ]] && ip=$(curl -fsS --max-time 5 https://ipv4.icanhazip.com 2>/dev/null || true)
  if [[ -z "$ip" && $(have dig && echo 1 || echo 0) -eq 1 ]]; then
    ip=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null || true)
  fi
  echo "${ip:-unknown}"
}

# ------------------------ Load .env to infer domains/hosts ------------------------
if [[ -f "$ENV_FILE" ]]; then
  log INFO "Loading env from: $ENV_FILE"
  set -o allexport
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +o allexport
else
  log WARN "No .env file found at $ENV_FILE (continuing; some checks may be limited)."
fi

# Build FQDNs (best effort)
N8N_FQDN="${N8N_HOST:-}"
[[ -z "${N8N_FQDN:-}" && -n "${SUBDOMAIN_N8N:-}" && -n "${DOMAIN:-}" ]] && N8N_FQDN="${SUBDOMAIN_N8N}.${DOMAIN}"
GRAFANA_FQDN="${GRAFANA_FQDN:-}"
[[ -z "${GRAFANA_FQDN:-}" && -n "${SUBDOMAIN_GRAFANA:-}" && -n "${DOMAIN:-}" ]] && GRAFANA_FQDN="${SUBDOMAIN_GRAFANA}.${DOMAIN}"
PROM_FQDN="${PROM_FQDN:-}"
[[ -z "${PROM_FQDN:-}" && -n "${SUBDOMAIN_PROMETHEUS:-}" && -n "${DOMAIN:-}" ]] && PROM_FQDN="${SUBDOMAIN_PROMETHEUS}.${DOMAIN}"

# ------------------------ Collect: VPS/System ------------------------
log INFO "Collecting system info..."
{
  echo "=== OS / Kernel ==="; uname -a
  [[ -f /etc/os-release ]] && { echo; cat /etc/os-release; }
  echo; echo "=== CPU / Memory ==="
  (have lscpu && lscpu) || echo "(lscpu not available)"
  free -h || true
  echo; echo "=== Disk usage ==="; df -h
  echo; echo "=== Timezone & Clock ==="
  (have timedatectl && timedatectl) || date '+%Z %z  (%Y-%m-%d %H:%M:%S)'
  echo; echo "=== Public IP ==="; public_ip
} > "${DIR_SYS}/host_system_info.txt" 2>&1 || true

# OOM checks
{
  echo "Kernel OOM (dmesg) recent:"
  (dmesg -T 2>/dev/null || true) | grep -Ei "killed process|out of memory" || echo "None in dmesg"
  if have journalctl; then
    echo; echo "journalctl -k (last 1d):"
    journalctl -k --since "1 day ago" 2>/dev/null | grep -Ei "killed process|out of memory" || echo "None in journalctl -k"
  fi
} > "${DIR_SYS}/oom_check.txt" || true

# ------------------------ Docker: PS and aligned table ------------------------
log INFO "Collecting Docker inventory..."
docker ps -a > "${DIR_DKR}/docker_ps.txt" || true
docker network ls > "${DIR_DKR}/docker_networks.txt" || true

# Build human table (tabs + column -t)
TABLE="${DIR_DKR}/container_report.txt"
{
  printf "NAME\tIMAGE\tSTATUS\tHEALTH\tRESTARTS\tOOM\tPORTS\n"
  while IFS= read -r line; do
    # Use docker ps --format for base columns
    # shellcheck disable=SC2046
    docker ps -a --format '{{.ID}}||{{.Names}}||{{.Image}}||{{.Status}}||{{.Ports}}' \
      | while IFS='||' read -r ID NAME IMAGE STATUS PORTS; do
          HEALTH=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$ID" 2>/dev/null || echo "none")
          RESTARTS=$(docker inspect -f '{{.RestartCount}}' "$ID" 2>/dev/null || echo "0")
          OOM=$(docker inspect -f '{{.State.OOMKilled}}' "$ID" 2>/dev/null || echo "false")
          # Trim very long port lists for readability
          [[ "${PORTS:-}" =~ ^.{1,120}$ ]] || PORTS="${PORTS:0:117}..."
          printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$NAME" "$IMAGE" "$STATUS" "$HEALTH" "$RESTARTS" "$OOM" "${PORTS:--}"
        done
    break
  done < <(echo x)
} | (have column && column -t -s $'\t' || cat) > "$TABLE"

# Save per-container quick inspect (status/health/ports) and logs
SINCE_OPT=(--since "$SINCE_HUMAN")
[[ -n "${TAIL_LINES}" ]] && TAIL_OPT=(--tail "$TAIL_LINES") || TAIL_OPT=()

mapfile -t ALL_IDS < <(docker ps -a -q || true)
for ID in "${ALL_IDS[@]:-}"; do
  NAME="$(docker inspect -f '{{.Name}}' "$ID" 2>/dev/null | sed 's#^/##')"
  [[ -z "$NAME" ]] && continue
  CBASE="${DIR_DKR}/${NAME}"
  mkdir -p "$CBASE"
  # Inspect (compact)
  docker inspect "$ID" > "${CBASE}/inspect.json" 2>/dev/null || true
  docker logs "${SINCE_OPT[@]}" "${TAIL_OPT[@]}" "$ID" 2>&1 | redact_stream > "${CBASE}/logs.txt" || true
  # Env (redacted) for n8n* containers
  if [[ "$NAME" =~ n8n ]]; then
    docker exec "$ID" sh -lc 'printenv' 2>/dev/null | redact_env_stream > "${CBASE}/env.txt" || echo "N/A" > "${CBASE}/env.txt"
    docker exec "$ID" sh -lc 'wget -qO- http://localhost:5678/healthz || curl -sf http://localhost:5678/healthz || true' \
      > "${CBASE}/healthz.txt" 2>/dev/null || true
    docker exec "$ID" sh -lc 'wget -qO- http://localhost:5678/metrics || curl -sf http://localhost:5678/metrics || true' \
      | head -n 100 > "${CBASE}/metrics_sample.txt" 2>/dev/null || true
  fi
done

# ------------------------ Traefik ACME presence ------------------------
if docker ps --format '{{.Names}}' | grep -q '^traefik$'; then
  log INFO "Checking Traefik ACME store..."
  {
    echo "Inside container /letsencrypt:"
    docker exec traefik sh -lc 'ls -l /letsencrypt 2>/dev/null; ls -lh /letsencrypt/acme.json 2>/dev/null' || true
    echo
    echo "acme.json size (bytes):"
    docker exec traefik sh -lc 'stat -c "%s" /letsencrypt/acme.json 2>/dev/null' || true
    echo
    if docker exec traefik sh -lc 'command -v jq >/dev/null 2>&1'; then
      echo "Best-effort parse (number of cert entries if structure matches):"
      docker exec traefik sh -lc 'jq "..|objects|select(has(\"Certificates\"))|.Certificates|length" /letsencrypt/acme.json 2>/dev/null || true'
    else
      echo "(jq not present in traefik image)"
    fi
  } > "${DIR_NET}/traefik_acme.txt" 2>&1 || true
else
  echo "Traefik container not found" > "${DIR_NET}/traefik_acme.txt"
fi

# ------------------------ HTTPS checks ------------------------
log INFO "Probing HTTPS endpoints (valid TLS required)…"
HTTPS_TXT="${DIR_NET}/https_checks.txt"
{
  echo "Now: $(date -Is)"
  for FQ in "${N8N_FQDN:-}" "${GRAFANA_FQDN:-}" "${PROM_FQDN:-}"; do
    [[ -z "$FQ" ]] && continue
    CODE="$(http_code "https://${FQ}")" || CODE="ERR"
    echo "https://${FQ}  ->  ${CODE}"
  done
} > "$HTTPS_TXT" || true

# ------------------------ Config lint (insecure/missing) ------------------------
log INFO "Running config lint…"
CFG_TXT="${DIR_CFG}/config_lint.txt"
{
  echo "=== CONFIG LINT ==="
  echo "- Using env file: ${ENV_FILE} (exists: $( [[ -f "$ENV_FILE" ]] && echo yes || echo no ))"
  echo

  # n8n encryption key
  if [[ -n "${N8N_ENCRYPTION_KEY:-}" ]]; then
    echo "N8N_ENCRYPTION_KEY: present (masked: $(mask_secret "$N8N_ENCRYPTION_KEY"))"
    looks_like_b64 "$N8N_ENCRYPTION_KEY" || echo "WARN: encryption key does not look base64-like."
  else
    echo "ERROR: N8N_ENCRYPTION_KEY missing."
  fi

  # Basic auth (n8n UI)
  if [[ "${N8N_BASIC_AUTH_ACTIVE:-false}" == "true" ]]; then
    echo "N8N_BASIC_AUTH_ACTIVE=true"
    [[ -n "${N8N_BASIC_AUTH_USER:-}" ]] || echo "WARN: N8N_BASIC_AUTH_USER missing."
    if [[ -n "${N8N_BASIC_AUTH_PASSWORD:-}" ]]; then
      local_pw_len=${#N8N_BASIC_AUTH_PASSWORD}
      [[ $local_pw_len -lt 12 ]] && echo "WARN: N8N_BASIC_AUTH_PASSWORD looks short (<12)."
    else
      echo "WARN: N8N_BASIC_AUTH_PASSWORD missing."
    fi
  else
    echo "INFO: N8N_BASIC_AUTH_ACTIVE=false (UI is not behind basic auth)"
  fi

  # STRONG_PASSWORD
  if [[ -n "${STRONG_PASSWORD:-}" ]]; then
    echo "STRONG_PASSWORD: present (masked: $(mask_secret "$STRONG_PASSWORD"))"
    [[ ${#STRONG_PASSWORD} -lt 12 ]] && echo "WARN: STRONG_PASSWORD looks short (<12)."
  else
    echo "WARN: STRONG_PASSWORD missing."
  fi

  # Queue-mode sanity
  if [[ "${EXECUTIONS_MODE:-}" == "queue" ]]; then
    echo "EXECUTIONS_MODE=queue"
    # Verify workers exist & running
    worker_count=$(docker ps --format '{{.Names}}' | grep -E '^n8n-worker' | wc -l | tr -d ' ')
    if [[ "${worker_count:-0}" -eq 0 ]]; then
      echo "ERROR: queue mode but no n8n-worker containers are running."
    else
      echo "OK: ${worker_count} worker(s) detected."
    fi
  else
    echo "EXECUTIONS_MODE=${EXECUTIONS_MODE:-(unset)}"
  fi

  # Grafana defaults
  if docker ps --format '{{.Names}}' | grep -q '^grafana$'; then
    g_pw="$(docker exec grafana sh -lc 'printenv GF_SECURITY_ADMIN_PASSWORD' 2>/dev/null || true)"
    if [[ -n "$g_pw" ]]; then
      [[ "$g_pw" == "admin" ]] && echo "WARN: Grafana admin password is 'admin' (default) — change it."
    fi
  fi

} > "$CFG_TXT" 2>&1 || true

# ------------------------ Network quick facts ------------------------
{
  echo "=== Port maps (docker ps) ==="
  docker ps --format 'table {{.Names}}\t{{.Ports}}'
  echo
  echo "=== Networks inspect (compose ones) ==="
  compose config 2>/dev/null | grep -E '^\s{2,}[a-zA-Z0-9_-]+:\s*$' | sed 's/^\s\+\(.*\):$/\1/' | sort -u | while read -r net; do
    docker network inspect "$net" >/dev/null 2>&1 && echo "- $net" && docker network inspect "$net" | jq '.[0] | {Name,Id,Driver,IPAM:.IPAM.Config}' 2>/dev/null || true
  done
} > "${DIR_NET}/ports_and_networks.txt" 2>&1 || true

# ------------------------ Service probes (best-effort) ------------------------
PROBE_TXT="${DIR_NET}/service_probes.txt"
{
  echo "=== Service Probes ==="
  # Prometheus health
  if [[ -n "${PROM_FQDN:-}" ]]; then
    code=$(http_code "https://${PROM_FQDN}/-/ready" || true)
    echo "Prometheus readiness (/-/ready): ${code:-ERR}"
  fi
  # Grafana
  if [[ -n "${GRAFANA_FQDN:-}" ]]; then
    code=$(http_code "https://${GRAFANA_FQDN}/api/health" || true)
    echo "Grafana /api/health: ${code:-ERR}"
  fi
  # n8n editor
  if [[ -n "${N8N_FQDN:-}" ]]; then
    code=$(http_code "https://${N8N_FQDN}/" || true)
    echo "n8n editor (/): ${code:-ERR}"
  fi
  # Redis ping (from redis container)
  if docker ps --format '{{.Names}}' | grep -q '^redis$'; then
    echo; echo "[redis] PING:"
    docker exec redis sh -lc "redis-cli ${STRONG_PASSWORD:+-a \"$STRONG_PASSWORD\"} ping" 2>/dev/null || echo "fail"
  fi
  # Postgres version (from postgres container)
  if docker ps --format '{{.Names}}' | grep -q '^postgres$'; then
    echo; echo "[postgres] version:"
    docker exec postgres sh -lc "psql -U \"${POSTGRES_USER:-n8n}\" -d \"${POSTGRES_DB:-n8n}\" -c 'select version();' -tA" 2>/dev/null || echo "fail"
  fi
} > "$PROBE_TXT" 2>&1 || true

# ------------------------ Summary & Recommendations ------------------------
log INFO "Writing final summary…"
{
  echo "n8n Diagnostic Summary"
  echo "======================"
  echo "Bundle: $(basename "$OUTPUT_DIR")"
  echo "Since:  $SINCE_HUMAN ${TAIL_LINES:+(tail ${TAIL_LINES} lines)}"
  echo

  # Count containers by health
  total=$(docker ps -a -q | wc -l | tr -d ' ')
  running=$(docker ps -q | wc -l | tr -d ' ')
  unhealthy=$(grep -E "\tunhealthy\t" "$TABLE" | wc -l | tr -d ' ')
  echo "Containers: total=$total, running=$running, unhealthy=$unhealthy"
  echo

  # Queue mode anomaly
  if [[ "${EXECUTIONS_MODE:-}" == "queue" ]]; then
    worker_count=$(docker ps --format '{{.Names}}' | grep -E '^n8n-worker' | wc -l | tr -d ' ')
    if [[ "${worker_count:-0}" -eq 0 ]]; then
      echo "❌ Queue mode enabled but no n8n-worker containers are running."
    else
      echo "✅ Queue mode with ${worker_count} worker(s)."
    fi
  fi

  # HTTPS reachability quick verdicts
  echo
  echo "HTTPS checks:"
  while read -r line; do
    [[ -z "$line" ]] && continue
    url=$(awk '{print $1}' <<<"$line"); code=$(awk '{print $2}' <<<"$line")
    if [[ "$code" =~ ^(200|301|302|308|404)$ ]]; then
      echo "  ✅ $url  ($code)"
    else
      echo "  ❌ $url  ($code)"
    fi
  done < "$HTTPS_TXT"

  echo
  # Config lint summarized signals
  echo "Config lint highlights:"
  awk '
    /ERROR:/ { e=1; print "  ❌ " $0; next }
    /WARN:/  { w=1; print "  ⚠️  " $0; next }
    /OK:/    { print "  ✅ " $0; next }
    /INFO:/  { print "  ℹ️  " $0; next }
  END {
    if (!e && !w) print "  ✅ No warnings/errors detected by lint."
  }' "$CFG_TXT"

  echo
  echo "Files of interest:"
  echo "  - Docker inventory: ${TABLE}"
  echo "  - Traefik ACME info: ${DIR_NET}/traefik_acme.txt"
  echo "  - HTTPS checks: ${HTTPS_TXT}"
  echo "  - Probes: ${PROBE_TXT}"
  echo "  - n8n logs/env/metrics samples: ${DIR_DKR}/n8n-*/"
  echo "  - System info: ${DIR_SYS}/host_system_info.txt"
  echo "  - OOM check: ${DIR_SYS}/oom_check.txt"

  echo
  echo "Recommendations (common fixes):"
  echo "  • If HTTPS ❌ — check DNS ➜ Traefik logs, and ACME file exists / certificates issued."
  echo "  • If queue mode ❌ — start at least one n8n-worker."
  echo "  • Change default admin passwords (Grafana, n8n basic auth)."
  echo "  • Ensure N8N_ENCRYPTION_KEY is set (and backed up safely)."
} > "$SUMMARY_TXT"

# ------------------------ Package ------------------------
if $CREATE_TAR; then
  tarball="${OUTPUT_DIR}.tar.gz"
  log INFO "Compressing bundle: $tarball"
  tar -czf "$tarball" "$OUTPUT_DIR"
  sha256sum "$tarball" > "${tarball}.sha256" 2>/dev/null || true
  ! $KEEP_TMP && rm -rf "$OUTPUT_DIR"
  log INFO "Done. Output: $tarball"
else
  log INFO "Done. Output dir: $OUTPUT_DIR"
fi
