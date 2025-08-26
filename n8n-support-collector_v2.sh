#!/usr/bin/env bash
#
# n8n Support Collector v2
# Full-stack diagnostics for n8n on Docker/Kubernetes with redaction, health probes, OOM checks,
# queue-mode sanity checks, and optional JSON/CSV summaries.
#
# ⚠️ Unofficial: community script, not maintained by the n8n team.
# Review outputs before sharing outside your organization.

set -euo pipefail

# ------------------------ Defaults ------------------------
SINCE_HUMAN="24h"            # human-friendly: 24h, 2h, 45m, 300s
SINCE_SECS=86400             # derived from SINCE_HUMAN
TAIL_LINES=""                # empty = no --tail
OUTPUT_DIR="n8n_support_$(date +%F_%H%M%S)"
SUMMARY_FILE=""
JSON_OUT=""
REDACT=false
KEEP_TMP=false
CREATE_TAR=true
NAME_FILTER="n8n"            # regex for container name match
LABEL_FILTER=""              # docker label filter
SCOPE="all"                  # host|docker|k8s|all
STATS_SECONDS=0              # >0 to sample docker stats
K8S_SELECTOR="app=n8n"
K8S_NS=""
REDACT_EXTRA_REGEX=""
REQUIRE_JQ=false            # set true for JSON enrichment requiring jq

# ------------------------ Help ------------------------
usage() {
  cat <<EOF
n8n Support Collector v2

Usage:
  $0 [options]

Options:
  -s, --since <dur>        Log window: 24h, 2h, 30m, 300s (default: 24h)
  -t, --since-seconds <n>  Log window in seconds (overrides --since)
  --tail <n>               Limit docker logs to last N lines
  -o, --output <dir>       Output directory (default: $OUTPUT_DIR)
  --redact                 Redact secrets in env and logs
  --redact-pattern <re>    Extra regex (sed -E) for redaction in logs/env
  --name-filter <regex>    Only containers whose names match regex (default: n8n)
  --label-filter <key=val> Only containers with this docker label
  --scope <scope>          host|docker|k8s|all (default: all)
  --stats-seconds <n>      Sample docker stats for n seconds
  --k8s-selector <kv>      k8s label selector (default: app=n8n)
  --k8s-ns <name>          k8s namespace (default: all namespaces)
  --json                   Emit summary.json alongside text summary
  --no-tar                 Do NOT compress results
  --keep-tmp               Keep working directory (don’t delete after tar)

Examples:
  $0 --redact
  $0 -s 2h --name-filter '^(n8n|n8n-worker)' --json
  $0 --since-seconds 7200 --stats-seconds 15 --redact --no-tar
EOF
  exit 1
}

# ------------------------ Args ------------------------
parse_human_duration() {
  local s="$1"
  if [[ "$s" =~ ^([0-9]+)h$ ]]; then
    echo $(( ${BASH_REMATCH[1]} * 3600 ))
  elif [[ "$s" =~ ^([0-9]+)m$ ]]; then
    echo $(( ${BASH_REMATCH[1]} * 60 ))
  elif [[ "$s" =~ ^([0-9]+)s$ ]]; then
    echo "${BASH_REMATCH[1]}"
  elif [[ "$s" =~ ^([0-9]+)$ ]]; then
    echo "${BASH_REMATCH[1]}"
  else
    # default 24h if unrecognized
    echo 86400
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--since) SINCE_HUMAN="$2"; shift;;
    -t|--since-seconds) SINCE_SECS="$2"; SINCE_HUMAN="${2}s"; shift;;
    --tail) TAIL_LINES="$2"; shift;;
    -o|--output) OUTPUT_DIR="$2"; shift;;
    --redact) REDACT=true;;
    --redact-pattern) REDACT_EXTRA_REGEX="$2"; shift;;
    --name-filter) NAME_FILTER="$2"; shift;;
    --label-filter) LABEL_FILTER="$2"; shift;;
    --scope) SCOPE="$2"; shift;;
    --stats-seconds) STATS_SECONDS="$2"; shift;;
    --k8s-selector) K8S_SELECTOR="$2"; shift;;
    --k8s-ns) K8S_NS="$2"; shift;;
    --json) JSON_OUT="summary.json";;
    --no-tar) CREATE_TAR=false;;
    --keep-tmp) KEEP_TMP=true;;
    -h|--help) usage;;
    *) echo "Unknown option: $1"; usage;;
  esac
  shift
done

# derive seconds from human if not explicitly set
if [[ -z "${SINCE_SECS:-}" || "$SINCE_SECS" == "86400" ]]; then
  SINCE_SECS=$(parse_human_duration "$SINCE_HUMAN")
fi

mkdir -p "$OUTPUT_DIR"
SUMMARY_FILE="$OUTPUT_DIR/final_summary.txt"
[[ -n "$JSON_OUT" ]] && JSON_OUT="$OUTPUT_DIR/$JSON_OUT"

log() { echo -e "[INFO] $*"; }
warn() { echo -e "[WARN] $*" >&2; }
err() { echo -e "[ERR ] $*" >&2; }

# ------------------------ Redaction ------------------------
redact_stream() {
  if ! $REDACT; then cat; return; fi
  # Base patterns + optional extra
  sed -E "
    s/(Authorization:[[:space:]]*Bearer[[:space:]]+)[A-Za-z0-9\.\-_]+/\1REDACTED/Ig;
    s/([?&](token|key|apikey|api_key|password)=[^&[:space:]]+)/\1_REDACTED/Ig;
    s/(\"?(password|secret|token|key)\"?[[:space:]]*[:=][[:space:]]*\")([^\"]+)/\1REDACTED/Ig;
    s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/REDACTED_IP/g;
  " | if [[ -n "$REDACT_EXTRA_REGEX" ]]; then sed -E "$REDACT_EXTRA_REGEX"; else cat; fi
}

redact_env_stream() {
  if ! $REDACT; then cat; return; fi
  sed -E "
    s/\b(PASSWORD|SECRET|TOKEN|KEY)\b=.*/\1=REDACTED/g;
    s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/REDACTED_IP/g;
  " | if [[ -n "$REDACT_EXTRA_REGEX" ]]; then sed -E "$REDACT_EXTRA_REGEX"; else cat; fi
}

# ------------------------ Tool checks ------------------------
have() { command -v "$1" >/dev/null 2>&1; }
if $REQUIRE_JQ && ! have jq; then
  warn "jq not found. Some JSON-enriched fields will be limited. Install jq for best results."
fi

# ------------------------ Host Diagnostics ------------------------
HOST_OS_INFO="$OUTPUT_DIR/host_system_info.txt"
HOST_OOM_FILE="$OUTPUT_DIR/oom_check.txt"

collect_host() {
  [[ "$SCOPE" == "docker" || "$SCOPE" == "k8s" ]] && return
  log "Collecting host diagnostics..."
  {
    echo "=== OS Info ==="
    uname -a
    [[ -f /etc/os-release ]] && cat /etc/os-release || true
    echo -e "\n=== Disk Space ==="
    df -h
    echo -e "\n=== CPU & Memory ==="
    (have lscpu && lscpu) || echo "lscpu not available"
    free -h || true
  } > "$HOST_OS_INFO" 2>/dev/null || true

  log "Checking host for OOM events..."
  {
    echo "Kernel OOM (dmesg/journalctl) recent entries:"
    (dmesg -T 2>/dev/null || true) | grep -Ei "killed process|out of memory" || echo "None found in dmesg"
    if have journalctl; then
      echo -e "\n--- journalctl -k (recent) ---"
      journalctl -k --since "1 day ago" 2>/dev/null | grep -Ei "killed process|out of memory" || echo "None found in journalctl -k (last day)"
    fi
  } > "$HOST_OOM_FILE" || true
}

# ------------------------ Docker Diagnostics ------------------------
DOCKER_PS_FILE="$OUTPUT_DIR/docker_ps.txt"
CONTAINER_CSV="$OUTPUT_DIR/container_report.csv"
CONTAINER_LIST=()

docker_collect() {
  [[ "$SCOPE" == "host" || "$SCOPE" == "k8s" ]] && return
  if ! have docker || ! docker ps >/dev/null 2>&1; then
    warn "Docker not available or not running; skipping Docker diagnostics."
    return
  fi

  log "Collecting docker ps..."
  docker ps -a > "$DOCKER_PS_FILE" || true

  local filter_args=( )
  [[ -n "$NAME_FILTER" ]] && filter_args+=( "--filter" "name=$NAME_FILTER" )
  if [[ -n "$LABEL_FILTER" ]]; then
    filter_args+=( "--filter" "label=$LABEL_FILTER" )
  fi

  # build list: id name status
  local lines
  lines=$(docker ps -a "${filter_args[@]}" --format '{{.ID}} {{.Names}} {{.Status}}' | sed '/^$/d' || true)
  if [[ -z "$lines" ]]; then
    warn "No containers matched (name~/$NAME_FILTER/ label=$LABEL_FILTER)."
    return
  fi

  echo "Container_Name,Status,n8n_Version,Node_Version,Executions_Mode,Redis_Ping,DB_Ping,Disk_Usage,OS_Version,OOMKilled,ExitCode" > "$CONTAINER_CSV"

  while IFS= read -r line; do
    local ID NAME STATUS
    ID="$(awk '{print $1}' <<<"$line")"
    NAME="$(awk '{print $2}' <<<"$line")"
    STATUS="$(cut -d' ' -f3- <<<"$line" )"
    CONTAINER_LIST+=("$ID::$NAME::$STATUS")
  done <<< "$lines"

  if [[ "$STATS_SECONDS" -gt 0 ]]; then
    log "Sampling docker stats for $STATS_SECONDS seconds..."
    {
      echo "time,container,cpu_percent,mem_usage,mem_percent,net_io,block_io,pids"
      for ((i=0;i<STATS_SECONDS;i++)); do
        docker stats --no-stream --format '{{.Container}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}},{{.PIDs}}' \
        | awk -v ts="$(date +%F_%T)" -F, '{print ts","$0}'
        sleep 1
      done
    } > "$OUTPUT_DIR/docker_stats_sample.csv" || true
  fi

  for entry in "${CONTAINER_LIST[@]}"; do
    local ID NAME STATUS
    IFS="::" read -r ID NAME STATUS <<< "$entry"
    log "→ Inspecting container: $NAME ($STATUS)"

    local out="$OUTPUT_DIR/report_${NAME}.txt"
    local tmp="$OUTPUT_DIR/_tmp_${NAME}"

    mkdir -p "$tmp"

    # Env (with optional redaction)
    if docker exec "$ID" sh -lc 'printenv' >/dev/null 2>&1; then
      docker exec "$ID" sh -lc 'printenv' \
        | redact_env_stream > "$tmp/env.txt" || true
    else
      echo "N/A" > "$tmp/env.txt"
    fi

    # Versions
    docker exec "$ID" sh -lc 'node -v' > "$tmp/node_version.txt" 2>/dev/null || echo "Unknown" > "$tmp/node_version.txt"
    docker exec "$ID" sh -lc 'n8n --version' > "$tmp/n8n_version.txt" 2>/dev/null || echo "Unknown" > "$tmp/n8n_version.txt"

    # Health endpoint (main/worker may share same binary)
    docker exec "$ID" sh -lc 'wget -qO- http://localhost:5678/healthz || curl -sf http://localhost:5678/healthz || true' > "$tmp/healthz.txt" 2>/dev/null || true

    # Execution mode
    docker exec "$ID" sh -lc 'printenv EXECUTIONS_MODE' > "$tmp/exec_mode.txt" 2>/dev/null || echo "unset" > "$tmp/exec_mode.txt"

    # n8n config presence (do not leak encryptionKey)
    docker exec "$ID" sh -lc 'test -f /home/node/.n8n/config && echo present || echo missing' > "$tmp/config_present.txt" 2>/dev/null || echo "unknown" > "$tmp/config_present.txt"
    docker exec "$ID" sh -lc 'test -f /home/node/.n8n/config && (grep -q "\"encryptionKey\"" /home/node/.n8n/config && echo "encryptionKey: present" || echo "encryptionKey: missing") || true' \
      > "$tmp/config_flags.txt" 2>/dev/null || true

    # Disk, OS
    docker exec "$ID" sh -lc 'df -h' > "$tmp/disk.txt" 2>/dev/null || true
    docker exec "$ID" sh -lc 'cat /etc/os-release 2>/dev/null || uname -a' > "$tmp/osinfo.txt" 2>/dev/null || true
    local DISK_USAGE
    DISK_USAGE="$(docker exec "$ID" sh -lc 'df -h / 2>/dev/null | awk "NR==2{print \$5\" used\"}"' 2>/dev/null || echo "")"

    local OS_VERSION
    OS_VERSION="$(grep -m1 PRETTY_NAME "$tmp/osinfo.txt" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"
    [[ -z "$OS_VERSION" ]] && OS_VERSION="$(head -n1 "$tmp/osinfo.txt" 2>/dev/null || echo "Unknown")"

    # Logs (since + optional tail)
    local log_cmd=( docker logs "--since" "${SINCE_SECS}s" "$ID" )
    [[ -n "$TAIL_LINES" ]] && log_cmd+=( "--tail" "$TAIL_LINES" )
    "${log_cmd[@]}" 2>&1 | redact_stream > "$tmp/logs.txt" || true

    # Inspect for OOMKilled / exit code / limits
    local INSPECT_JSON
    if have jq; then
      INSPECT_JSON="$(docker inspect "$ID" 2>/dev/null || echo "[]")"
      local OOMKILLED EXITCODE MEMORY CPUQUOTA
      OOMKILLED="$(jq -r '.[0].State.OOMKilled' <<<"$INSPECT_JSON" 2>/dev/null || echo "")"
      EXITCODE="$(jq -r '.[0].State.ExitCode' <<<"$INSPECT_JSON" 2>/dev/null || echo "")"
      MEMORY="$(jq -r '.[0].HostConfig.Memory' <<<"$INSPECT_JSON" 2>/dev/null || echo "")"
      CPUQUOTA="$(jq -r '.[0].HostConfig.CpuQuota' <<<"$INSPECT_JSON" 2>/dev/null || echo "")"
      echo "OOMKilled: $OOMKILLED" > "$tmp/limits.txt"
      echo "ExitCode: $EXITCODE" >> "$tmp/limits.txt"
      echo "MemoryLimit(bytes): ${MEMORY:-0}" >> "$tmp/limits.txt"
      if [[ -n "$CPUQUOTA" && "$CPUQUOTA" != "0" ]]; then
        awk -v q="$CPUQUOTA" 'BEGIN{printf "CPUQuota: %s (~CPUs: %.1f)\n", q, q/100000}' >> "$tmp/limits.txt"
      else
        echo "CPUQuota: 0 (unlimited)" >> "$tmp/limits.txt"
      fi
    else
      docker inspect "$ID" > "$tmp/inspect.txt" 2>/dev/null || true
      echo "OOMKilled: (jq not installed)" > "$tmp/limits.txt"
      echo "ExitCode: (jq not installed)" >> "$tmp/limits.txt"
      echo "MemoryLimit(bytes): (jq not installed)" >> "$tmp/limits.txt"
      echo "CPUQuota: (jq not installed)" >> "$tmp/limits.txt"
    fi

    # Redis / DB probes from inside the container (best effort)
    {
      echo "RedisPing=$(docker exec "$ID" sh -lc 'redis-cli -h ${QUEUE_BULL_REDIS_HOST:-redis} -p ${QUEUE_BULL_REDIS_PORT:-6379} ${QUEUE_BULL_REDIS_PASSWORD:+-a $QUEUE_BULL_REDIS_PASSWORD} ping 2>/dev/null || echo FAIL')"
      echo "DBPing=$(docker exec "$ID" sh -lc 'PGPASSWORD="${DB_POSTGRESDB_PASSWORD}" psql -h ${DB_POSTGRESDB_HOST:-postgres} -U ${DB_POSTGRESDB_USER:-n8n} -d ${DB_POSTGRESDB_DATABASE:-n8n} -c "select 1" -tA 2>/dev/null || echo FAIL')"
    } > "$tmp/probes.txt" || true

    # Build merged report
    {
      echo "==== Container: $NAME ===="
      echo "Status: $STATUS"
      echo "Node Version: $(cat "$tmp/node_version.txt")"
      echo "n8n Version: $(cat "$tmp/n8n_version.txt")"
      echo "Healthz: $(tr -d '\n' < "$tmp/healthz.txt" | sed 's/[[:space:]]\+/ /g')"
      echo "Executions Mode: $(cat "$tmp/exec_mode.txt")"
      echo "Config: $(cat "$tmp/config_present.txt"); $(cat "$tmp/config_flags.txt" 2>/dev/null || echo '')"
      echo "Disk Usage: ${DISK_USAGE:-unknown}"
      echo "OS Version: $OS_VERSION"
      echo "--- Limits / Exit ---"
      cat "$tmp/limits.txt" 2>/dev/null || true
      echo "--- Probes ---"
      cat "$tmp/probes.txt" 2>/dev/null || true

      echo -e "\n=== ENVIRONMENT VARIABLES ==="
      cat "$tmp/env.txt"
      echo -e "\n=== DISK SPACE ==="
      cat "$tmp/disk.txt"
      echo -e "\n=== OS INFO ==="
      cat "$tmp/osinfo.txt"
      echo -e "\n=== LOGS (since $SINCE_HUMAN ${TAIL_LINES:+, tail $TAIL_LINES}) ==="
      cat "$tmp/logs.txt"
    } > "$out"

    # Extract fields for CSV
    local NVER NODEVER MODE REDISP DBP OOMK EXITC
    NVER="$(cat "$tmp/n8n_version.txt" 2>/dev/null || echo Unknown)"
    NODEVER="$(cat "$tmp/node_version.txt" 2>/dev/null || echo Unknown)"
    MODE="$(cat "$tmp/exec_mode.txt" 2>/dev/null || echo unset)"
    REDISP="$(grep -m1 '^RedisPing=' "$tmp/probes.txt" 2>/dev/null | cut -d= -f2- || echo N/A)"
    DBP="$(grep -m1 '^DBPing=' "$tmp/probes.txt" 2>/dev/null | cut -d= -f2- || echo N/A)"
    if have jq; then
      OOMK="$(grep -m1 '^OOMKilled:' "$tmp/limits.txt" | awk '{print $2}')"
      EXITC="$(grep -m1 '^ExitCode:' "$tmp/limits.txt" | awk '{print $2}')"
    else
      OOMK="unknown"; EXITC="unknown"
    fi
    echo "$NAME,$STATUS,$NVER,$NODEVER,$MODE,$REDISP,$DBP,${DISK_USAGE:-},$OS_VERSION,$OOMK,$EXITC" >> "$CONTAINER_CSV"

    rm -rf "$tmp"
  done

  # Simple queue-mode sanity: warn if EXECUTIONS_MODE=queue but no worker containers found
  if grep -q ',queue,' "$CONTAINER_CSV"; then
    local workers
    workers=$(awk -F, '/,queue,/{print $1}' "$CONTAINER_CSV" | grep -ci 'worker' || true)
    if [[ "${workers:-0}" -eq 0 ]]; then
      warn "Queue mode detected but no worker containers matched filters — check scaling and filters."
    fi
  fi
}

# ------------------------ Kubernetes Diagnostics ------------------------
collect_k8s() {
  [[ "$SCOPE" == "host" || "$SCOPE" == "docker" ]] && return
  if ! have kubectl; then
    warn "kubectl not found; skipping Kubernetes diagnostics."
    return
  fi

  # list pods matching selector
  local podlist
  if [[ -n "$K8S_NS" ]]; then
    podlist=$(kubectl get pods -n "$K8S_NS" -l "$K8S_SELECTOR" --no-headers 2>/dev/null || true)
  else
    podlist=$(kubectl get pods -A -l "$K8S_SELECTOR" --no-headers 2>/dev/null || true)
  fi

  if [[ -z "$podlist" ]]; then
    warn "No Kubernetes pods matched selector '$K8S_SELECTOR' (ns=${K8S_NS:-all}); skipping."
    return
  fi

  log "Collecting Kubernetes pod info/logs..."
  if [[ -n "$K8S_NS" ]]; then
    kubectl get pods -n "$K8S_NS" -l "$K8S_SELECTOR" -o wide > "$OUTPUT_DIR/k8s_pods.txt" || true
    kubectl logs -n "$K8S_NS" -l "$K8S_SELECTOR" --tail=1000 --all-containers \
      | redact_stream > "$OUTPUT_DIR/k8s_logs.txt" || true
  else
    kubectl get pods -A -l "$K8S_SELECTOR" -o wide > "$OUTPUT_DIR/k8s_pods.txt" || true
    kubectl logs -A -l "$K8S_SELECTOR" --tail=1000 --all-containers \
      | redact_stream > "$OUTPUT_DIR/k8s_logs.txt" || true
  fi
}

# ------------------------ Summaries ------------------------
write_summaries() {
  log "Generating summaries…"
  local disk_summary
  disk_summary=$(df -h | awk '/^\/dev\// {printf "%s %s used on %s; ", $1, $5, $6}')
  local docker_used="No"
  local k8s_used="No"
  [[ -f "$DOCKER_PS_FILE" ]] && docker_used="Yes"
  [[ -f "$OUTPUT_DIR/k8s_pods.txt" ]] && k8s_used="Yes"
  local n_containers=0
  [[ -f "$CONTAINER_CSV" ]] && n_containers=$(($(wc -l < "$CONTAINER_CSV") - 1))

  {
    echo "n8n Diagnostic Summary Report"
    echo "------------------------------------------"
    echo "- Host: $(uname -a)"
    echo "- Disk Summary: $disk_summary"
    echo "- Docker Used: $docker_used"
    echo "- Kubernetes Used: $k8s_used"
    echo "- Containers Matched: $n_containers"
    echo "- Redaction Enabled: $REDACT"
    echo "- Time Window: ${SINCE_HUMAN} (${SINCE_SECS}s) ${TAIL_LINES:+, tail $TAIL_LINES lines}"
    [[ -f "$CONTAINER_CSV" ]] && echo "- Version Table: $(basename "$CONTAINER_CSV")"
    [[ -f "$OUTPUT_DIR/docker_stats_sample.csv" ]] && echo "- Stats Sample: docker_stats_sample.csv (${STATS_SECONDS}s)"
    echo "------------------------------------------"
    echo "Findings:"
    if [[ -f "$CONTAINER_CSV" ]]; then
      # Simple heuristics:
      if grep -q ',queue,' "$CONTAINER_CSV"; then
        local wc
        wc=$(grep -E ',queue,' "$CONTAINER_CSV" | grep -ci 'worker' || true)
        if [[ "${wc:-0}" -eq 0 ]]; then
          echo "• Queue mode detected but no worker containers found (by name)."
        fi
      fi
      if grep -q 'FAIL' "$OUTPUT_DIR"/report_* 2>/dev/null; then
        echo "• One or more containers failed Redis/DB probes. See report_* files."
      fi
      if grep -qi 'oomkilled: *true' "$OUTPUT_DIR"/report_* 2>/dev/null; then
        echo "• OOMKilled detected in one or more containers."
      fi
    else
      echo "• No containers collected (filters may be too strict)."
    fi
    echo "------------------------------------------"
    echo "Bundle directory: $OUTPUT_DIR"
  } | tee "$SUMMARY_FILE" >/dev/null

  if [[ -n "$JSON_OUT" ]]; then
    {
      echo '{'
      echo "  \"host\": $(jq -Rn --arg v "$(uname -a)" '{os:$v}'),"
      echo "  \"dockerUsed\": \"$docker_used\","
      echo "  \"kubernetesUsed\": \"$k8s_used\","
      echo "  \"containers\": $n_containers,"
      echo "  \"redaction\": $REDACT,"
      echo "  \"timeWindow\": {\"human\":\"$SINCE_HUMAN\",\"seconds\":$SINCE_SECS},"
      if [[ -f "$CONTAINER_CSV" ]]; then
        echo -n "  \"csv\": "
        jq -Rs 'split("\n") | map(select(length>0))' < "$CONTAINER_CSV"
        echo ","
      fi
      echo "  \"notes\": [\"Check report_<container>.txt files for detailed logs and probes\"]"
      echo '}'
    } > "$JSON_OUT" 2>/dev/null || warn "Could not write JSON summary (jq recommended)."
  fi
}

# ------------------------ Pack & finish ------------------------
pack_and_finish() {
  if $CREATE_TAR; then
    log "Compressing output…"
    local tarball="${OUTPUT_DIR}.tar.gz"
    tar -czf "$tarball" "$OUTPUT_DIR"
    sha256sum "$tarball" | tee "${tarball}.sha256" >/dev/null || true
    du -h "$tarball" | awk '{print "[INFO] Bundle size: "$1}'
    if ! $KEEP_TMP; then
      rm -rf "$OUTPUT_DIR"
    fi
    log "Done! Bundle saved: $tarball"
    log "Checksum: ${tarball}.sha256"
  else
    log "Done! Files left in: $OUTPUT_DIR"
  fi
}

# ------------------------ Run ------------------------
collect_host
docker_collect
collect_k8s
write_summaries
pack_and_finish
