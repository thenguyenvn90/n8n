#!/usr/bin/env bash
################################################################################
# n8n Support Collector v3 (enhanced)
#
# Description:
#   A comprehensive diagnostics collector for n8n running on Docker and/or
#   Kubernetes. It gathers host, container, and cluster context; captures
#   timestamped logs (including Kubernetes "previous" container logs); inspects
#   resource limits, OOM events, restarts; probes Redis/Postgres health from
#   inside containers; and generates human-readable and optional JSON summaries.
#   Sensitive info can be redacted (with optional hashed placeholders).
#
# Key Capabilities:
#   - Host snapshots: OS, CPU/memory, disk, kernel OOM traces, cgroup limits.
#   - Docker context: version/info, networks, volumes, compose state, events,
#     container inspect JSON, stats sampling, logs with timestamps+details,
#     stdout/stderr splits, optional raw json-file logs.
#   - Kubernetes context: pods/nodes inventory & describe, resource usage
#     (kubectl top), events timeline, workloads & networking inventory, logs
#     for current and previous containers with timestamps.
#   - n8n awareness: versions, EXECUTIONS_MODE, safe config dump (sans secrets),
#     queue-mode sanity checks (warn if queue mode but no workers detected).
#   - Redaction: removes/obscures common secret patterns in logs and ENV,
#     optional SHA1 hashing for ENV secrets to correlate without exposing.
#   - Outputs: per-container reports, CSV (quoted), optional JSON summary,
#     compressed tarball with checksum (unless disabled).
#
# Safety & Scope:
#   - Unofficial community tool — review outputs before sharing externally.
#   - Redaction is best-effort. Use --redact (and optionally --hash-redactions).
#   - --copy-raw-json may copy large/rotated Docker json logs (root required).
#
# Typical Usage:
#   ./n8n-support-collector.sh --redact
#   ./n8n-support-collector.sh -s 2h --name-filter '^(n8n|n8n-worker)' --json
#   ./n8n-support-collector.sh --since-seconds 7200 --stats-seconds 15 --redact
#   ./n8n-support-collector.sh --redact --hash-redactions --copy-raw-json
#
# Outputs:
#   - final_summary.txt                 (human summary)
#   - summary.json                      (optional)
#   - container_report.csv              (quoted CSV)
#   - container_report.tsv              (raw TSV)
#   - container_report_table.txt        (pretty aligned table)
#   - report_<container>.txt            (per-container merged report)
#   - docker_*.txt / k8s_*.txt          (contextual artifacts)
#   - inspect_<container>.json          (full docker inspect)
#   - <bundle>.tar.gz + .sha256         (unless --no-tar)
#
# Notes:
#   - Uses timeouts to prevent hangs on slow shells/exec.
#   - Emits warnings when filters match no containers/pods.
#   - Designed for incident triage, post-mortems, and support bundles.
################################################################################

set -euo pipefail

# trap errors so we still produce a summary/bundle
trap 'code=$?; [[ $code -ne 0 ]] && echo "[ERR ] Aborted at line $LINENO (exit $code)" >&2' ERR

# ------------------------ Defaults ------------------------
SINCE_HUMAN="24h"            # human-friendly: 24h, 2h, 45m, 300s
SINCE_SECS=86400             # derived from SINCE_HUMAN unless overridden
SINCE_SECS_EXPLICIT=false    # set true if --since-seconds was provided
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
COPY_RAW_JSON_LOGS=false     # opt-in: copy /var/lib/docker/.../container.json logs (root)
HASH_REDACTIONS=false        # opt-in: stable hashes for redacted ENV secrets
EXEC_TIMEOUT=10              # seconds for docker exec/kubectl where applicable

################################################################################
# usage()
# Description:
#   Print CLI usage and examples, then exit.
#
# Behaviors:
#   - Shows all flags, defaults, and examples.
#
# Returns:
#   Exits with code 1.
################################################################################
usage() {
  cat <<EOF
n8n Support Collector v3

Usage:
  \$0 [options]

Options:
  -s, --since <dur>        Log window: 24h, 2h, 30m, 300s (default: 24h)
  -t, --since-seconds <n>  Log window in seconds (overrides --since)
  --tail <n>               Limit docker logs to last N lines
  -o, --output <dir>       Output directory (default: $OUTPUT_DIR)

  --redact                 Redact secrets in env and logs.
                           Recommended when sharing bundles externally.
  --hash-redactions        Add-on to --redact: replace env secret values with
                           REDACTED[sha1] so you can correlate identical values
                           without exposing them.
  --redact-pattern <re>    Extra regex (sed -E) for redaction in logs/env.

  --name-filter <regex>    Only containers whose names match regex
                           (default: ^(n8n-main|n8n-worker))
  --label-filter <key=val> Only containers with this docker label

  --scope <scope>          host|docker|k8s|all (default: all)
  --stats-seconds <n>      Sample docker stats for n seconds

  --k8s-selector <kv>      k8s label selector (default: app=n8n)
  --k8s-ns <name>          k8s namespace (default: all namespaces)

  --json                   Emit summary.json alongside text summary
  --no-tar                 Do NOT compress results
  --keep-tmp               Keep working directory (don’t delete after tar)
  --copy-raw-json          Copy raw Docker json logs (root; can be very large)
  --exec-timeout <sec>     Timeout for exec/log commands (default: 10)

  -h, --help               Show this help

Examples:
  \$0 --redact
  \$0 --redact --hash-redactions
  \$0 -s 2h --name-filter '^(n8n-main|n8n-worker)' --json
  \$0 --since-seconds 7200 --stats-seconds 15 --redact --no-tar
EOF
  exit 1
}

################################################################################
# parse_human_duration(s)
# Description:
#   Convert human-readable duration (e.g., "24h", "30m", "300s", "120") to
#   seconds.
#
# Inputs:
#   $1 - Human duration string.
#
# Returns:
#   Echoes integer seconds (defaults to 86400 when unrecognized).
################################################################################
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
    echo 86400
  fi
}

# ------------------------ Arg Parsing ------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--since) SINCE_HUMAN="$2"; shift;;
    -t|--since-seconds) SINCE_SECS="$2"; SINCE_HUMAN="${2}s"; SINCE_SECS_EXPLICIT=true; shift;;
    --tail) TAIL_LINES="$2"; shift;;
    -o|--output) OUTPUT_DIR="$2"; shift;;
    --redact) REDACT=true;;
    --redact-pattern) REDACT_EXTRA_REGEX="$2"; shift;;
    --hash-redactions) HASH_REDACTIONS=true;;
    --name-filter) NAME_FILTER="$2"; shift;;
    --label-filter) LABEL_FILTER="$2"; shift;;
    --scope) SCOPE="$2"; shift;;
    --stats-seconds) STATS_SECONDS="$2"; shift;;
    --k8s-selector) K8S_SELECTOR="$2"; shift;;
    --k8s-ns) K8S_NS="$2"; shift;;
    --json) JSON_OUT="summary.json";;
    --no-tar) CREATE_TAR=false;;
    --keep-tmp) KEEP_TMP=true;;
    --copy-raw-json) COPY_RAW_JSON_LOGS=true;;
    --exec-timeout) EXEC_TIMEOUT="$2"; shift;;
    -h|--help) usage;;
    *) echo "Unknown option: $1"; usage;;
  esac
  shift
done

# derive seconds from human if not explicitly set
if ! $SINCE_SECS_EXPLICIT; then
  SINCE_SECS=$(parse_human_duration "$SINCE_HUMAN")
fi

mkdir -p "$OUTPUT_DIR"
SUMMARY_FILE="$OUTPUT_DIR/final_summary.txt"
[[ -n "$JSON_OUT" ]] && JSON_OUT="$OUTPUT_DIR/$JSON_OUT"

################################################################################
# log(), warn(), err()
# Description:
#   Convenience log helpers for INFO/WARN/ERR prefixes.
#
# Behaviors:
#   - log:   prints to stdout
#   - warn:  prints to stderr with [WARN] prefix
#   - err:   prints to stderr with [ERR ] prefix
#
# Returns:
#   0 always.
################################################################################
log() { echo -e "[INFO] $*"; }
warn() { echo -e "[WARN] $*" >&2; }
err() { echo -e "[ERR ] $*" >&2; }

################################################################################
# have(cmd)
# Description:
#   Check if a command exists in PATH.
#
# Inputs:
#   $1 - Command/binary name.
#
# Returns:
#   0 if found; 1 otherwise.
################################################################################
have() { command -v "$1" >/dev/null 2>&1; }

TIMEOUT_BIN="$(command -v timeout || true)"

################################################################################
# run_with_timeout(seconds, cmd...)
# Description:
#   Execute a command with a timeout when 'timeout' is available; otherwise
#   execute directly.
#
# Inputs:
#   $1     - Timeout in seconds (integer; 0 disables timeout).
#   $2..N  - Command and arguments to execute.
#
# Behaviors:
#   - Preserves exit status when 'timeout' is used (--preserve-status).
#   - Prevents long-hanging docker/kubectl exec/log calls.
#
# Returns:
#   Exit status of the invoked command (or timeout).
################################################################################
run_with_timeout() {
  local secs="$1"; shift
  if [[ -n "$TIMEOUT_BIN" && "$secs" -gt 0 ]]; then
    timeout --preserve-status "$secs" "$@"
  else
    "$@"
  fi
}

################################################################################
# sha1_of(string)
# Description:
#   Compute SHA1 of a given string and print the hex digest.
#
# Inputs:
#   $1 - Input string (passed via printf).
#
# Returns:
#   Echoes hex digest (40 chars).
################################################################################
sha1_of() { printf "%s" "$1" | sha1sum | awk '{print $1}'; }

# ------------------------ Redaction ------------------------
################################################################################
# redact_stream()
# Description:
#   Redact sensitive tokens from arbitrary text streams (logs, outputs).
#
# Behaviors:
#   - Removes Authorization Bearer tokens, common URL credentials, likely JWTs.
#   - Redacts emails, IPv4/IPv6 addresses.
#   - Redacts common secret key names (password/secret/token/key/pass/AWS keys).
#   - Applies extra user-provided sed regex when --redact-pattern is set.
#   - No-ops when --redact is not enabled.
#
# Returns:
#   0 on success; acts as a filter on stdin/stdout.
################################################################################
redact_stream() {
  if ! $REDACT; then cat; return; fi
  sed -E "
    s/(Authorization:[[:space:]]*Bearer[[:space:]]+)[A-Za-z0-9_\-\.]+/\1REDACTED/Ig;
    s/([?&](token|key|apikey|api_key|password|pass|secret)=[^&[:space:]]+)/\1_REDACTED/Ig;
    s#(https?://)[^/@[:space:]]+:[^/@[:space:]]+@#\1REDACTED:REDACTED@#g;
    s/(\"?(password|secret|token|key|pass|aws_access_key_id|aws_secret_access_key|n8n_encryption_key)\"?[[:space:]]*[:=][[:space:]]*\")([^\"]+)/\1REDACTED/Ig;
    s/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/REDACTED_EMAIL/g;
    s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/REDACTED_IPv4/g;
    s/\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b/REDACTED_IPv6/g;
    s/\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/REDACTED_JWT/g;
  " | if [[ -n "$REDACT_EXTRA_REGEX" ]]; then sed -E "$REDACT_EXTRA_REGEX"; else cat; fi
}

################################################################################
# redact_env_lines()
# Description:
#   Redact sensitive environment variables from VAR=VAL lines. Supports optional
#   SHA1 hashing of redacted values for correlation without disclosure.
#
# Behaviors:
#   - Redacts: PASSWORD, SECRET, TOKEN, KEY, PASS, AWS_ACCESS_KEY_ID,
#              AWS_SECRET_ACCESS_KEY, N8N_ENCRYPTION_KEY.
#   - Rewrites non-secret envs to redact emails and IP addresses.
#   - Applies extra user-provided sed regex when --redact-pattern is set.
#   - When --hash-redactions is enabled, prints REDACTED[sha1] for secret values.
#
# Returns:
#   0 on success; acts as a filter on stdin/stdout.
################################################################################
redact_env_lines() {
  while IFS= read -r line; do
    if ! $REDACT; then
      echo "$line"
      continue
    fi
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      local key="${BASH_REMATCH[1]}"
      local val="${BASH_REMATCH[2]}"
      if [[ "$key" =~ ^(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|PASSWORD|SECRET|TOKEN|KEY|PASS|N8N_ENCRYPTION_KEY)$ ]]; then
        if $HASH_REDACTIONS; then
          local h; h="$(sha1_of "$val")"
          echo "${key}=REDACTED[${h}]"
        else
          echo "${key}=REDACTED"
        fi
      else
        echo "${key}=${val}" | sed -E "
          s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/REDACTED_IPv4/g;
          s/\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b/REDACTED_IPv6/g;
          s/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/REDACTED_EMAIL/g;
        "
      fi
    else
      echo "$line"
    fi
  done | if [[ -n "$REDACT_EXTRA_REGEX" ]]; then sed -E "$REDACT_EXTRA_REGEX"; else cat; fi
}

# ------------------------ Tool checks ------------------------
if $REQUIRE_JQ && ! have jq; then
  warn "jq not found. Some JSON-enriched fields will be limited. Install jq for best results."
fi

# ------------------------ Host Diagnostics ------------------------
HOST_OS_INFO="$OUTPUT_DIR/host_system_info.txt"
HOST_OOM_FILE="$OUTPUT_DIR/oom_check.txt"

################################################################################
# collect_host()
# Description:
#   Collect host-level diagnostics unless scope limits to docker/k8s only.
#
# Behaviors:
#   - Captures OS info, disk usage, CPU/memory, cgroup memory constraints.
#   - Greps kernel/journal OOM events from last day.
#
# Outputs:
#   - host_system_info.txt
#   - oom_check.txt
#
# Returns:
#   0 on best-effort success (never hard-fails the script).
################################################################################
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
    echo -e "\n=== cgroup memory limits (if any) ==="
    (grep -H . /sys/fs/cgroup/*/memory.max 2>/dev/null || true)
    (grep -H . /sys/fs/cgroup/*/memory.current 2>/dev/null || true)
  } > "$HOST_OS_INFO" 2>/dev/null || true

  log "Checking host for OOM events..."
  {
    echo "Kernel OOM (dmesg/journalctl) recent entries:"
    (dmesg -T 2>/dev/null || true) | grep -Ei "killed process|out of memory" || echo "None found in dmesg"
    if have journalctl; then
      echo -e "\n--- journalctl -k (recent) ---"
      journalctl --no-pager -k --since "1 day ago" 2>/dev/null | grep -Ei "killed process|out of memory" || echo "None found in journalctl -k (last day)"
    fi
  } > "$HOST_OOM_FILE" || true
}

# ------------------------ Docker Diagnostics ------------------------
DOCKER_PS_FILE="$OUTPUT_DIR/docker_ps.txt"
CONTAINER_CSV="$OUTPUT_DIR/container_report.csv"
CONTAINER_TSV_RAW="$OUTPUT_DIR/container_report.tsv"
CONTAINER_TABLE_TXT="$OUTPUT_DIR/container_report_table.txt"
CONTAINER_LIST=()

################################################################################
# docker_collect()
# Description:
#   Gather Docker daemon context, per-container diagnostics, logs, probes, and
#   CSV/TSV summary for matched containers.
#
# Behaviors:
#   - Captures docker version/info/system df/networks/volumes/compose.
#   - Records docker events in the selected time window.
#   - Filters containers by name regex and/or label filter.
#   - For each container:
#       * Env (with redaction), Node/n8n versions, healthz.
#       * n8n EXECUTIONS_MODE, config presence & encryptionKey flag.
#       * Disk/OS info, timestamped logs with details + stdout/stderr split.
#       * Inspect-derived limits: OOMKilled, ExitCode, Memory, CPUQuota, restarts,
#         start/finish timestamps.
#       * Redis ping & Postgres "select 1" probes.
#       * Optional raw json-file logs copy (root), full inspect JSON.
#       * Merged human report file.
#   - Samples docker stats if --stats-seconds > 0.
#   - Writes quoted CSV row + TSV row per container.
#   - Warns if queue mode detected but no worker containers matched.
#
# Outputs:
#   - docker_version.txt, docker_info.txt, docker_system_df.txt
#   - docker_networks.txt, docker_volumes.txt
#   - docker_compose_{ls,ps}.txt (when docker compose available)
#   - docker_events.txt
#   - docker_ps.txt
#   - docker_stats_sample.csv (optional)
#   - inspect_<container>.json
#   - report_<container>.txt
#   - container_report.csv
#   - container_report.tsv
#
# Returns:
#   0 on best-effort success; non-fatal warnings if docker unavailable.
################################################################################
docker_collect() {
  [[ "$SCOPE" == "host" || "$SCOPE" == "k8s" ]] && return
  if ! have docker || ! docker ps >/dev/null 2>&1; then
    warn "Docker not available or not running; skipping Docker diagnostics."
    return
  fi

  log "Collecting Docker daemon context..."
  docker version > "$OUTPUT_DIR/docker_version.txt" 2>/dev/null || true
  docker info > "$OUTPUT_DIR/docker_info.txt" 2>/dev/null || true
  docker system df > "$OUTPUT_DIR/docker_system_df.txt" 2>/dev/null || true
  docker network ls > "$OUTPUT_DIR/docker_networks.txt" 2>/dev/null || true
  docker volume ls > "$OUTPUT_DIR/docker_volumes.txt" 2>/dev/null || true
  if docker compose version >/dev/null 2>&1; then
    docker compose ls > "$OUTPUT_DIR/docker_compose_ls.txt" 2>/dev/null || true
    docker compose ps -a > "$OUTPUT_DIR/docker_compose_ps.txt" 2>/dev/null || true
  fi
  run_with_timeout "$EXEC_TIMEOUT" docker events --since "${SINCE_SECS}s" > "$OUTPUT_DIR/docker_events.txt" 2>/dev/null || true

  log "Collecting docker ps..."
  docker ps -a > "$DOCKER_PS_FILE" || true

  local filter_args=( )
  [[ -n "$NAME_FILTER" ]] && filter_args+=( "--filter" "name=$NAME_FILTER" )
  if [[ -n "$LABEL_FILTER" ]]; then
    filter_args+=( "--filter" "label=$LABEL_FILTER" )
  fi

  local lines
  lines=$(docker ps -a "${filter_args[@]}" --format '{{.ID}} {{.Names}} {{.Status}}' | sed '/^$/d' || true)
  if [[ -z "$lines" ]]; then
    warn "No containers matched (name~/$NAME_FILTER/ label=$LABEL_FILTER)."
    return
  fi

  echo "Container_Name,Status,n8n_Version,Node_Version,Executions_Mode,Redis_Ping,DB_Ping,Disk_Usage,OS_Version,OOMKilled,ExitCode" > "$CONTAINER_CSV"
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "Container_Name" "Status" "n8n_Version" "Node_Version" "Executions_Mode" "Redis_Ping" "DB_Ping" "Disk_Usage" "OS_Version" "OOMKilled" "ExitCode" \
    > "$CONTAINER_TSV_RAW"

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

  while IFS= read -r line; do
    local ID NAME STATUS
    ID="$(awk '{print $1}' <<<"$line")"
    NAME="$(awk '{print $2}' <<<"$line")"
    STATUS="$(cut -d' ' -f3- <<<"$line" )"
    CONTAINER_LIST+=("$ID::$NAME::$STATUS")
  done <<< "$lines"

  for entry in "${CONTAINER_LIST[@]}"; do
    local ID NAME STATUS
    IFS="::" read -r ID NAME STATUS <<< "$entry"
    log "→ Inspecting container: $NAME ($STATUS)"

    local out="$OUTPUT_DIR/report_${NAME}.txt"
    local tmp="$OUTPUT_DIR/_tmp_${NAME}"

    mkdir -p "$tmp"

    # Env (with optional redaction/hash)
    if run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'printenv' >/dev/null 2>&1; then
      run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'printenv' \
        | redact_env_lines > "$tmp/env.txt" || true
    else
      echo "N/A" > "$tmp/env.txt"
    fi

    # Versions
    run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'node -v' > "$tmp/node_version.txt" 2>/dev/null || echo "Unknown" > "$tmp/node_version.txt"
    run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'n8n --version' > "$tmp/n8n_version.txt" 2>/dev/null || echo "Unknown" > "$tmp/n8n_version.txt"

    # Health endpoint
    run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'wget -qO- http://localhost:5678/healthz || curl -sf http://localhost:5678/healthz || true' > "$tmp/healthz.txt" 2>/dev/null || true

    # Execution mode
    run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'printenv EXECUTIONS_MODE' > "$tmp/exec_mode.txt" 2>/dev/null || echo "unset" > "$tmp/exec_mode.txt"

    # n8n config presence (do not leak encryptionKey)
    run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'test -f /home/node/.n8n/config && echo present || echo missing' > "$tmp/config_present.txt" 2>/dev/null || echo "unknown" > "$tmp/config_present.txt"
    run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'test -f /home/node/.n8n/config && (grep -q "\"encryptionKey\"" /home/node/.n8n/config && echo "encryptionKey: present" || echo "encryptionKey: missing") || true' \
      > "$tmp/config_flags.txt" 2>/dev/null || true

    # Optional: safe config dump keys
    run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'n8n config:show 2>/dev/null' \
      | grep -Ev '(encryptionKey|password|secret|token|key)' \
      | redact_stream > "$tmp/n8n_config_show.txt" 2>/dev/null || true

    # Disk, OS
    run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'df -h' > "$tmp/disk.txt" 2>/dev/null || true
    run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'cat /etc/os-release 2>/dev/null || uname -a' > "$tmp/osinfo.txt" 2>/dev/null || true
    local DISK_USAGE
    DISK_USAGE="$(run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'df -h / 2>/dev/null | awk "NR==2{print \$5\" used\"}"' 2>/dev/null || echo "")"

    local OS_VERSION
    OS_VERSION="$(grep -m1 PRETTY_NAME "$tmp/osinfo.txt" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"
    [[ -z "$OS_VERSION" ]] && OS_VERSION="$(head -n1 "$tmp/osinfo.txt" 2>/dev/null || echo "Unknown")"

    # Logs (timestamps + details; split stdout/stderr)
    local log_base=( docker logs "--since" "${SINCE_SECS}s" "--timestamps" "--details" "$ID" )
    if [[ -n "$TAIL_LINES" ]]; then
      log_base+=( "--tail" "$TAIL_LINES" )
    fi
    run_with_timeout "$EXEC_TIMEOUT" "${log_base[@]}" > "$tmp/combined.log" 2>&1 || true
    run_with_timeout "$EXEC_TIMEOUT" docker logs --since "${SINCE_SECS}s" --timestamps --details "$ID" 1> "$tmp/stdout.log" 2> "$tmp/stderr.log" || true

    # Inspect for OOMKilled / exit code / limits / restarts / times
    local INSPECT_JSON
    if have jq; then
      INSPECT_JSON="$(docker inspect "$ID" 2>/dev/null || echo "[]")"
      local OOMKILLED EXITCODE MEMORY CPUQUOTA RESTARTS STARTED FINISHED
      OOMKILLED="$(jq -r '.[0].State.OOMKilled' <<<"$INSPECT_JSON" 2>/dev/null || echo "")"
      EXITCODE="$(jq -r '.[0].State.ExitCode' <<<"$INSPECT_JSON" 2>/dev/null || echo "")"
      MEMORY="$(jq -r '.[0].HostConfig.Memory' <<<"$INSPECT_JSON" 2>/dev/null || echo "")"
      CPUQUOTA="$(jq -r '.[0].HostConfig.CpuQuota' <<<"$INSPECT_JSON" 2>/dev/null || echo "")"
      RESTARTS="$(jq -r '.[0].RestartCount' <<<"$INSPECT_JSON" 2>/dev/null || echo "0")"
      STARTED="$(jq -r '.[0].State.StartedAt' <<<"$INSPECT_JSON" 2>/dev/null || echo "")"
      FINISHED="$(jq -r '.[0].State.FinishedAt' <<<"$INSPECT_JSON" 2>/dev/null || echo "")"
      {
        echo "OOMKilled: $OOMKILLED"
        echo "ExitCode: $EXITCODE"
        echo "MemoryLimit(bytes): ${MEMORY:-0}"
        if [[ -n "$CPUQUOTA" && "$CPUQUOTA" != "0" ]]; then
          awk -v q="$CPUQUOTA" 'BEGIN{printf "CPUQuota: %s (~CPUs: %.1f)\n", q, q/100000}'
        else
          echo "CPUQuota: 0 (unlimited)"
        fi
        echo "RestartCount: ${RESTARTS:-0}"
        echo "StartedAt: ${STARTED:-unknown}"
        echo "FinishedAt: ${FINISHED:-unknown}"
      } > "$tmp/limits.txt"
    else
      docker inspect "$ID" > "$tmp/inspect.txt" 2>/dev/null || true
      {
        echo "OOMKilled: (jq not installed)"
        echo "ExitCode: (jq not installed)"
        echo "MemoryLimit(bytes): (jq not installed)"
        echo "CPUQuota: (jq not installed)"
        echo "RestartCount: (jq not installed)"
        echo "StartedAt: (jq not installed)"
        echo "FinishedAt: (jq not installed)"
      } > "$tmp/limits.txt"
    fi

    # Redis / DB probes from inside the container (best effort)
    {
      echo "RedisPing=$(run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'redis-cli -h ${QUEUE_BULL_REDIS_HOST:-redis} -p ${QUEUE_BULL_REDIS_PORT:-6379} ${QUEUE_BULL_REDIS_PASSWORD:+-a $QUEUE_BULL_REDIS_PASSWORD} ping' 2>/dev/null || echo FAIL)"
      echo "DBPing=$(run_with_timeout "$EXEC_TIMEOUT" docker exec "$ID" sh -lc 'PGPASSWORD="${DB_POSTGRESDB_PASSWORD}" psql -h ${DB_POSTGRESDB_HOST:-postgres} -U ${DB_POSTGRESDB_USER:-n8n} -d ${DB_POSTGRESDB_DATABASE:-n8n} -c "select 1" -tA' 2>/dev/null || echo FAIL)"
    } > "$tmp/probes.txt" || true

    # Optional raw Docker JSON logs (can be huge; requires root)
    if $COPY_RAW_JSON_LOGS; then
      local CID; CID="$(docker inspect --format '{{.Id}}' "$ID" 2>/dev/null || echo "")"
      local LOGDIR="/var/lib/docker/containers/$CID"
      if [[ -n "$CID" && -d "$LOGDIR" ]]; then
        mkdir -p "$OUTPUT_DIR/rawlogs_${NAME}/"
        sudo cp "$LOGDIR"/*.log* "$OUTPUT_DIR/rawlogs_${NAME}/" 2>/dev/null || true
      fi
    fi

    # Save full inspect JSON (useful for mounts/env/limits)
    docker inspect "$ID" > "$OUTPUT_DIR/inspect_${NAME}.json" 2>/dev/null || true

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
      echo -e "\n=== n8n CONFIG (SAFE) ==="
      cat "$tmp/n8n_config_show.txt" 2>/dev/null || true
      echo -e "\n=== LOGS (since $SINCE_HUMAN ${TAIL_LINES:+, tail $TAIL_LINES}) [timestamps+details] ==="
      cat "$tmp/combined.log" | redact_stream
      echo -e "\n=== STDOUT (since $SINCE_HUMAN) ==="
      cat "$tmp/stdout.log" | redact_stream
      echo -e "\n=== STDERR (since $SINCE_HUMAN) ==="
      cat "$tmp/stderr.log" | redact_stream
    } > "$out"

    # CSV (quoted) for spreadsheets
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
    printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
      "$NAME" "$STATUS" "$NVER" "$NODEVER" "$MODE" "$REDISP" "$DBP" "${DISK_USAGE:-}" "$OS_VERSION" "$OOMK" "$EXITC" \
      >> "$CONTAINER_CSV"

    # TSV (plain) for human table
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
      "$NAME" "$STATUS" "$NVER" "$NODEVER" "$MODE" "$REDISP" "$DBP" "${DISK_USAGE:-}" "$OS_VERSION" "$OOMK" "$EXITC" \
      >> "$CONTAINER_TSV_RAW"

    rm -rf "$tmp"
  done

  # Simple queue-mode sanity: warn if EXECUTIONS_MODE=queue but no worker containers found
  if grep -q ',queue,' "$CONTAINER_CSV"; then
    local workers
    workers=$(awk -F, '/,queue,/{print $1}' "$CONTAINER_CSV" | tr -d '"' | grep -ci 'worker' || true)
    if [[ "${workers:-0}" -eq 0 ]]; then
      warn "Queue mode detected but no worker containers matched filters — check scaling and filters."
    fi
  fi
}

################################################################################
# emit_human_table()
# Description:
#   Render a human-readable aligned table from the raw TSV summary.
#
# Behaviors:
#   - Uses `column -t` if available to align columns.
#   - Falls back to copying TSV if `column` is missing.
#   - Writes: container_report_table.txt
#
# Inputs:
#   Uses globals:
#     CONTAINER_TSV_RAW   - raw TSV file with header row
#     CONTAINER_TABLE_TXT - pretty text output file
#
# Returns:
#   0 on best-effort success.
################################################################################
emit_human_table() {
  if [[ ! -f "$CONTAINER_TSV_RAW" ]]; then
    return 0
  fi

  {
    echo "Container Summary (human-readable table)"
    echo
    if command -v column >/dev/null 2>&1; then
      column -t -s $'\t' "$CONTAINER_TSV_RAW"
    else
      echo "[WARN] 'column' not found; showing raw TSV. Install 'bsdmainutils' or 'util-linux' for nicer alignment." >&2
      cat "$CONTAINER_TSV_RAW"
    fi
  } > "$CONTAINER_TABLE_TXT" || true
}

# ------------------------ Kubernetes Diagnostics ------------------------
################################################################################
# collect_k8s()
# Description:
#   Collect Kubernetes diagnostics when kubectl is available and selector matches.
#
# Behaviors:
#   - Lists pods by selector (optionally namespaced).
#   - Captures current and previous container logs with timestamps.
#   - Describes pods; collects cluster/node/pod metrics (kubectl top).
#   - Gathers events timeline and objects inventory (workloads, services, ingress,
#     configmaps, secrets [names only], PVCs).
#
# Outputs:
#   - k8s_pods.txt, k8s_logs.txt, k8s_logs_previous.txt
#   - k8s_describe_pods.txt, k8s_events.txt
#   - k8s_nodes.txt, k8s_describe_nodes.txt
#   - k8s_top_nodes.txt, k8s_top_pods.txt
#   - k8s_objects.txt
#
# Returns:
#   0 on best-effort success; non-fatal warnings if kubectl unavailable or no pods.
################################################################################
collect_k8s() {
  [[ "$SCOPE" == "host" || "$SCOPE" == "docker" ]] && return
  if ! have kubectl; then
    warn "kubectl not found; skipping Kubernetes diagnostics."
    return
  fi

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
    kubectl logs -n "$K8S_NS" -l "$K8S_SELECTOR" --all-containers --timestamps ${TAIL_LINES:+--tail="$TAIL_LINES"} \
      | redact_stream > "$OUTPUT_DIR/k8s_logs.txt" || true
    kubectl logs -n "$K8S_NS" -l "$K8S_SELECTOR" --all-containers --previous --timestamps ${TAIL_LINES:+--tail="$TAIL_LINES"} \
      | redact_stream > "$OUTPUT_DIR/k8s_logs_previous.txt" || true
    kubectl describe pods -n "$K8S_NS" -l "$K8S_SELECTOR" > "$OUTPUT_DIR/k8s_describe_pods.txt" || true
    kubectl get events -n "$K8S_NS" --sort-by=.lastTimestamp > "$OUTPUT_DIR/k8s_events.txt" || true
    kubectl top pods -n "$K8S_NS" --containers > "$OUTPUT_DIR/k8s_top_pods.txt" 2>/dev/null || true
  else
    kubectl get pods -A -l "$K8S_SELECTOR" -o wide > "$OUTPUT_DIR/k8s_pods.txt" || true
    kubectl logs -A -l "$K8S_SELECTOR" --all-containers --timestamps ${TAIL_LINES:+--tail="$TAIL_LINES"} \
      | redact_stream > "$OUTPUT_DIR/k8s_logs.txt" || true
    kubectl logs -A -l "$K8S_SELECTOR" --all-containers --previous --timestamps ${TAIL_LINES:+--tail="$TAIL_LINES"} \
      | redact_stream > "$OUTPUT_DIR/k8s_logs_previous.txt" || true
    kubectl describe pods -A -l "$K8S_SELECTOR" > "$OUTPUT_DIR/k8s_describe_pods.txt" || true
    kubectl get events -A --sort-by=.lastTimestamp > "$OUTPUT_DIR/k8s_events.txt" || true
    kubectl top pods -A --containers > "$OUTPUT_DIR/k8s_top_pods.txt" 2>/dev/null || true
  fi

  kubectl get nodes -o wide > "$OUTPUT_DIR/k8s_nodes.txt" 2>/dev/null || true
  kubectl describe nodes > "$OUTPUT_DIR/k8s_describe_nodes.txt" 2>/dev/null || true
  kubectl top nodes > "$OUTPUT_DIR/k8s_top_nodes.txt" 2>/dev/null || true
  kubectl get deploy,sts,ds,job,cronjob,svc,ingress,cm,secret,pvc -A -o wide > "$OUTPUT_DIR/k8s_objects.txt" 2>/dev/null || true
}

# ------------------------ Summaries ------------------------
################################################################################
# write_summaries()
# Description:
#   Generate human-readable final summary and optional JSON summary of findings.
#
# Behaviors:
#   - Summarizes host, scope, counts, time window, and captured artifacts.
#   - Highlights heuristics: queue-mode without workers, failed probes, OOMKilled.
#   - Emits summary.json when --json and jq are available.
#
# Outputs:
#   - final_summary.txt
#   - summary.json (optional)
#
# Returns:
#   0 on success (warns when jq missing for JSON).
################################################################################
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
    echo "- Redaction Enabled: $REDACT (hash:$HASH_REDACTIONS)"
    echo "- Time Window: ${SINCE_HUMAN} (${SINCE_SECS}s) ${TAIL_LINES:+, tail $TAIL_LINES lines}"
    [[ -f "$CONTAINER_CSV" ]] && echo "- Version Table (CSV): $(basename "$CONTAINER_CSV")"
    [[ -f "$CONTAINER_TABLE_TXT" ]] && echo "- Table (text): $(basename "$CONTAINER_TABLE_TXT")"
    [[ -f "$OUTPUT_DIR/docker_stats_sample.csv" ]] && echo "- Stats Sample: docker_stats_sample.csv (${STATS_SECONDS}s)"
    [[ -f "$OUTPUT_DIR/docker_events.txt" ]] && echo "- Docker Events: docker_events.txt (since $SINCE_HUMAN)"
    [[ -f "$OUTPUT_DIR/k8s_logs_previous.txt" ]] && echo "- K8s previous container logs captured."
    echo "------------------------------------------"
    echo "Findings:"
    if [[ -f "$CONTAINER_CSV" ]]; then
      if grep -q ',queue,' "$CONTAINER_CSV"; then
        local wc
        wc=$(grep -E ',queue,' "$CONTAINER_CSV" | tr -d '"' | grep -ci 'worker' || true)
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
    if have jq; then
      {
        echo '{'
        echo "  \"host\": $(jq -Rn --arg v "$(uname -a)" '{os:$v}'),"
        echo "  \"dockerUsed\": \"$docker_used\","
        echo "  \"kubernetesUsed\": \"$k8s_used\","
        echo "  \"containers\": $n_containers,"
        echo "  \"redaction\": {\"enabled\": $REDACT, \"hash\": $HASH_REDACTIONS},"
        echo "  \"timeWindow\": {\"human\":\"$SINCE_HUMAN\",\"seconds\":$SINCE_SECS},"
        if [[ -f "$CONTAINER_CSV" ]]; then
          echo -n "  \"csv\": "
          jq -Rs 'split("\n") | map(select(length>0))' < "$CONTAINER_CSV"
          echo ","
        fi
        echo "  \"notes\": [\"Check report_<container>.txt files for detailed logs and probes\", \"Docker/K8s context included\"]"
        echo '}'
      } > "$JSON_OUT" 2>/dev/null || warn "Could not write JSON summary."
    else
      warn "jq not found; skipping JSON summary."
    fi
  fi
}

# ------------------------ Pack & finish ------------------------
################################################################################
# pack_and_finish()
# Description:
#   Compress output directory to a tar.gz bundle and emit checksum unless
#   --no-tar is specified.
#
# Behaviors:
#   - Creates <OUTPUT_DIR>.tar.gz and <tarball>.sha256.
#   - Optionally removes the working directory unless --keep-tmp is set.
#
# Outputs:
#   - <OUTPUT_DIR>.tar.gz
#   - <OUTPUT_DIR>.tar.gz.sha256
#
# Returns:
#   0 on success.
################################################################################
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
emit_human_table
collect_k8s
write_summaries
pack_and_finish
