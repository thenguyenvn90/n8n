#!/bin/bash

# n8n Support Collector
# Full diagnostics for all n8n containers, including redaction, merged reports, and OOM checks

# **DISCLAIMER:**  
# This is an unofficial diagnostic script created by the community.  
# It is **not developed or maintained by the n8n team**.  
# Use at your own risk. Always review the output before sharing externally to ensure no sensitive information is exposed.


TIME_IN_PAST=86400
OUTPUT_DIR="n8n_support_$(date +%F_%H%M%S)"
SUMMARY_FILE="$OUTPUT_DIR/final_summary.txt"
REDACT=false
mkdir -p "$OUTPUT_DIR"

# ------------------------ Args ------------------------
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -t) TIME_IN_PAST=$2; shift ;;
    -o) OUTPUT_DIR=$2; shift ;;
    --redact) REDACT=true ;;
    *) echo "Usage: $0 [-t <seconds>] [-o <output_dir>] [--redact]"; exit 1 ;;
  esac
  shift
done

log() { echo -e "[INFO] $1"; }
add_summary() { echo -e "$1" >> "$SUMMARY_FILE"; }

# ------------------------ System Info ------------------------
log "📋 Gathering OS & host info..."
{
  echo "=== OS Info ==="
  uname -a
  [ -f /etc/os-release ] && cat /etc/os-release

  echo -e "\n=== Host Disk Space ==="
  df -h

  echo -e "\n=== CPU & Memory ==="
  lscpu
  free -h
} > "$OUTPUT_DIR/host_system_info.txt" 2>/dev/null

DISK_SUMMARY=$(df -h | grep -E '^/dev/' | awk '{print $1": "$5" used on "$6}' | paste -sd ", " -)

# ------------------------ Host OOM Check ------------------------
log "🔥 Checking host for OOM events..."
{
  OOM_COUNT=$(dmesg -T 2>/dev/null | grep -i 'killed process' | tee /dev/tty | wc -l)
  echo -e "\nOOM kills found: $OOM_COUNT"
} > "$OUTPUT_DIR/oom_check.txt"
OOM_STATUS="No"
[ "$OOM_COUNT" -gt 0 ] && OOM_STATUS="Yes"

# ------------------------ Docker & Container Checks ------------------------
DOCKER_PRESENT="No"
K8S_STATUS="No"
N8N_CONTAINERS_FOUND=0

if docker ps &>/dev/null; then
  DOCKER_PRESENT="Yes"
  docker ps -a > "$OUTPUT_DIR/docker_ps.txt"

  log "📦 Scanning all n8n containers..."
  ALL_N8N_CONTAINERS=$(docker ps -a --filter "name=n8n" --format "{{.ID}} {{.Names}} {{.Status}}")

  if [ -z "$ALL_N8N_CONTAINERS" ]; then
    log "No n8n containers found."
  else
    echo "Container_Name,Status,n8n_Version,Node_Version,Disk_Usage,OS_Version,Container_OOM" > "$OUTPUT_DIR/container_report.csv"

    while read -r ID NAME STATUS; do
      ((N8N_CONTAINERS_FOUND++))
      log "  → [$NAME] Status: $STATUS"

      # Env vars
      if $REDACT; then
        docker exec "$ID" printenv | \
          sed -E 's/(PASSWORD|SECRET|TOKEN|KEY)=.*/\1=REDACTED/g' | \
          sed -E 's/([0-9]{1,3}\.){3}[0-9]{1,3}/REDACTED_IP/g' \
          > "$OUTPUT_DIR/env_${NAME}.txt"
      else
        docker exec "$ID" printenv > "$OUTPUT_DIR/env_${NAME}.txt"
      fi

      # Versions
      docker exec "$ID" node -v > "$OUTPUT_DIR/node_version_${NAME}.txt" 2>/dev/null || echo "Not installed" > "$OUTPUT_DIR/node_version_${NAME}.txt"
      docker exec "$ID" n8n --version > "$OUTPUT_DIR/n8n_version_${NAME}.txt" 2>/dev/null || echo "Unknown" > "$OUTPUT_DIR/n8n_version_${NAME}.txt"

      NODE_VERSION=$(<"$OUTPUT_DIR/node_version_${NAME}.txt")
      N8N_VERSION=$(<"$OUTPUT_DIR/n8n_version_${NAME}.txt")

      # Disk space
      docker exec "$ID" df -h > "$OUTPUT_DIR/diskspace_${NAME}.txt" 2>/dev/null
      DISK_USAGE=$(docker exec "$ID" df -h / | awk 'NR==2 {print $5 " used"}' 2>/dev/null)

      # OS Info
      docker exec "$ID" sh -c 'cat /etc/os-release 2>/dev/null || uname -a' > "$OUTPUT_DIR/osinfo_${NAME}.txt"
      OS_VERSION=$(grep PRETTY_NAME "$OUTPUT_DIR/osinfo_${NAME}.txt" 2>/dev/null | cut -d= -f2 | tr -d '"' || head -n 1 "$OUTPUT_DIR/osinfo_${NAME}.txt")

      # Logs
      docker logs --since ${TIME_IN_PAST}s "$ID" &> "$OUTPUT_DIR/logs_${NAME}.txt"

      # OOM inside container
      docker exec "$ID" sh -c 'dmesg -T 2>/dev/null | grep -i "killed process"' > "$OUTPUT_DIR/oom_dmesg_${NAME}.txt" 2>/dev/null
      docker exec "$ID" sh -c 'journalctl -k 2>/dev/null | grep -i "out of memory"' > "$OUTPUT_DIR/oom_journal_${NAME}.txt" 2>/dev/null
      CONTAINER_OOM="None"
      if [ -s "$OUTPUT_DIR/oom_dmesg_${NAME}.txt" ] || [ -s "$OUTPUT_DIR/oom_journal_${NAME}.txt" ]; then
        CONTAINER_OOM="OOM(s) Detected"
      fi

      # Merge into single report
      {
        echo "🔹 Container: $NAME"
        echo "📦 Status: $STATUS"
        echo "🧠 Node Version: $NODE_VERSION"
        echo "⚙️  n8n Version: $N8N_VERSION"
        echo "🗂  Disk Usage: $DISK_USAGE"
        echo "🖥  OS Version: $OS_VERSION"
        echo "🚨 OOM Events: $CONTAINER_OOM"

        echo -e "\n=== ENVIRONMENT VARIABLES ==="
        cat "$OUTPUT_DIR/env_${NAME}.txt"

        echo -e "\n=== DISK SPACE ==="
        cat "$OUTPUT_DIR/diskspace_${NAME}.txt"

        echo -e "\n=== OS INFO ==="
        cat "$OUTPUT_DIR/osinfo_${NAME}.txt"

        echo -e "\n=== OOM - dmesg ==="
        cat "$OUTPUT_DIR/oom_dmesg_${NAME}.txt"

        echo -e "\n=== OOM - journalctl ==="
        cat "$OUTPUT_DIR/oom_journal_${NAME}.txt"

        echo -e "\n=== LOGS ==="
        cat "$OUTPUT_DIR/logs_${NAME}.txt"
      } > "$OUTPUT_DIR/report_${NAME}.txt"

      # Clean up
      rm "$OUTPUT_DIR/"{env,diskspace,logs,n8n_version,node_version,osinfo,oom_dmesg,oom_journal}_${NAME}.txt 2>/dev/null

      echo "$NAME,$STATUS,$N8N_VERSION,$NODE_VERSION,$DISK_USAGE,$OS_VERSION,$CONTAINER_OOM" >> "$OUTPUT_DIR/container_report.csv"
    done <<< "$ALL_N8N_CONTAINERS"
  fi
fi

# ------------------------ Kubernetes Check ------------------------
if command -v kubectl &>/dev/null && kubectl get pods --all-namespaces | grep -qi n8n; then
  kubectl get pods --all-namespaces | grep n8n > "$OUTPUT_DIR/k8s_pods.txt"
  kubectl logs --tail=1000 -l app=n8n > "$OUTPUT_DIR/k8s_logs.txt"
  K8S_STATUS="Yes"
fi

# ------------------------ Summary ------------------------
log "✅ Generating summary..."
{
  echo "🔧 n8n Diagnostic Summary Report"
  echo "------------------------------------------"
  echo "- OS Version: $(uname -a)"
  echo "- Host Disk Summary: $DISK_SUMMARY"
  echo "- Docker Used: $DOCKER_PRESENT"
  echo "- Total n8n Containers: $N8N_CONTAINERS_FOUND"
  echo "- Kubernetes Detected: $K8S_STATUS"
  echo "- Host OOM Kills Found: $OOM_STATUS"
  echo "- Redaction Enabled: $REDACT"
  echo "- Per-Container Reports: report_<container>.txt"
  echo "- Version Table: container_report.csv"
  echo "------------------------------------------"
  echo "📁 Bundle: ${OUTPUT_DIR}.tar.gz"
} | tee "$SUMMARY_FILE"

# ------------------------ Compress ------------------------
log "📦 Compressing output..."
tar -czf "${OUTPUT_DIR}.tar.gz" "$OUTPUT_DIR"
rm -rf "$OUTPUT_DIR"
log "🎉 Done! Bundle saved: ${OUTPUT_DIR}.tar.gz"
