# n8n Support Collector

The **n8n Support Collector** is an **unofficial community script** that gathers diagnostics for troubleshooting n8n deployments on Docker and/or Kubernetes.  

It collects host, Docker, and container-level information (including logs, environment variables, probes, and version details) and packages them into a **single compressed tarball** you can review or share with support.

⚠️ **Disclaimer:**  
This script is not maintained by the n8n team. Always **review the output bundle** before sharing externally to ensure it contains no sensitive information.

---

## ✨ Features

- **One-run diagnostics**: Collects host info, container logs, environment, versions, probes, metrics, and events.  
- **Multi-layer coverage**:
  - **Host**: OS, disk, CPU/memory, cgroup limits, OOM events  
  - **Docker**: containers, versions, logs, restart counts, events, inspect JSON, optional raw log files  
  - **Kubernetes**: pods, node metrics, previous container logs, events, workloads inventory  
- **Queue-mode awareness**:
  - Captures `EXECUTIONS_MODE`, `/healthz`, Redis/Postgres probes  
  - Warns if queue mode detected but no workers  
- **Safety**:
  - `--redact` masks secrets (`PASSWORD`, `TOKEN`, `SECRET`, `KEY`, `AWS_*`, `N8N_ENCRYPTION_KEY`) and IPs  
  - `--hash-redactions` (with `--redact`) replaces env secrets with `REDACTED[sha1]` for correlation  
  - `--redact-pattern` lets you add your own regex masks  
- **Outputs**:
  - Per-container reports (`report_<container>.txt`)  
  - CSV (`container_report.csv`) + pretty text table (`container_report_table.txt`)  
  - Optional JSON summary (`summary.json`)  
  - Context files: `docker_events.txt`, `k8s_events.txt`, `inspect_<container>.json`  
  - Compressed bundle (`.tar.gz`) with SHA256 checksum  

---

## 🔧 Usage

```bash
chmod +x n8n-support-collector.sh
./n8n-support-collector.sh [options]
```

### Options

| Option | Description |
|--------|-------------|
| `-s, --since <dur>` | Log window: `24h`, `2h`, `30m`, `300s` (default: 24h) |
| `-t, --since-seconds <n>` | Log window in seconds (overrides `--since`) |
| `--tail <n>` | Limit container logs to last N lines |
| `-o, --output <dir>` | Output directory (default: `n8n_support_<timestamp>`) |
| `--redact` | Redact secrets in env/logs (recommended when sharing externally) |
| `--hash-redactions` | **Add-on to `--redact`**: replace env secrets with `REDACTED[sha1]` for correlation |
| `--redact-pattern <regex>` | Extra regex (sed -E) for redaction |
| `--name-filter <regex>` | Filter containers by name (default: `^(n8n-main\|n8n-worker)`) |
| `--label-filter <key=val>` | Filter containers by Docker label |
| `--scope <scope>` | `host`, `docker`, `k8s`, or `all` (default: all) |
| `--stats-seconds <n>` | Sample `docker stats` for N seconds |
| `--k8s-selector <label>` | Kubernetes label selector (default: `app=n8n`) |
| `--k8s-ns <namespace>` | Kubernetes namespace (default: all namespaces) |
| `--json` | Emit `summary.json` in addition to text summary |
| `--no-tar` | Do not compress results (leave raw folder) |
| `--keep-tmp` | Keep working directory after creating tarball |
| `--copy-raw-json` | Copy raw Docker json logs (`/var/lib/docker/containers/...`) – root + large files |
| `--exec-timeout <sec>` | Timeout for exec/log commands (default: 10s) |

---

## 🖥 Examples

```bash
# Default: collect last 24h logs from all containers
./n8n-support-collector.sh

# With secret redaction
./n8n-support-collector.sh --redact

# With redaction + hashed secrets (correlate without revealing)
./n8n-support-collector.sh --redact --hash-redactions

# Last 2h of logs, sample docker stats for 15s, JSON summary
./n8n-support-collector.sh -s 2h --stats-seconds 15 --json --redact

# Only main + worker containers, don’t tar results
./n8n-support-collector.sh --name-filter '^(n8n-main|n8n-worker)' --no-tar --keep-tmp

# Collect from Kubernetes pods in namespace 'prod'
./n8n-support-collector.sh --scope k8s --k8s-ns prod --k8s-selector 'app.kubernetes.io/name=n8n'
```

---

## 📦 Outputs

After running, you’ll get (inside the output dir):

- **Summaries**
  - `final_summary.txt` → top-level overview with host info, warnings, findings  
  - `summary.json` → optional machine-readable JSON  
- **Tables**
  - `container_report.csv` → quoted CSV (for Excel/Sheets)  
  - `container_report_table.txt` → aligned text table (for quick viewing)  
- **Per-container reports**
  - `report_<container>.txt` → environment, probes, logs, config flags  
  - `inspect_<container>.json` → raw Docker inspect  
- **Context**
  - `docker_ps.txt`, `docker_events.txt`, `docker_info.txt`  
  - `k8s_pods.txt`, `k8s_logs.txt`, `k8s_logs_previous.txt`, `k8s_events.txt`  
- **Bundle**
  - `<output_dir>.tar.gz` → compressed archive  
  - `<output_dir>.tar.gz.sha256` → checksum  

---

## ⚠️ Notes & Best Practices

- **Always review before sharing**: Even with `--redact`, logs may still include business data.  
- **Use `--redact`** for any external bundle; add `--hash-redactions` if you want to correlate values safely.  
- **Bundle size**: With `--copy-raw-json`, expect very large outputs.  
- **Performance**: Wide `--since` windows and `--stats-seconds` > 30 can take time.  
- **Security**: Requires Docker/Kubernetes CLI access; run only on trusted hosts.  

---

## ✅ TL;DR

- Run with `--redact` (and optionally `--hash-redactions`).  
- Get everything in one `.tar.gz`: host info, Docker/K8s context, logs, probes.  
- CSV for spreadsheets, text table for humans, JSON for machines.  
- Helps troubleshoot n8n quickly by surfacing all signals in one place.  
