# n8n Support Collector

The **n8n Support Collector** is an **unofficial community script** that gathers diagnostics for troubleshooting n8n deployments on Docker or Kubernetes.  

It collects host, Docker, and container-level information (including logs, environment variables, and version details), and packages them into a **single compressed tarball** that you can review or share with support.

⚠️ **Disclaimer:**  
This script is not maintained by the n8n team. Always **review the output bundle** before sharing externally to ensure it contains no sensitive information.

---

## ✨ Features

- **One-click diagnostics**: Collects system info, container logs, versions, and environment settings in one run.
- **Covers multiple layers**:
  - Host (OS, disk, memory, OOM events)
  - Docker (n8n containers, versions, logs, limits)
  - Kubernetes (pods & logs if detected)
- **Queue-mode awareness**:
  - Captures `EXECUTIONS_MODE`, `/healthz`, and warns if workers are missing.
- **Safety**:
  - `--redact` masks secrets (`PASSWORD`, `TOKEN`, `SECRET`, `KEY`) and IPs.
  - Optional `--redact-pattern` lets you add your own regex masks.
- **Outputs**:
  - Per-container reports (`report_<container>.txt`)
  - A CSV summary (`container_report.csv`)
  - Optional JSON summary (`summary.json`)
  - A compressed bundle (`.tar.gz`) with SHA256 checksum

---

## 🔧 Usage

```bash
chmod +x n8n-support-collector.sh
./n8n-support-collector.sh [options]
```

### Options

| Option | Description |
|--------|-------------|
| `-s, --since <dur>` | Log window, e.g. `24h`, `2h`, `30m`, `300s` (default: 24h) |
| `-t, --since-seconds <n>` | Log window in seconds (overrides `--since`) |
| `--tail <n>` | Limit container logs to last N lines |
| `-o, --output <dir>` | Output directory (default: `n8n_support_<timestamp>`) |
| `--redact` | Redact secrets in env and logs |
| `--redact-pattern <regex>` | Extra regex for redaction |
| `--name-filter <regex>` | Only containers whose names match regex (default: `n8n`) |
| `--label-filter <key=val>` | Only containers with this Docker label |
| `--scope <scope>` | `host`, `docker`, `k8s`, or `all` (default: all) |
| `--stats-seconds <n>` | Sample `docker stats` for N seconds |
| `--k8s-selector <label>` | Kubernetes label selector (default: `app=n8n`) |
| `--k8s-ns <namespace>` | Kubernetes namespace (default: all namespaces) |
| `--json` | Emit `summary.json` in addition to text summary |
| `--no-tar` | Do not compress results (leave raw folder) |
| `--keep-tmp` | Keep working directory after creating tarball |

---

## 🖥 Examples

```bash
# Default (last 24h logs, all containers)
./n8n-support-collector.sh

# With redaction
./n8n-support-collector.sh --redact

# Last 2h of logs, include Docker stats for 15s, JSON summary
./n8n-support-collector.sh -s 2h --stats-seconds 15 --json --redact

# Only worker containers, don’t tar results
./n8n-support-collector.sh --name-filter 'n8n-worker' --no-tar --keep-tmp

# Collect from Kubernetes pods in namespace 'prod'
./n8n-support-collector.sh --scope k8s --k8s-ns prod --k8s-selector 'app.kubernetes.io/name=n8n'
```

---

## 📦 Outputs

After running, you’ll get:

- `final_summary.txt` → top-level report with host info, counts, warnings  
- `container_report.csv` → tabular summary of all containers  
- `report_<container>.txt` → merged diagnostics for each n8n container  
- `docker_ps.txt` → list of Docker containers  
- `docker_stats_sample.csv` → optional, if `--stats-seconds` is used  
- `k8s_pods.txt`, `k8s_logs.txt` → if Kubernetes detected  
- `<output_dir>.tar.gz` → compressed bundle (with `.sha256` checksum)

---

## ⚠️ Notes & Best Practices

- **Review before sharing**: Even with `--redact`, logs may still contain sensitive info. Open the reports and check.  
- **Backups**: Always keep your `.env` and database backups — this script is for diagnostics only, not recovery.  
- **Performance**: Collecting logs from many containers can take time, especially if you use a large `--since` window.  
- **Security**: Run only on trusted hosts; script requires Docker/K8s access.  

---

## ✅ TL;DR

This script:
- Collects **everything needed for troubleshooting n8n** (host → Docker → containers → logs → K8s).  
- Redacts secrets when asked.  
- Outputs a **clean tarball bundle** with CSV/JSON summaries.  
- Helps reduce time to resolution by providing all the right signals in one shot.  
