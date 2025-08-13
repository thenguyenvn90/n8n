# n8n Manager — User Guide

**Version:** 1.0.0  
**Author:** TheNguyen  
**Last Updated:** 2025-08-05  

Welcome to the **n8n Manager** script, your one‑stop tool for installing, upgrading, and cleaning up the n8n automation platform using Docker Compose. This guide is written for non‑technical users and walks you through all the steps and common scenarios.

---

## 📖 Introduction

The **n8n Manager** script automates the entire lifecycle of your n8n deployment:

- **Install**: Set up Docker, Docker Compose, SSL certificates, and launch n8n behind Traefik.
- **Upgrade**: Pull the latest n8n image, migrate settings, and restart services.
- **Cleanup**: Remove all containers, volumes, networks, and images to start fresh.

---

## 🚀 Features

1. **Domain Validation**: Checks that your chosen domain or sub‑domain resolves to this server’s IP.
2. **Docker & Compose Installer**: Automatically installs/removes any old Docker versions and pulls in Docker Engine & Compose v2.
3. **Persistent Volumes**: Creates `n8n-data`, `postgres-data`, and `letsencrypt` volumes.
4. **SSL Certificates**: Prompts for your email and obtains Let’s Encrypt certs via Traefik (or accept `-m you@example.com`).
5. **Health Checks**: Waits for containers to report “healthy” before completing and validates HTTPS/certificate.
6. **Upgrades**: Pulls the correct image tag and safely redeploys the stack.
7. **Version Pinning (`-v`)**: Install or upgrade to an exact n8n version (e.g., `-v 1.106.3`), or omit to use latest stable.
8. **Force Mode (`-f`)**: Redeploy even if versions match; also required to **downgrade** safely.
9. **Cleanup Mode**: Stops/removes everything—containers, images, volumes, and networks.
10. **Logging**: Writes a detailed log to `logs/n8n_manager.log` in your install directory.

---

## 📋 Prerequisites

1. **Linux Server**  
   Ubuntu 20.04+ or Debian with root (or sudo) access.

2. **Domain/Subdomain**  
   e.g. `n8n.example.com`.

3. **DNS A Record**  
   In your DNS provider dashboard:
   - Create an A record for your domain/subdomain
   - Point it at your server’s **public IP**
   - Wait a few minutes for DNS changes to propagate

4. **Open Ports**  
   Ensure ports **80** (HTTP) and **443** (HTTPS) are open in your cloud firewall or server firewall.

5. **Email Address**  
   A valid email (e.g. `you@company.com`) for SSL certificate registration.

---

## 🚀 Getting Started

1. **Download the Script**  
   ```bash
   apt install unzip
   curl -L -o n8n.zip https://github.com/thenguyenvn90/n8n/archive/refs/heads/main.zip && unzip n8n.zip && cd n8n-main && chmod +x *.sh
   ```
   Note: After unzipping, GitHub appends -main to the folder name n8n; So in this case it’s n8n-main.

2. **Run Help**  
   ```bash
   sudo ./n8n_manager.sh -h
   ```
   CLI quick reference (most‑used flags)../
  ```bash
   Usage: ./n8n_manager.sh [-i DOMAIN] [-u DOMAIN] [-v VERSION] [-m EMAIL] [-f] [-c] [-d TARGET_DIR] [-l LOG_LEVEL] -h
     -i <DOMAIN>         Install n8n stack
     -u <DOMAIN>         Upgrade n8n stack
     -v <VERSION>        Pin n8n version (e.g. 1.106.3). Omit or use 'latest' for latest stable
     -m <EMAIL>          Provide SSL email non‑interactively (skips prompt)
     -f                  Force redeploy / allow downgrade
     -c                  Cleanup all containers, volumes, network
     -d <DIR>            Install directory (default: current)
     -l <LEVEL>          Log level: DEBUG|INFO|WARN|ERROR
     -h                  Help
   ```
---

## 🔧 Installation Flow

1. Install n8n

Interactive email prompt:
```bash
sudo ./n8n_manager.sh -i n8n.YourDomain.com (install the latest n8n version)
or
sudo ./n8n_manager.sh -i n8n.YourDomain.com -v  1.105.3 (install the version 1.105.3)
```

When prompted, enter your email (used for SSL).
```
   root@ubuntu-s-1vcpu-1gb-01:~/n8n-main# ./n8n_manager.sh -i n8n.YourDomain.com
   [INFO] Working on directory: /root/n8n-main
   [INFO] Logging to /root/n8n-main/logs/n8n_manager.log
   [INFO] Starting N8N installation for domain: n8n.YourDomain.com
   Enter your email address (used for SSL cert): yourValidEmail@gmail.com
```

Or provide your SSL email inline (no prompt)

```bash
sudo ./n8n_manager.sh -i n8n.YourDomain.com -m you@YourDomain.com
```
2. Installation Flow

The script will:
   1. **Enter your email** for SSL notifications (if the argument -m was not specified)
   2. **Verify DNS**: script confirms your domain points at this server.
   3. **Copy and configure** `docker-compose.yml` and `.env` with your domain, email, and password.
   4. **Install Docker & Compose** if missing.
   5. **Create volumes** and start the stack behind Traefik.
   6. **Wait for health checks** to pass.

At the end, you’ll see a summary with your URL, version, and log file path.
   ```
   ─────────────────────────────────────────────────────────
   N8N has been successfully installed!
   Domain:             https://n8n.YourDomain.com
   Installed Version:  1.105.3
   Install Timestamp:  2025-08-13 10:42:14
   Installed By:       root
   Target Directory:   /root/n8n-main
   SSL Email:          yourValidEmail@gmail.com
   Execution log:      /root/n8n-main/logs/n8n_manager.log
   ─────────────────────────────────────────────────────────
   ```
---

## 🔄 Upgrade n8n

**Latest stable:**

```bash
sudo ./n8n_manager.sh -u n8n.YourDomain.com
```

**Pin a specific version:** (installs/upgrades to exactly this tag and writes it to `.env` as `N8N_IMAGE_TAG`)

```bash
sudo ./n8n_manager.sh -u n8n.YourDomain.com -v 1.106.3
```

**Downgrade:** (requires `-f` to proceed)

```bash
sudo ./n8n_manager.sh -u n8n.YourDomain.com -v 1.105.3 -f
```

- On success, you’ll see:
  ```
   ─────────────────────────────────────────────────────────
   N8N has been successfully upgraded!
   Domain:             https://n8n.YourDomain.com
   Installed Version:  1.106.3
   Install Timestamp:  2025-08-13 10:42:14
   Installed By:       root
   Target Directory:   /root/n8n-main
   SSL Email:          yourValidEmail@gmail.com
   Execution log:      /root/n8n-main/logs/n8n_manager.log
   ─────────────────────────────────────────────────────────
  ```

**Notes:**
- If you **omit `-v`** (or pass `latest`), the script resolves the latest stable tag and updates `.env` to that version.
- If you **pass `-v <version>`**, the script validates the tag, pins it in `.env`, and deploys that exact version.
- A later `-u` **without `-v`** will switch you back to the latest stable.

---

## 🧹 Cleanup (Uninstall)

If you need to completely remove n8n and start over:

```bash
sudo ./n8n_manager.sh -c
```

> ⚠️ This stops all containers, prunes images, and deletes volumes & networks. Use only if you want a full reset.

---

## 🗂️ Logs & Status

- **Main log file:** `/root/n8n-main/logs/n8n_manager.log`  
- **Check container health:**
  ```bash
  docker compose -f /root/n8n-main/docker-compose.yml ps
  ```
- **Browse UI:** Visit `https://n8n.YourDomain.com` in your web browser.

---

## ⚙️ Advanced Options

- **Target Directory**: By default uses current folder. To change:
  ```bash
  mkdir -p /home/n8n
  sudo ./n8n_manager.sh -i n8n.YourDomain.com -d /home/n8n
  ```
- **Log Level** (DEBUG, INFO, WARN, ERROR):
  ```bash
  sudo ./n8n_manager.sh -i n8n.YourDomain.com -l DEBUG
  ```
All logs write to `/home/n8n/logs/n8n_manager.log`.

---

## 🤝 Support & Troubleshooting

1. **View recent logs:**
   ```bash
   tail -n 50 logs/n8n_manager.log
   ```
2. **Verify DNS:**
   ```bash
   dig +short n8n.YourDomain.com
   ```
3. **Check firewall:**
   ```bash
   sudo ufw status
   ```

Thank you for using **n8n Manager**! If you encounter any issues, please open an issue on the GitHub repo or email [thenguyen.ai.automation@gmail.com](mailto\:thenguyen.ai.automation@gmail.com). 🎉
