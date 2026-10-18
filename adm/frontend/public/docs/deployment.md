# Deployment & Operations

## Overview

Proxima is deployed via Git and Docker Compose on self-hosted Linux servers. The application consists of a Python/Flask backend that serves a React frontend, along with several supporting containers for DNS resolution, traffic routing, and VPN tunneling. All deployment operations use standard Git pulls followed by Docker Compose builds and restarts.

The deployment model is straightforward: code lives in a private GitHub repository, and each server pulls the latest changes, rebuilds the relevant Docker images, and restarts containers. Configuration is stored in bind-mounted volumes that persist across rebuilds.

---

## Deployment Targets

Proxima is currently deployed on two servers:

### ERG (Home Server)

| Property       | Value                    |
|----------------|--------------------------|
| Server IP      | `192.168.2.91`           |
| SSH Alias      | `erg`                    |
| Proxima Root   | `/opt/erg/proxima`       |
| Routing Mode   | DNS Mode                 |
| Router         | Keenetic                 |
| Web UI Port    | `5050`                   |

### OFC (Office Server)

| Property       | Value                    |
|----------------|--------------------------|
| Server IP      | `192.168.77.121`         |
| SSH Alias      | `ofc`                    |
| Proxima Root   | `/opt/proxima`           |
| Routing Mode   | DNS Mode                 |
| Router         | MikroTik                 |
| Web UI Port    | `5050`                   |

---

## Standard Deploy

A standard deploy updates the Proxima application (backend + frontend) without touching the DNS Mode infrastructure containers.

### ERG

```bash
cd /opt/erg/proxima && git pull
cd docker && docker compose build proxima
docker compose up -d proxima
```

### OFC

```bash
cd /opt/proxima && git pull
cd docker && docker compose build proxima
docker compose up -d proxima
```

The build process is a multi-stage Docker build:
1. **Stage 1 (Node):** Installs frontend dependencies, runs `npm run build` to produce static assets.
2. **Stage 2 (Python):** Installs backend dependencies, copies the built frontend into the Flask static directory.

The resulting image contains everything needed to serve both the API and the UI.

---

## DNS Mode Deploy

DNS Mode requires two additional compose services, `dnsmasq` and `dns-router`, behind the `dns` profile. The tunnel client containers (`awg-client-slot-N`, `outline-client-slot-N`, `xray-client-slot-N`, `zapret-client-slot-N`) are **not** compose services: compose only builds their images (the `build` profile) and Proxima creates one container per slot from `backend/core/failover.py`. Adding a slot in the UI is all it takes — there is no fixed number of AWG slots.

### Full DNS Mode Deploy

```bash
cd /opt/proxima/docker
docker compose --profile dns --profile build build
docker compose --profile dns up -d
```

Only the `dns` profile is started. The `build` profile holds image-only services and must never be `up`-ed.

### Rebuild Only DNS Containers

```bash
cd /opt/proxima/docker
docker compose --profile dns build dnsmasq dns-router
docker compose --profile dns up -d dnsmasq dns-router
```

### Rebuild a Tunnel Client Image

```bash
cd /opt/proxima/docker
docker compose --profile build build awg-client     # or outline-client / xray-client / zapret-client
```

Proxima notices on the next restart of each slot (or on its own startup) that the container's image tag has moved on and replaces the container. Nothing needs to be `up`-ed by hand.

### Deploy Proxima + DNS Together

```bash
cd /opt/proxima && git pull
cd docker
docker compose build proxima
docker compose --profile dns --profile build build
docker compose up -d proxima
docker compose --profile dns up -d
```

> **Note:** The data plane (dnsmasq, nftables, tun2socks, AWG) runs independently of the Proxima application container. If only the Proxima container is restarted, VPN routing continues to function. Health checks and failover will be temporarily unavailable until Proxima is back up.

---

## Container Management

### Check Container Status

```bash
# All containers
docker compose ps

# DNS Mode containers only
docker compose --profile dns ps
```

### View Logs

```bash
# Follow Proxima logs
docker compose logs -f proxima

# Follow dnsmasq logs
docker compose logs -f dnsmasq

# Follow dns-router logs
docker compose logs -f dns-router

# Follow AWG client logs (not a compose service — use docker directly)
docker logs -f awg-client-slot-1

# Last 100 lines of a specific container
docker compose logs --tail=100 proxima
```

### Restart Containers

```bash
# Restart Proxima only (VPN routing continues)
docker compose restart proxima

# Restart a DNS Mode container
docker compose --profile dns restart dnsmasq

# Full restart of everything
docker compose down
docker compose up -d
docker compose --profile dns up -d
```

### Stop Everything

```bash
# Stop all containers (VPN routing will stop)
docker compose --profile dns down
docker compose down
```

### Check Resource Usage

```bash
# CPU and memory usage per container
docker stats --no-stream
```

### Container Resource Limits

Docker Compose enforces resource limits on Proxima containers:

| Container | Memory Limit | CPU Limit | Notes |
|-----------|-------------|-----------|-------|
| `proxima` | 512M | 1.0 | Flask API + React frontend |
| `dnsmasq` | 64M | 0.25 | DNS resolver |
| `dns-router` | 512M | 2.0 | nftables + tun2socks + gost + SNI router |
| `awg-client-slot-*` | 256M | 2.0 | AWG tunnels (amneziawg-go) + gost SOCKS5 |
| `outline-client-*` | 128M | 0.25 | Shadowsocks (Outline) tunnels |
| `xray-client-*` | 128M | 0.25 | VLESS+Reality (Xray) tunnels |
| `zapret-client-*` | 128M | 0.25 | DPI bypass (zapret/nfqws2) |

### Automatic Container Management

Proxima automatically manages container lifecycle. Disabled slot containers are stopped on startup.

**Important:** Shadowsocks client containers (`ss-client-slot-*`) will crash-loop if no valid config file exists (e.g., `slot-1.json`). If SS slots are not in use, stop them manually:

```bash
docker stop ss-client-slot-1 ss-client-slot-2 ss-client-slot-3 ss-client-slot-4
```

Crash-looping containers hammer containerd and dockerd, causing significant CPU waste. Proxima's `_stop_disabled_slots()` function handles this automatically for slots marked as disabled in the config.

---

## Config Backup

### Critical Files

The following files contain all Proxima state and should be backed up regularly:

| File                            | Description                          |
|---------------------------------|--------------------------------------|
| `config/proxima-config.json`    | All settings, groups, domains, slots |
| `config/proxima.db`             | Performance tracking data (SQLite)   |
| `config/proxima.log`            | Application log (7-day rotation)     |

### Backup Commands

```bash
# Create a timestamped backup
BACKUP_DIR="/opt/backups/proxima/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp config/proxima-config.json "$BACKUP_DIR/"
cp config/proxima.db "$BACKUP_DIR/"
cp config/proxima.log "$BACKUP_DIR/"
echo "Backup saved to $BACKUP_DIR"
```

```bash
# Automated daily backup via cron
# Add to crontab: crontab -e
0 3 * * * cd /opt/proxima && mkdir -p /opt/backups/proxima/$(date +\%Y\%m\%d) && cp config/proxima-config.json config/proxima.db /opt/backups/proxima/$(date +\%Y\%m\%d)/
```

```bash
# Restore from backup
cp /opt/backups/proxima/20260427/proxima-config.json config/proxima-config.json
docker compose restart proxima
```

### What NOT to Back Up

The following files are auto-generated and will be recreated on startup:

- `config/slot-N.json` — Shadowsocks client configs (generated from proxima-config.json)
- `config/awg-slot-6.conf` — AWG config (generated from proxima-config.json)
- `config/dnsmasq/` — dnsmasq config files (regenerated on domain changes)
- `config/dnsmasq-logs/` — dnsmasq query logs (used by arbiter, rotated automatically)
- `config/dns-router/` — nftables, tc scripts, tunnels.json, domain-groups.map (regenerated on config changes)

---

## Updating Proxima

### Standard Update Procedure

```bash
# 1. Pull latest code
cd /opt/proxima && git pull

# 2. Rebuild the Proxima image
cd docker && docker compose build proxima

# 3. Restart with new image
docker compose up -d proxima
```

### Update with DNS Mode Changes

If the update includes changes to DNS Mode containers (dnsmasq config generation, dns-router scripts, AWG client setup):

```bash
cd /opt/proxima && git pull
cd docker
docker compose build proxima
docker compose --profile dns --profile build build
docker compose up -d proxima
docker compose --profile dns up -d
```

### Important Notes

- **Database migrations** are automatic. The SQLite schema is checked and upgraded on startup if needed.
- **Config schema** is backward compatible. New fields are added with sensible defaults; old fields are never removed without migration.
- **Frontend assets** are rebuilt during `docker compose build proxima` (multi-stage build). No separate frontend deploy step is needed.
- **Zero-downtime** is not supported. There will be a brief interruption (typically 5-15 seconds) during the restart. VPN routing continues if only the Proxima container is restarted.

---

## Docker Volume Management

### Bind-Mounted Config Directory

Proxima uses a bind-mounted directory (not a Docker named volume) for configuration persistence:

```yaml
# In docker-compose.yml
volumes:
  - ./config:/config
```

This means:

- Config files live in `./config/` relative to `docker-compose.yml`
- Files persist across container rebuilds and restarts
- Files are directly accessible from the host filesystem
- No `docker volume` commands are needed

### Directory Structure

```
docker/
├── docker-compose.yml
├── config/                          # Bind-mounted to /config in container
│   ├── proxima-config.json          # Main config (single source of truth)
│   ├── proxima.db                   # SQLite performance database
│   ├── proxima.log                  # Application log
│   ├── slot-1.json                  # Auto-generated SS config
│   ├── slot-2.json                  # Auto-generated SS config
│   ├── awg-slot-1.conf              # Auto-generated AWG config (one per AWG slot)
│   ├── dnsmasq/                     # Auto-generated dnsmasq configs
│   │   ├── proxima-domains.conf     # Domain → nftset mappings
│   │   ├── proxima-upstream.conf    # Upstream DNS server
│   │   └── proxima-local.conf       # Local domain overrides (hairpin NAT)
│   ├── dnsmasq-logs/                # Shared volume: dnsmasq writes, arbiter reads
│   │   └── dnsmasq.log             # dnsmasq query log (log-queries=extra)
│   └── dns-router/                  # Auto-generated nftables/tc configs
│       ├── proxima.nft              # nftables rules
│       ├── tc-rules.sh              # Traffic control script
│       ├── tunnels.json             # Multi-tunnel configuration
│       └── domain-groups.map        # Domain → group mark mapping (for arbiter)
└── ...
```

### Permissions

The config directory must be writable by the Docker process. Typically:

```bash
# Ensure correct ownership
chown -R root:root config/
chmod -R 755 config/
chmod 600 config/proxima-config.json  # Restrict access to credentials
```

---

## Multi-Server Sync

### Domain Group Sync

Groups and domain configurations can be synchronized between ERG and OFC servers. Both servers manage the same set of blocked/proxied domains but may have different slot configurations and routing preferences.

### Config Sync via UI

From the Proxima UI **Groups** page, click the **Sync** button in the toolbar to open the Config Sync modal:

1. **Source URL** — enter the remote Proxima export URL (e.g., `http://192.168.2.91:5050/api/groups/export`)
2. **Mode** — choose **Merge** (additive only) or **Full Sync** (remote is source of truth)
3. **What to sync** — checkboxes for: custom domains, critical domains, notes, slot assignments
4. **Preview** — shows a diff of what will change before applying
5. **Slot Assignment sync** — if enabled, preview shows a slot mapping table where you can map remote slot IDs to local equivalents (servers may have different slot IDs for similar tunnels)
6. **Apply** — executes the sync

> **Previous location:** Config Sync was on the Settings page in older versions. It was moved to the Groups page as a modal to be closer to the data it operates on.

### Export Config

The same Sync modal has an **Export** button that downloads the current groups as a JSON file. This file can be used as the source for a manual import or kept as a backup.

### Manual Sync via Config File

```bash
# Copy domain groups from OFC to ERG
scp ofc:/opt/proxima/docker/config/proxima-config.json /tmp/ofc-config.json
# Then use the Groups page Sync button to import the file
```

### What Syncs

- Domain groups and their domain lists
- Community database category selections
- IPv6 blocking preferences per group
- Group slot assignments (optional, with slot ID remapping)

### What Does NOT Sync

- Slot configurations (each server has its own VPN providers)
- Health state (each server tracks its own health)
- Performance data (per-server SQLite database)
- Scheduler intervals and other server-specific settings

---

## TCP Optimizations

For best VPN throughput, both the Proxima host and VPN exit servers should have TCP tuning applied. These settings are especially impactful for high-latency or lossy links (LTE, international tunnels).

### Configuration File

Create `/etc/sysctl.d/99-proxima-tcp.conf` on each server:

```bash
# BBR congestion control (dramatically better than cubic on lossy links)
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# TCP Fast Open (saves 1 RTT on repeated connections)
net.ipv4.tcp_fastopen = 3

# Larger TCP buffers (16MB max, good for high-bandwidth tunnels)
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# Connection reuse and keepalive
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
```

Apply without reboot:

```bash
sysctl -p /etc/sysctl.d/99-proxima-tcp.conf
```

### Initial Congestion Window

Increase the initial congestion window for faster page loads on first connection:

```bash
# One-time (lost on reboot)
ip route change default via GATEWAY_IP dev INTERFACE initcwnd 20 initrwnd 20
```

For persistence, add to `/etc/network/interfaces`:

```bash
post-up ip route change default via 192.168.2.1 dev enp3s0 initcwnd 20 initrwnd 20
```

### What These Settings Do

| Setting | Default | Proxima | Impact |
|---------|---------|---------|--------|
| `tcp_congestion_control` | cubic | bbr | Better throughput on lossy/high-latency links |
| `default_qdisc` | fq_codel | fq | Fair queuing, required for BBR |
| `tcp_fastopen` | 0 | 3 | Saves 1 RTT on repeated connections (client+server) |
| `initcwnd` | 10 | 20 | Faster initial page loads (more data in first burst) |
| `tcp_rmem/wmem` | 4MB max | 16MB max | Better sustained throughput for large transfers |

### Where to Apply

- **Proxima host** (ERG, OFC): Apply all settings
- **VPN exit servers** (Hetzner VPS, etc.): Apply all settings
- **AWG provider servers**: Cannot modify (managed by provider)

---

## Monitoring

### Automatic Health Checks

Proxima runs health checks on configurable intervals:

- **IP Check:** Verifies the exit IP of each active slot matches the expected VPN IP. Triggers failover on mismatch or failure.
- **Domain Check:** Tests critical domains through each slot to verify they are accessible. Logs individual results.

Both checks run independently and do not block each other.

### Bypass Mode

When all pool configurations for a slot fail, Proxima enters **bypass mode**:

- nftset entries are removed from dnsmasq config
- nftsets are flushed in nftables
- Traffic goes direct (no VPN) to maintain connectivity
- A recovery check runs every 2 minutes
- When a working config is found, bypass mode is automatically deactivated

The Dashboard UI shows a prominent alert when bypass mode is active.

### Log File

The application log at `config/proxima.log` uses `TimedRotatingFileHandler` with 7-day retention:

```bash
# View recent log entries
tail -100 config/proxima.log

# Search for errors
grep -i error config/proxima.log

# Search for a specific slot
grep "\[SLOT-1\]" config/proxima.log
```

### Performance Database

The SQLite database at `config/proxima.db` stores:

- Key success rates over time
- Health check results history
- Failover event records

This data is visualized in the **Performances** page in the UI.

### External Monitoring

For external monitoring, you can poll the Proxima API:

```bash
# Check if Proxima is responding (no auth required for health)
curl -s http://SERVER_IP:5050/api/status | jq .

# Check from a monitoring script
if ! curl -sf http://SERVER_IP:5050/api/status > /dev/null; then
    echo "Proxima is down!"
fi
```

### Cron Monitoring with Healthchecks.io

For monitoring cron jobs (backups, anomaly checks, weekly reports), [healthchecks.io](https://healthchecks.io/) can be self-hosted alongside Proxima. It tracks cron execution and sends alerts via Telegram when a job misses its expected schedule.

Recommended checks:
- **Backup cron** — daily, alert if missed for >24h
- **Anomaly check** — daily, monitors disk health, Docker status, backup freshness
- **Weekly summary** — weekly, aggregated health report

> **Tip:** If healthchecks.io needs internet access (for Telegram alerts) and your server routes traffic through Proxima, connect the healthchecks container to `proxy_net` so it can reach the Telegram API.

---

## SSL/HTTPS

Per [ADR-002](https://github.com/erghold/proxima), the standard approach for SSL is **Nginx Proxy Manager (NPM)**, deployed as a separate service outside Proxima's docker-compose.

### Why NPM

- Automatic Let's Encrypt certificate provisioning and renewal
- Web UI for managing proxy hosts — no manual nginx config files
- Consistent across all Proxima deployments
- Runs independently — updating Proxima does not affect SSL

### Setup

1. Deploy NPM using its own docker-compose stack
2. Connect NPM to the `proxy_net` Docker network
3. Create a proxy host: `your-domain` → `proxima:5000`
4. Enable SSL with Let's Encrypt
5. Optionally forward HTTPS port (e.g., 443 or 5443) on your router

See the [Deployment Checklists](/docs/deployment-checklist.md) for step-by-step instructions.
