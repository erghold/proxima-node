# Deployment Checklists

Step-by-step checklists for deploying Proxima to a new site. Choose the mode that matches your deployment scenario.

---

## Mode A: Central Hub

**Scenario:** Full LAN integration — router points all DNS and gateway traffic to the Proxima server. All devices on the network benefit from domain-based VPN routing without any per-device configuration.

**Examples:** Home server (ERG), office server (OFC), any site where you control the router.

### Prerequisites

- [ ] Linux server with static LAN IP (Debian 12 / Ubuntu 22.04 recommended)
- [ ] At least one VPN credential (AWG config, SS key, or VLESS config)
- [ ] Router admin access (for DNS/gateway configuration)
- [ ] SSH access to the server
- [ ] Domain name for HTTPS access (optional but recommended)

### 1. Server Preparation

- [ ] Set a static IP on the server
- [ ] Set timezone: `timedatectl set-timezone Europe/Moscow` (adjust for your site)
- [ ] Ensure Docker is not on ZFS storage (`docker info | grep "Storage Driver"`)
- [ ] Install Docker: `curl -fsSL https://get.docker.com | sh`
- [ ] Verify Docker Compose v2: `docker compose version` (must be v2.20+)
- [ ] Apply TCP optimizations: create `/etc/sysctl.d/99-proxima-tcp.conf` (see Deployment docs)

### 2. Install Proxima

```bash
cd /opt
sudo git clone https://github.com/erghold/proxima.git
cd proxima
docker network create proxy_net
mkdir -p config
cp proxima-config.example.json config/proxima-config.json
```

- [ ] Repository cloned to `/opt/proxima` (or your preferred path)
- [ ] `proxy_net` Docker network created
- [ ] `config/` directory created with example config copied

### 3. Configure Environment

```bash
cd docker
cp .env.example .env
```

- [ ] Edit `.env` — set `TZ` to your timezone
- [ ] Edit `.env` — adjust `PROXIMA_PORT` and `GATEWAY_HOST_PORT` if needed
- [ ] Edit `config/proxima-config.json`:
  - [ ] Set `server_code` (short site identifier, e.g., "HOME", "OFC")
  - [ ] Set `server_ip` to the server's LAN IP
  - [ ] Configure initial slots (at least one AWG or SS slot)
  - [ ] Set `default_vpn_slot`

### 4. Build and Start

```bash
# Build all images (DNS mode + the tunnel client images)
cd /opt/proxima/docker
docker compose build proxima
docker compose --profile dns --profile build build

# Start everything. Only these are compose services; the tunnel clients are
# created per slot by Proxima once a slot has a key.
docker compose up -d proxima
docker compose --profile dns up -d
```

- [ ] `docker compose ps` shows `proxima`, `dnsmasq` and `dns-router` `Up`
- [ ] `docker ps` shows one `*-client-slot-N` per configured slot (none yet on a fresh box)
- [ ] Web UI accessible at `http://SERVER_IP:5050`
- [ ] Create admin account on first launch

### 5. Add VPN Credentials

- [ ] Go to **Keys & Tunnels** page
- [ ] Add at least one AWG config, SS key, or VLESS config
- [ ] Assign key to a slot pool on the Dashboard
- [ ] Verify slot shows a valid exit IP after activation

### 6. Configure Domain Groups

- [ ] Go to **Groups** page
- [ ] Create domain groups (e.g., Messaging, Streaming, AI)
- [ ] Add domains to groups (or use Community Database categories)
- [ ] Assign each group to a slot
- [ ] Mark critical domains for failover monitoring

### 7. Router Configuration

- [ ] Set Proxima server IP as **primary DNS** in router DHCP settings
- [ ] Set Proxima server IP as **default gateway** in router DHCP settings (if supported)
- [ ] Renew DHCP leases on client devices (or restart them)
- [ ] Test: `nslookup youtube.com SERVER_IP` from a client device

### 8. SSL/HTTPS (Recommended)

Using Nginx Proxy Manager (NPM) per ADR-002:

- [ ] Deploy NPM (external to Proxima's docker-compose)
- [ ] Create proxy host: your domain → `proxima:5000` via `proxy_net`
- [ ] Enable SSL with Let's Encrypt
- [ ] Verify HTTPS access to Proxima UI

### 9. ProximaVPN (Optional)

- [ ] Install WireGuard on the server
- [ ] Configure `wg1` interface (always `wg1`, port `5555`)
- [ ] Set up ProximaVPN subnet (e.g., `10.x.x.0/24`)
- [ ] Forward port `5555/UDP` on the router
- [ ] Test VPN connection from ProximaVPN client app

### 10. Monitoring (Recommended)

- [ ] Set up daily backup cron job
- [ ] Set up anomaly-check script with Telegram alerts
- [ ] Set up healthchecks.io (self-hosted or cloud) for cron monitoring
- [ ] Verify Proxima health endpoint: `curl http://SERVER_IP:5050/api/status`

### Post-Deploy Verification

- [ ] All slots show healthy exit IPs on Dashboard
- [ ] Domain check passes for all critical domains
- [ ] Client devices route configured domains through VPN
- [ ] Direct domains bypass VPN correctly
- [ ] HTTPS access works (if configured)
- [ ] Backup cron runs successfully
- [ ] ProximaVPN clients can connect (if configured)

---

## Mode B: Site Deployment

**Scenario:** Minimal deployment — no router control, only ProximaVPN users get VPN routing. Suitable for temporary or remote sites (construction offices, temporary setups) where you cannot modify the network infrastructure.

**Examples:** Construction site office, temporary event location, remote branch office.

### Prerequisites

- [ ] Linux server or mini PC with network access
- [ ] At least one VPN credential
- [ ] SSH access to the server
- [ ] Public IP or port forwarding for ProximaVPN access (if remote users needed)

### 1. Server Preparation

- [ ] Set timezone
- [ ] Install Docker: `curl -fsSL https://get.docker.com | sh`
- [ ] Verify Docker Compose v2: `docker compose version`

### 2. Install Proxima

```bash
cd /opt
sudo git clone https://github.com/erghold/proxima.git
cd proxima
docker network create proxy_net
mkdir -p config
cp proxima-config.example.json config/proxima-config.json
```

- [ ] Repository cloned
- [ ] `proxy_net` network created
- [ ] Config directory set up

### 3. Configure Environment

```bash
cd docker
cp .env.example .env
```

- [ ] Edit `.env` — set `TZ`
- [ ] Edit `config/proxima-config.json`:
  - [ ] Set `server_code`
  - [ ] Set `server_ip`
  - [ ] Configure at least one slot

### 4. Build and Start

```bash
cd /opt/proxima/docker
docker compose build proxima
docker compose --profile dns --profile build build
docker compose up -d proxima
docker compose --profile dns up -d
```

- [ ] Containers running
- [ ] Web UI accessible
- [ ] Admin account created

### 5. Add VPN Credentials

- [ ] Add keys/configs via Keys & Tunnels page
- [ ] Assign to slots and verify activation

### 6. Configure Domain Groups

- [ ] Set up domain groups and routing rules
- [ ] Use Config Sync to import groups from an existing site (optional)

### 7. Set Up ProximaVPN

This is the primary access method for Mode B — users connect via ProximaVPN instead of router-level routing.

- [ ] Install WireGuard on the server
- [ ] Configure `wg1` interface (port `5555`)
- [ ] Set up ProximaVPN subnet
- [ ] If behind NAT: configure port forwarding for `5555/UDP`
- [ ] Create VPN user accounts in Proxima UI
- [ ] Distribute ProximaVPN client app to users
- [ ] Test: user connects via ProximaVPN, traffic routes through VPN slots

### 8. SSL/HTTPS (Optional)

If the server has a public domain:

- [ ] Deploy NPM with Let's Encrypt
- [ ] Or use self-signed certificates for internal-only access

### Post-Deploy Verification

- [ ] VPN slots healthy
- [ ] ProximaVPN users can connect and route traffic
- [ ] Domain check passes for critical domains
- [ ] Backup configured (at minimum, manual periodic `proxima-config.json` copy)

---

## Teardown Checklist

When decommissioning a Proxima site:

- [ ] Export domain groups from Groups page (for reuse at another site)
- [ ] Back up `config/proxima-config.json` and `config/proxima.db`
- [ ] Revoke all VPN user credentials
- [ ] Remove ProximaVPN port forwarding from router
- [ ] Restore router DNS/gateway settings to defaults
- [ ] Stop and remove containers: `docker compose --profile dns down && docker compose down`
- [ ] Remove Docker images: `docker image prune -a`
- [ ] Remove project directory: `rm -rf /opt/proxima`
- [ ] Remove `proxy_net` network: `docker network rm proxy_net`
