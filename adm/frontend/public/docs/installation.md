# Installation & Setup

This guide covers installing Proxima on a fresh Linux server, running the initial setup wizard, and configuring your router.

---

## Quick Install (Recommended)

Run the guided installer on your Linux server as root:

```bash
curl -fsSL https://raw.githubusercontent.com/erghold/proxima/main/install.sh | sudo bash
```

The installer will:
1. Scan your system for existing components
2. Collect all configuration inputs upfront (routing mode, admin credentials, etc.)
3. Install Docker, AmneziaWG kernel module, and AdGuard Home as needed
4. Clone the repo, build containers, and start all services
5. Print access URLs and a "what to do next" summary

Continue with **Step 5: Setup Wizard** below after the installer finishes.

---

## Hardware Requirements

Resource usage scales with the number of active VPN slots, not the number of groups. Groups are nftables rules and dnsmasq config entries — adding more groups has no measurable overhead.

| | **Minimal** | **Standard** | **Full** |
|---|---|---|---|
| **Active slots** | 1 | 3 | 3 |
| **Groups** | 1 | 3 | 10+ |
| **Keys / slot** | 1 (no failover) | 2 (failover) | 2 (failover) |
| **Recommended mode** | DNS | DNS | DNS |
| **Running containers** | proxima + 1× awg + dnsmasq + dns-router | proxima + 3× awg + dnsmasq + dns-router | same as Standard |
| **RAM — active use** | ~700 MB | ~1.1 GB | ~1.2 GB |
| **RAM — recommended** | 2 GB | 4 GB | 4 GB |
| **CPU — minimum** | 2 cores | 4 cores | 4 cores |
| **CPU — recommended** | 2 cores | 4 cores | 6–8 cores |
| **Disk** | 10 GB SSD | 15 GB SSD | 20 GB SSD |
| **Concurrent users** | 1–3 | 5–15 | 15–50 |
| **Concurrent HD streams** | 1–2 | 3–6 | 6–15 |
| **Concurrent 4K streams** | 1 | 2–3 | 3–6 |
| **AdGuard Home** | ✅ | ✅ | ✅ |
| **ProximaVPN** | ✅ | ✅ | ✅ |
| **Raspberry Pi 5 8 GB** | ✅ comfortable | ✅ adequate | ✅ requires NVMe HAT |
| **Example hardware** | Pi 5 4 GB · 1-vCPU VPS | Pi 5 8 GB · 2-vCPU VPS | 4–8 core mini PC · 4-vCPU VPS |

> **Note:** Concurrent stream counts depend on the AWG tunnel server's outbound bandwidth, not local hardware. Moving from Standard → Full requires no hardware change — only additional configuration in the UI.

> **Raspberry Pi 5:** Use NVMe storage via PCIe HAT — SQLite writes and log rotation will wear out an SD card under production load. Active cooling is required for sustained AWG throughput.

---

## Manual Installation

Follow these steps if you prefer to install manually or need custom configuration.

---

## Prerequisites

### VPN Credentials (Required Before Installing)

Proxima is a VPN client and traffic router — it does not provide VPN servers. You must have at least one of the following before you can route any traffic:

| Type | Format | Notes |
|------|--------|-------|
| **AmneziaWG** | `.conf` file content | From a self-hosted or commercial AWG server |
| **Shadowsocks** | `ss://` URI | From any SS provider or self-hosted server |
| **Outline SS+Prefix** | `ssconf://` URL | DPI-resistant obfuscated SS. From [VanyaVPN](https://vanya.jp.net/) or a self-hosted Outline server |
| **VLESS+Reality** | Server address + UUID + keys | From a self-hosted Xray server. Mimics normal TLS traffic |

You add these after installation via the **Keys & Tunnels** page. Without at least one working credential, Proxima installs successfully but has nothing to route traffic through.

> Setting up your own exit node? See [Self-Hosted Outline Server](/docs/self-hosted-outline.md) or [Self-Hosted AWG Server](/docs/self-hosted-awg.md).

---

### Server Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Debian 12 / Ubuntu 22.04 | Debian 12 |
| Docker | 24.0+ | Latest stable |
| Docker Compose | v2.20+ | Latest stable |
| Network | Static LAN IP | Static LAN IP |

> **Important:** Never run Docker on ZFS storage. Use ext4 or xfs on SSD/NVMe. Set `data-root` in `/etc/docker/daemon.json` if needed.

### Network Requirements

- The server must have a **static LAN IP** address
- Router admin access is required to configure DNS settings after installation
- The server must be reachable as both DNS server and gateway
- Firewall must allow inbound traffic on required ports (see below)

---

## Step 1: Install Docker

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Add your user to the docker group
sudo usermod -aG docker $USER

# Verify Docker is running
docker --version
docker compose version
```

If Docker's data-root needs to be on a different disk:

```bash
sudo mkdir -p /etc/docker
sudo cat > /etc/docker/daemon.json << 'EOF'
{
  "data-root": "/mnt/nvme/docker"
}
EOF
sudo systemctl restart docker
```

---

## Step 2: Clone and Configure

```bash
# Clone the repository
cd /opt
sudo git clone https://github.com/erghold/proxima.git
cd proxima

# Create the Docker network
docker network create proxy_net

# Create config directory
mkdir -p config

# Copy example config
cp proxima-config.example.json config/proxima-config.json

# Set up environment variables
cd docker
cp .env.example .env
# Edit .env — set TZ to your timezone, adjust ports if needed
```

---

## Step 3: Firewall Configuration

### UFW (Debian/Ubuntu)

```bash
# API and frontend
sudo ufw allow 5050/tcp

# DNS
sudo ufw allow 53/tcp
sudo ufw allow 53/udp

# Proxy gateway (for Docker containers)
sudo ufw allow 8080/tcp
```

### iptables

```bash
sudo iptables -A INPUT -p tcp --dport 5050 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
```

---

## Step 4: Build and Start

### Basic Start (Management Plane Only)

```bash
cd docker
docker compose build proxima
docker compose up -d proxima
```

### DNS Mode (Full Stack)

```bash
cd docker
docker compose --profile dns build
docker compose --profile dns up -d
```

---

## Step 5: First Launch

Open `http://SERVER_IP:5050` in your browser.

### Create Admin Account

On first launch, Proxima shows a setup wizard to create the admin account. Set your username and password — this is used for all Proxima UI access.

> **If you used the guided installer:** the installer already configured server IP, routing mode, and proxy mode. You only need to create the admin account here.

### Router Configuration

The wizard shows router-specific instructions based on your mode selection.

---

## Step 6: Router Configuration

Configure your router's DHCP to assign:
- **DNS server** = Proxima server IP
- **Default gateway** = Proxima server IP (for transparent routing)

#### Keenetic Router

1. Go to **Internet** > **DNS Servers**
2. Add Proxima server IP as primary DNS
3. Go to **Network Rules** > **Static Routes**
4. Optionally add a secondary DNS (router IP) as failsafe

#### MikroTik Router

```
# Set DNS server in DHCP
/ip dhcp-server network set [find] dns-server=192.168.77.121

# Optionally disable DNS-over-HTTPS on the router
/ip dns set use-doh-server=""
```

---

## Step 7: Add VPN Configurations

After the wizard completes, go to the **Keys** page to add your VPN credentials:

### For AmneziaWG

1. Go to the **AWG Configs** tab
2. Click **New AWG Config**
3. Paste the `.conf` file content
4. The config is automatically sanitized (removes DNS/Table/PostUp/PostDown)
5. Assign to an AWG slot pool on the Dashboard

### For VLESS+Reality (Xray)

1. Click **New Tunnel Config** and select type **Xray**
2. Enter the server address, port, VLESS UUID, Reality public key, and short ID
3. Assign to an Xray slot pool on the Dashboard

---

## Step 8: Configure Domain Groups

Go to the **Groups** page to set up domain routing:

1. Create groups (e.g., "Streaming", "AI", "Social")
2. Add domains to each group
3. Assign each group to a slot
4. Mark critical domains for failover monitoring

> **See also:** [Domain Management](/docs/domains.md) for detailed instructions

---

## Step 9: SSL/HTTPS (Recommended)

For secure remote access, set up HTTPS using [Nginx Proxy Manager](https://nginxproxymanager.com/) (NPM). NPM is the standard reverse proxy for Proxima (per ADR-002).

1. Deploy NPM as a separate Docker Compose stack (external to Proxima)
2. Connect NPM to the `proxy_net` Docker network
3. Create a proxy host: `your-domain.example.com` → `proxima:5000`
4. Enable SSL with Let's Encrypt (automatic certificate provisioning)
5. Access Proxima via `https://your-domain.example.com`

> **Note:** NPM runs outside of Proxima's docker-compose.yml. It is a separate service that you manage independently. See the [Deployment Checklists](/docs/deployment-checklist.md) for detailed steps.

---

## Verifying the Installation

### Check Container Status

```bash
cd /opt/proxima/docker
docker compose ps
```

All containers should show `Up` status.

### Check API Health

```bash
curl http://localhost:5050/api/status
```

Should return JSON with slot health information.

### Check DNS

```bash
# From a client device using Proxima as DNS
nslookup youtube.com SERVER_IP
```

---

## Updating Proxima

```bash
cd /opt/proxima
git pull
cd docker
docker compose build proxima
docker compose up -d proxima
```

For DNS Mode containers:

```bash
docker compose --profile dns build
docker compose --profile dns up -d
```

> **See also:** [Deployment & Operations](/docs/deployment.md) for detailed deployment procedures
