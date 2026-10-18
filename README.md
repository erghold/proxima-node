# proxima-node

**Continuing from a copied folder:** read [AGENTS.md](AGENTS.md) and
[CONTINUITY.md](CONTINUITY.md) for local setup and the current handoff.
Old AI histories and sibling repositories are not startup requirements.
[Saved conversations](continuity/sessions/INDEX.md) are kept separate from
project state; [restore instructions](continuity/SESSIONS.md) travel with them.

Infrastructure-as-Code for [Proxima](https://github.com/erghold/proxima) server nodes — VPN exit servers and DPI bypass nodes.

Manages provisioning, configuration, credential rotation, and lifecycle of all Proxima server infrastructure via Ansible roles and playbooks.

## Server Types

| Type | Servers | Key Components |
|------|---------|---------------|
| **VPN Exit** | ERG-TR, ERG-DE, ERG-FI, ERG-PL | outline-ss-server, ssconf, speedtest, proxima-agent |
| **DPI Bypass** | ERG-RU (Pi5) | shadowsocks-libev, zapret-nfqws2, proxima-agent |

See [docs/server-types.md](docs/server-types.md) for detailed comparison.

## Quick Start

### Option 1: Ansible (recommended)

```bash
# Clone the repo on the Ansible control machine
git clone https://github.com/erghold/proxima-node.git
cd proxima-node

# Setup host variables
cp inventory/host_vars/erg-pl.yml.example inventory/host_vars/erg-pl.yml
# Edit with real values...

# Provision a VPN exit node (first connect, password auth):
ansible-playbook playbooks/setup-vpn-exit.yml -l erg-pl --ask-pass

# Provision a DPI bypass node:
ansible-playbook playbooks/setup-dpi-bypass.yml -l erg-ru --ask-pass
```

### Option 2: Standalone script (no Ansible needed on target)

```bash
# SSH into a fresh Debian 12 VPS as root:
curl -sSL https://raw.githubusercontent.com/erghold/proxima-node/main/setup.sh | bash
```

## Repo Structure

```
proxima-node/
├── ansible.cfg              # Ansible configuration
├── setup.sh                 # Standalone curl-installer (no Ansible needed)
│
├── inventory/
│   ├── hosts.yml            # Server inventory (IPs, groups)
│   ├── group_vars/          # Per-group defaults
│   └── host_vars/           # Per-server secrets (gitignored)
│
├── roles/
│   ├── common/              # System hardening, SSH, UFW, Docker
│   ├── outline-ss/          # Outline SS server (VPN exit)
│   ├── ss-server/           # shadowsocks-libev (DPI bypass)
│   ├── ssconf/              # SS config distribution server
│   ├── speedtest/           # Speed test server
│   ├── zapret/              # Zapret DPI bypass (nfqws2)
│   └── proxima-agent/       # Universal management agent
│
├── playbooks/
│   ├── site.yml             # Full site setup (all servers)
│   ├── setup-vpn-exit.yml   # VPN exit node provisioning
│   ├── setup-dpi-bypass.yml # DPI bypass node provisioning
│   ├── update-agent.yml     # Update proxima-agent everywhere
│   ├── health-check.yml     # Verify all servers healthy
│   ├── rotate-credentials.yml  # Rotate SS passwords, API keys
│   └── decommission.yml     # Safely remove a server
│
├── agent/                   # proxima-agent source code
│   ├── agent.py             # Universal agent (HTTPS, auto-detect server type)
│   └── requirements.txt
│
├── scripts/                 # Standalone bash scripts (used by setup.sh)
└── docs/                    # Documentation
```

## Playbooks

| Playbook | Purpose | Example |
|----------|---------|---------|
| `setup-vpn-exit.yml` | Provision VPN exit node | `ansible-playbook playbooks/setup-vpn-exit.yml -l erg-pl` |
| `setup-dpi-bypass.yml` | Provision DPI bypass node | `ansible-playbook playbooks/setup-dpi-bypass.yml -l erg-ru` |
| `site.yml` | All servers (dispatches by type) | `ansible-playbook playbooks/site.yml` |
| `update-agent.yml` | Update proxima-agent | `ansible-playbook playbooks/update-agent.yml` |
| `health-check.yml` | Check all servers | `ansible-playbook playbooks/health-check.yml` |
| `rotate-credentials.yml` | Rotate secrets | `ansible-playbook playbooks/rotate-credentials.yml -l erg-pl` |
| `decommission.yml` | Remove a server | `ansible-playbook playbooks/decommission.yml -l erg-old` |

## proxima-agent

Universal management agent deployed on every server. Provides HTTPS API (self-signed cert, API key auth) for remote management.

**Key endpoints:**
- `GET /health` — basic health check (no auth)
- `GET /api/status` — disk, memory, uptime, services
- `GET /api/info` — agent version, server type, cert fingerprint
- `POST /api/restart` — restart services
- `GET /api/ss-key` — current SS connection key

Auto-detects server type (VPN exit vs DPI bypass) and exposes type-specific endpoints.

## Requirements

- **Control machine:** Linux with Ansible 2.14+
- **Target servers:** Debian 12+ or Ubuntu 22+ with root SSH access
- **VPN exit:** KVM/QEMU VPS (required for WireGuard kernel module)

## Architecture

```
┌─────────────────────────────────────────────────┐
│           Control Machine (ERG)                  │
│    Ansible → SSH → target servers                │
│    adm.prxa.net → HTTPS → proxima-agents         │
└─────────────────────┬───────────────────────────┘
                      │
      ┌───────────────┼───────────────────┐
      │               │                   │
┌─────▼─────┐  ┌──────▼──────┐   ┌───────▼───────┐
│ VPN Exit   │  │ VPN Exit    │   │ DPI Bypass    │
│ ERG-PL     │  │ ERG-DE/FI/TR│   │ ERG-RU (Pi5)  │
│            │  │             │   │               │
│ outline-ss │  │ outline-ss  │   │ ss-server     │
│ ssconf     │  │ ssconf      │   │ zapret-nfqws2 │
│ speedtest  │  │ speedtest   │   │ proxima-agent │
│ prx-agent  │  │ prx-agent   │   │ watchdog      │
│ [AWG/Xray] │  │ [AWG/Xray]  │   └───────────────┘
└────────────┘  └─────────────┘
```

## License

MIT
