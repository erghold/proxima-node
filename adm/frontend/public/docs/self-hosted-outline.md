# Self-Hosted Outline SS Server

Deploy your own Shadowsocks+Prefix (Outline protocol) exit node on any Linux VPS and add it to Proxima in under 10 minutes.

## What Gets Installed

Two lightweight services run on the VPS:

| Service | Role | Port |
|---------|------|------|
| `outline-ss-server` | Shadowsocks server (chacha20-ietf-poly1305 + TLS prefix) | 8388/tcp+udp |
| `proxima-ssconf` | Tiny HTTPS endpoint serving the key config in ssconf:// format | 8390/tcp |

Proxima's backend fetches the ssconf JSON to configure its Outline client container. The prefix makes traffic look like a TLS handshake to bypass DPI.

---

## Quick Setup (Single Script)

SSH into the VPS as root and run:

```bash
bash <(curl -sL https://raw.githubusercontent.com/erghold/proxima/main/scripts/setup-outline-ss.sh)
```

> If the script is not yet available, follow the **Manual Steps** below — the script does exactly the same thing.

The script will:
1. Download `outline-ss-server` v1.9.2 binary
2. Generate a random password, token, and TLS prefix
3. Create `/opt/outline-ss/` with all config files
4. Generate a self-signed TLS certificate (10-year validity)
5. Create and enable systemd services
6. Open UFW rules if UFW is active
7. Print the `ssconf://` URL to paste into Proxima

---

## Manual Steps

### 1. Prepare the directory and binary

```bash
mkdir -p /opt/outline-ss
cd /tmp
curl -sL https://github.com/OutlineFoundation/tunnel-server/releases/download/v1.9.2/outline-ss-server_1.9.2_linux_x86_64.tar.gz | tar xz
cp outline-ss-server /opt/outline-ss/
chmod +x /opt/outline-ss/outline-ss-server
```

### 2. Generate credentials

```bash
PASSWORD=$(python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())")
TOKEN=$(python3 -c "import os; print(os.urandom(24).hex())")
PREFIX="FgMBAgABAAH8AwM="   # TLS 1.3 ClientHello header — DPI bypass
SERVER_IP=$(curl -s https://api.ipify.org)

echo "Password : $PASSWORD"
echo "Token    : $TOKEN"
echo "Server IP: $SERVER_IP"
```

Save these — you'll need them in the next steps.

### 3. Create server config

```bash
cat > /opt/outline-ss/config.yml << EOF
services:
  - listeners:
      - type: tcp
        address: "[::]:8388"
      - type: udp
        address: "[::]:8388"
    keys:
      - id: proxima
        cipher: chacha20-ietf-poly1305
        secret: "$PASSWORD"
        prefix: "$PREFIX"
EOF
```

### 4. Generate self-signed certificate

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /opt/outline-ss/key.pem \
  -out /opt/outline-ss/cert.pem \
  -days 3650 -nodes -subj "/CN=proxima-ssconf" 2>/dev/null
```

### 5. Create the ssconf HTTPS server

```bash
cat > /opt/outline-ss/ssconf-server.py << PYEOF
#!/usr/bin/env python3
import json, ssl, http.server

TOKEN = "$TOKEN"
CONFIG = {
    "server": "$SERVER_IP",
    "server_port": 8388,
    "password": "$PASSWORD",
    "method": "chacha20-ietf-poly1305",
    "prefix": "$PREFIX"
}

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == f"/{TOKEN}":
            data = json.dumps(CONFIG).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, fmt, *args):
        pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/opt/outline-ss/cert.pem", "/opt/outline-ss/key.pem")
server = http.server.HTTPServer(("0.0.0.0", 8390), Handler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print("ssconf server listening on :8390", flush=True)
server.serve_forever()
PYEOF
chmod +x /opt/outline-ss/ssconf-server.py
```

### 6. Fix file permissions

Both services run as `nobody`. Give them read access:

```bash
chown -R nobody:nogroup /opt/outline-ss
chmod 750 /opt/outline-ss
chmod 640 /opt/outline-ss/*.pem /opt/outline-ss/config.yml
chmod 755 /opt/outline-ss/outline-ss-server /opt/outline-ss/ssconf-server.py
```

### 7. Create systemd services

```bash
cat > /etc/systemd/system/outline-ss-server.service << 'EOF'
[Unit]
Description=Outline SS Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/outline-ss/outline-ss-server -config /opt/outline-ss/config.yml
Restart=always
RestartSec=5
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/proxima-ssconf.service << 'EOF'
[Unit]
Description=Proxima ssconf HTTPS Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/outline-ss/ssconf-server.py
Restart=always
RestartSec=5
User=nobody
Group=nogroup
WorkingDirectory=/opt/outline-ss

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable outline-ss-server proxima-ssconf
systemctl start outline-ss-server proxima-ssconf
```

### 8. Verify services are running

```bash
systemctl is-active outline-ss-server proxima-ssconf
ss -tlnp | grep -E ':(8388|8390)'
```

Expected output:
```
active
active
LISTEN  *:8388  ...  outline-ss-serv
LISTEN  0.0.0.0:8390  ...  python3
```

### 9. Open firewall (if UFW is active)

```bash
# Check if UFW is running
ufw status | head -1

# If active, open the required ports
ufw allow 8388/tcp
ufw allow 8388/udp
ufw allow 8390/tcp
```

### 10. Test the ssconf endpoint

From the Proxima server (ERG or OFC):

```bash
curl -sk https://YOUR_VPS_IP:8390/YOUR_TOKEN
```

Expected JSON response:
```json
{
  "server": "YOUR_VPS_IP",
  "server_port": 8388,
  "password": "...",
  "method": "chacha20-ietf-poly1305",
  "prefix": "FgMBAgABAAH8AwM="
}
```

---

## Adding to Proxima

Your `ssconf://` URL is:

```
ssconf://YOUR_VPS_IP:8390/YOUR_TOKEN#ServerName
```

Add this in Proxima → **Keys** → **Outline (SS+Prefix)** section → **Add Outline Config**.

The name (after `#`) is just a display label. Choose something descriptive like `ERG-DE` or `My-Finland-VPS`.

**Slot assignment:** Assign the key to an existing Outline slot or create a new one. Multiple keys per slot form a failover pool — if one fails, Proxima rotates to the next automatically.

---

## Design Notes

**Why self-signed cert?**
The ssconf endpoint only needs to be reachable from your Proxima servers (ERG, OFC). It is not a public service. Proxima fetches it with `verify=False`. The token in the URL path provides authentication — only someone with the full URL can retrieve the config.

**What does the prefix do?**
`FgMBAgABAAH8AwM=` decodes to the first 11 bytes of a TLS 1.3 ClientHello record header. These bytes are prepended to every Shadowsocks handshake by `outline-ss-local` on the client side. To a DPI system, the connection looks like HTTPS traffic. Both client and server must use the same prefix.

**outline-ss-server vs shadowsocks-libev**
`outline-ss-server` (by Jigsaw/Google's OutlineFoundation) natively supports prefix configuration per key. `shadowsocks-libev` does not — it would receive the prefix bytes as garbage and fail to decrypt.

**Port 8390 security**
The ssconf endpoint only needs to be reachable from your Proxima servers — not from end users. You can restrict UFW to allow 8390 only from ERG/OFC IPs if you want extra hardening:
```bash
ufw allow from 46.138.254.119 to any port 8390  # ERG public IP
ufw allow from 46.39.245.211 to any port 8390   # OFC public IP
```

---

## Maintenance

### Rotate the password

Generate a new password, update `config.yml` and `ssconf-server.py`, then restart:

```bash
# Edit /opt/outline-ss/config.yml — update secret
# Edit /opt/outline-ss/ssconf-server.py — update password in CONFIG dict
systemctl restart outline-ss-server proxima-ssconf
```

Then in Proxima → Keys, delete the old key and add the URL again (the ssconf endpoint will return the new config).

### Check logs

```bash
journalctl -u outline-ss-server -f
journalctl -u proxima-ssconf -f
```

### Upgrade outline-ss-server

```bash
cd /tmp
curl -sL https://github.com/OutlineFoundation/tunnel-server/releases/download/vX.Y.Z/outline-ss-server_X.Y.Z_linux_x86_64.tar.gz | tar xz
cp outline-ss-server /opt/outline-ss/
chown nobody:nogroup /opt/outline-ss/outline-ss-server
chmod 755 /opt/outline-ss/outline-ss-server
systemctl restart outline-ss-server
```

---

## Current Deployments

| Server | IP | Region | Port | ssconf Port |
|--------|----|--------|------|-------------|
| ERG-DE | 46.224.49.250 | Hetzner, Nuremberg | 8388 | 8390 |
| ERG-FI | 109.120.187.205 | Aeza, Finland | 8388 | 8390 |

Both servers auto-start on reboot via systemd.
