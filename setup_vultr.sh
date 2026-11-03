#!/usr/bin/env bash
# One-shot provisioning for a fresh Vultr Cloud Compute VM (Ubuntu 24.04).
# Usage: sudo bash setup_vultr.sh   (run from the repo directory)
set -euo pipefail
APP_DIR=/opt/dealwatch
SUBNET=172.30.0.0/24

apt-get update -y
apt-get install -y ca-certificates curl gnupg python3-venv iptables debian-keyring debian-archive-keyring apt-transport-https

# Docker
if ! command -v docker >/dev/null; then curl -fsSL https://get.docker.com | sh; fi

# gVisor (runsc): user-space kernel between the sandbox and the host kernel
if ! command -v runsc >/dev/null; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
  apt-get update -y && apt-get install -y runsc
fi
runsc install
systemctl restart docker

# Caddy (HTTPS reverse proxy)
if ! command -v caddy >/dev/null; then
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y && apt-get install -y caddy
fi

# Isolated sandbox network
docker network inspect dwsandbox >/dev/null 2>&1 || \
  docker network create --driver bridge --subnet $SUBNET -o com.docker.network.bridge.name=dwsbx0 dwsandbox

# Egress firewall for the sandbox network (re-applied at boot)
cat > /usr/local/sbin/dealwatch-firewall <<FW
#!/bin/sh
for c in "DOCKER-USER" "INPUT"; do iptables -D \$c -s $SUBNET -j DWSANDBOX 2>/dev/null || true; done
iptables -F DWSANDBOX 2>/dev/null || iptables -N DWSANDBOX
iptables -A DWSANDBOX -d 169.254.0.0/16 -j REJECT
iptables -A DWSANDBOX -d 10.0.0.0/8 -j REJECT
iptables -A DWSANDBOX -d 172.16.0.0/12 -j REJECT
iptables -A DWSANDBOX -d 192.168.0.0/16 -j REJECT
iptables -A DWSANDBOX -d 100.64.0.0/10 -j REJECT
iptables -A DWSANDBOX -p tcp --dport 25 -j REJECT
iptables -A DWSANDBOX -j RETURN
iptables -I DOCKER-USER -s $SUBNET -j DWSANDBOX
# Sandbox -> host itself (control plane, SSH): only DNS to the embedded resolver is allowed
iptables -N DWSANDBOX_IN 2>/dev/null || iptables -F DWSANDBOX_IN
iptables -A DWSANDBOX_IN -p udp --dport 53 -j ACCEPT
iptables -A DWSANDBOX_IN -p tcp --dport 53 -j ACCEPT
iptables -A DWSANDBOX_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A DWSANDBOX_IN -j REJECT
iptables -D INPUT -i dwsbx0 -j DWSANDBOX_IN 2>/dev/null || true
iptables -I INPUT -i dwsbx0 -j DWSANDBOX_IN
FW
chmod +x /usr/local/sbin/dealwatch-firewall
cat > /etc/systemd/system/dealwatch-firewall.service <<UNIT
[Unit]
Description=DealWatch sandbox egress firewall
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dealwatch-firewall
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now dealwatch-firewall.service

# App
mkdir -p $APP_DIR /var/lib/dealwatch
cp app.py llm.py sandbox_runner.py index.html evil_deals.html requirements.txt Dockerfile.sandbox $APP_DIR/
python3 -m venv $APP_DIR/venv
$APP_DIR/venv/bin/pip install -q -r $APP_DIR/requirements.txt
docker build -t dealwatch-sandbox:latest -f $APP_DIR/Dockerfile.sandbox $APP_DIR
[ -f /etc/dealwatch.env ] || cp .env.example /etc/dealwatch.env
chmod 600 /etc/dealwatch.env

cat > /etc/systemd/system/dealwatch.service <<UNIT
[Unit]
Description=DealWatch Agent control plane
After=docker.service dealwatch-firewall.service
[Service]
WorkingDirectory=$APP_DIR
EnvironmentFile=/etc/dealwatch.env
ExecStart=$APP_DIR/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now dealwatch.service
systemctl restart dealwatch.service

IP=$(curl -s4 https://api.ipify.org)
HOST="${DEALWATCH_DOMAIN:-$(echo $IP | tr . -).sslip.io}"
cat > /etc/caddy/Caddyfile <<CF
$HOST {
  encode gzip
  reverse_proxy 127.0.0.1:8000
}
CF
systemctl reload caddy || systemctl restart caddy
echo "DealWatch is up at https://$HOST"
