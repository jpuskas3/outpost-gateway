#!/bin/bash
GATEWAY_DIR="/home/backup/outpost-gateway"

echo "[gateway] Stopping systemd services..."
sudo systemctl stop outpost-heartbeat outpost-auth-proxy outpost-gateway 2>/dev/null

echo "[gateway] Starting nginx container..."
docker stop outpost-gateway 2>/dev/null
docker rm outpost-gateway 2>/dev/null
docker build --network host -t outpost-gateway "$GATEWAY_DIR" -q
docker run -d \
    --name outpost-gateway \
    --network host \
    --restart unless-stopped \
    -v "$GATEWAY_DIR/logs:/var/log/nginx" \
    outpost-gateway

echo "[gateway] Starting heartbeat..."
OUTPOST_API=http://192.168.0.107:8000 \
GATEWAY_NODE=samsung \
GATEWAY_PORT=80 \
python3 "$GATEWAY_DIR/outpost-heartbeat.py" &

echo "[gateway] Auth proxy live — watching..."
OUTPOST_API=http://192.168.0.107:8000 \
OUTPOST_UI=http://192.168.0.107:80 \
SESSION_SECRET=crosbysucks04 \
python3 "$GATEWAY_DIR/auth_proxy.py"
