#!/bin/bash
GATEWAY_DIR="/home/backup/outpost-gateway"
DOCKER="/usr/bin/docker"

echo "Starting Outpost Gateway (Nginx only)..."

# Stop and remove existing nginx container
if $DOCKER ps -aq -f name=outpost-gateway | grep -q .; then
    $DOCKER stop outpost-gateway 2>/dev/null
    $DOCKER rm outpost-gateway 2>/dev/null
fi

# Build nginx gateway image
echo "Building gateway image..."
if ! $DOCKER build --network host -t outpost-gateway "$GATEWAY_DIR"; then
    echo "Gateway build failed."
    exit 1
fi

# Run nginx with host networking
echo "Starting nginx gateway..."
if ! $DOCKER run -d \
    --name outpost-gateway \
    --network host \
    --restart unless-stopped \
    -v "$GATEWAY_DIR/logs:/var/log/nginx" \
    outpost-gateway; then
    echo "Gateway start failed."
    exit 1
fi

echo "Gateway live on port 80."
