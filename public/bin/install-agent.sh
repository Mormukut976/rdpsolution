#!/bin/bash
set -e

# Usage helper
show_usage() {
    echo "Usage: sudo ./install-agent.sh -u <ServerUrl> -t <AgentToken>"
    exit 1
}

# Parse options
while getopts "u:t:" opt; do
    case "$opt" in
        u) SERVER_URL="${OPTARG%/}" ;;
        t) AGENT_TOKEN="$OPTARG" ;;
        *) show_usage ;;
    esac
done

if [ -z "$SERVER_URL" ] || [ -z "$AGENT_TOKEN" ]; then
    show_usage
fi

if [ "$EUID" -ne 0 ]; then
    echo "Please run this installer as root (using sudo)."
    exit 1
fi

echo "Installing OpenRemote Linux Agent..."

# Create installer path
INSTALL_DIR="/opt/openremote-agent"
mkdir -p "$INSTALL_DIR"

# Write the core script loop
CAT_AGENT_FILE="$INSTALL_DIR/openremote-agent.sh"
cat << 'EOF' > "$CAT_AGENT_FILE"
#!/bin/bash
SERVER_URL="$1"
AGENT_TOKEN="$2"

while true; do
    # Read CPU percentage
    # First reading can be inaccurate, get difference over 1 second
    CPU_PREV_IDLE=$(grep '^cpu ' /proc/stat | awk '{print $5}')
    CPU_PREV_TOTAL=$(grep '^cpu ' /proc/stat | awk '{sum=0; for (i=2; i<=8; i++) sum+=$i; print sum}')
    sleep 1
    CPU_NEXT_IDLE=$(grep '^cpu ' /proc/stat | awk '{print $5}')
    CPU_NEXT_TOTAL=$(grep '^cpu ' /proc/stat | awk '{sum=0; for (i=2; i<=8; i++) sum+=$i; print sum}')
    
    CPU_IDLE_DIFF=$((CPU_NEXT_IDLE - CPU_PREV_IDLE))
    CPU_TOTAL_DIFF=$((CPU_NEXT_TOTAL - CPU_PREV_TOTAL))
    
    if [ "$CPU_TOTAL_DIFF" -gt 0 ]; then
        CPU_USAGE=$(awk "BEGIN {print (1 - $CPU_IDLE_DIFF / $CPU_TOTAL_DIFF) * 100}")
    else
        CPU_USAGE=0
    fi

    # Read Memory percentage
    MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    MEM_AVAILABLE=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    if [ -z "$MEM_AVAILABLE" ]; then
        # Fallback if MemAvailable does not exist
        MEM_FREE=$(grep MemFree /proc/meminfo | awk '{print $2}')
        MEM_CACHED=$(grep -w Cached /proc/meminfo | awk '{print $2}')
        MEM_BUFFERS=$(grep Buffers /proc/meminfo | awk '{print $2}')
        MEM_AVAILABLE=$((MEM_FREE + MEM_CACHED + MEM_BUFFERS))
    fi
    MEM_USED=$((MEM_TOTAL - MEM_AVAILABLE))
    MEM_USAGE=$(awk "BEGIN {print ($MEM_USED / $MEM_TOTAL) * 100}")

    OS_INFO=$(uname -sr)
    HOSTNAME=$(hostname)
    CPU_COUNT=$(nproc)

    # Build JSON Payload
    JSON_PAYLOAD=$(cat <<EOF2
{
  "osInfo": "$OS_INFO",
  "cpuPercent": $CPU_USAGE,
  "memoryPercent": $MEM_USAGE,
  "metadata": {
    "machineName": "$HOSTNAME",
    "framework": "Bash Agent",
    "processorCount": $CPU_COUNT,
    "agentVersion": "0.1.0"
  }
}
EOF2
)

    # Post heartbeat
    curl -s -X POST "${SERVER_URL}/api/agent/heartbeat" \
      -H "Authorization: Bearer ${AGENT_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$JSON_PAYLOAD" > /dev/null || true

    # Sleep for remainder of the 30s cycle
    sleep 29
done
EOF

chmod +x "$CAT_AGENT_FILE"

# Create systemd service
SERVICE_FILE="/etc/systemd/system/openremote-agent.service"
cat << EOF > "$SERVICE_FILE"
[Unit]
Description=OpenRemote Linux Agent Service
After=network.target

[Service]
Type=simple
ExecStart=$CAT_AGENT_FILE "$SERVER_URL" "$AGENT_TOKEN"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start service
systemctl daemon-reload
systemctl enable openremote-agent.service
systemctl start openremote-agent.service

echo "OpenRemote Linux Agent successfully installed and started as a systemd service!"
