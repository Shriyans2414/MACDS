# MACDS — Multi-Agent Autonomous Cyber Defense System

Two-plane architecture: Execution Plane on Ubuntu/Mininet, Control Plane on Mac/Docker.

## Architecture

```
Ubuntu (Mininet)                          Mac (Docker)
─────────────────                         ────────────────────────
h4_ids.py                                 FastAPI :8000
  Scapy sniffs s1-eth3  ──POST /api/logs──►  MultiAgentSystem
  client.py polls        ◄─GET /api/action──  Q-learning × 3 agents
  iptables block/unblock                      /app/qtables/ (persisted)
```

## Step 1 — Mac: Start Control Plane

```bash
cd control_plane
docker-compose up -d --build
curl http://localhost:8000/health   # should return {"status":"ok"}
```

## Step 2 — Mac: Run smoke test

```bash
pip install requests
python3 test_flow.py   # should show 14/14 passed
```

## Step 3 — Mac: Pre-train agents

```bash
curl -s -X POST "http://localhost:8000/api/train?rounds=500" | python3 -m json.tool
# block_ip_rate should be > 95%
```

## Step 4 — Ubuntu: Install dependencies

```bash
sudo apt install mininet tcpdump hping3 -y
python3 -m venv ~/macds-venv
source ~/macds-venv/bin/activate
pip install scapy requests
```

## Step 5 — Ubuntu: Find Mac's IP

```bash
# Run on Mac:
ipconfig getifaddr en0
# Note this IP — call it <MAC_IP>
```

## Step 6 — Ubuntu Terminal 1: Start Mininet

```bash
cd /home/mininet/macds-main
sudo mn --custom execution_plane/topology/attacker_topo.py --topo attacktopo --mac
```

## Step 7 — Ubuntu Terminal 2: Start IDS

Open a second SSH session to Ubuntu (plain shell, NOT inside Mininet CLI):

```bash
cd /home/mininet/macds-main
sudo CONTROL_PLANE_URL=http://<MAC_IP>:8000 /home/mininet/macds-venv/bin/python3 execution_plane/ids/h4_ids.py
```

Expected output:
```
[*] MACDS IDS starting
[*] Sniffing interface: s1-eth3
[*] Control plane reachable at http://<MAC_IP>:8000
[*] Polling http://<MAC_IP>:8000/api/action for actions
```

## Step 8 — Mininet CLI: Launch attack

```bash
mininet> h3 hping3 -S -p 80 --flood 10.0.0.4
```

## What you will see

**Ubuntu IDS terminal:**
```
[ATTACK START] SYN FLOOD from 10.0.0.3 (2000+ pps)
[CLIENT] Log sent: SYN_FLOOD from 10.0.0.3
[CLIENT] Blocking 10.0.0.3
```

**Mac Docker logs** (`docker logs -f macds_control_plane`):
```
POST /api/logs HTTP/1.1" 200 OK
GET /api/action HTTP/1.1" 200 OK
```

**Stop the attack** (Ctrl+C in Mininet):
```
[ATTACK END] SYN FLOOD ended from 10.0.0.3
[CLIENT] Log sent: none from 10.0.0.3
[CLIENT] Unblocking 10.0.0.3
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check |
| POST | /api/logs | Receive attack log from IDS |
| GET | /api/action | Poll for enforcement action |
| POST | /api/train?rounds=N | Train live agents in-process |
| GET | /api/status | Show agent epsilons + pending queue |
| GET | /docs | Interactive Swagger UI |

## Key design decisions

- **IDS runs outside Mininet namespace** — Ubuntu plain shell, sniffs s1-eth3
- **CONTROL_PLANE_URL via sudo VAR=val** — sudo -E doesn't work on this Ubuntu
- **Training via /api/train only** — docker exec creates a separate process
- **Q-tables volume-mounted** — ./qtables on Mac persists across container restarts
- **Thresholds at 20 pps** — tuned for VM; raise to 300/400/500 for real hardware
