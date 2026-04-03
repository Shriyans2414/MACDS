<div align="center">

# MACDS
### Multi-Agent Autonomous Cyber Defense System

[![AWS](https://img.shields.io/badge/AWS-Deployed-FF9900?style=flat-square&logo=amazon-aws&logoColor=white)](http://15.206.238.18:9000)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![DynamoDB](https://img.shields.io/badge/DynamoDB-Attack%20History-4053D6?style=flat-square&logo=amazon-dynamodb&logoColor=white)](https://aws.amazon.com/dynamodb/)
[![Lambda](https://img.shields.io/badge/Lambda-Auto--Train-FF9900?style=flat-square&logo=aws-lambda&logoColor=white)](https://aws.amazon.com/lambda/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Live](https://img.shields.io/badge/Dashboard-Live-22c55e?style=flat-square)](http://15.206.238.18:9000)

**A production-deployed, self-learning network defense system — three Q-learning agents cooperatively detect, classify, and block attacks in under one second with no human in the loop.**


</div>

---

## Overview

MACDS is an autonomous intrusion defense system that replaces static firewall rules with a team of reinforcement learning agents. It runs a full network simulation on AWS EC2, sniffs traffic in real time, and enforces `iptables` decisions — all within a sub-second feedback loop.

**The core insight:** no single agent is trusted. Three independent Q-learning agents with different hyperparameters vote on every detected event. A priority-based coordinator resolves conflicts. The winning action is enforced immediately and the outcome feeds back into each agent's Q-table — the system gets smarter with every attack.

```
Attack detected → DPI analysis → 3 agents vote → coordinator resolves
      → iptables block → DynamoDB log → Q-tables update → repeat
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        AWS VPC  ·  ap-south-1                        │
│                                                                      │
│   ┌────────────────────────────┐    ┌────────────────────────────┐   │
│   │   EC2 #1  ·  Control Plane │    │  EC2 #2  ·  Execution Plane│   │
│   │   15.206.238.18            │    │  13.205.228.1              │   │
│   │                            │    │                            │   │
│   │  FastAPI  :8000            │◄──►│  Mininet  (h1-h4, s1)      │   │
│   │  traffic_agent             │    │  Deep Packet Inspector     │   │
│   │  ids_agent                 │    │  TCP fingerprinting        │   │
│   │  response_agent            │    │  HTTP inspection           │   │
│   │  Priority coordinator      │    │  DNS analysis              │   │
│   │  Q-tables /app/qtables     │    │  Payload scanning          │   │
│   │  Live dashboard  :9000     │    │  Behavioral profiling      │   │
│   └────────────┬───────────────┘    └────────────────────────────┘   │
│                │                                                     │
│   S3  DynamoDB  CloudWatch  SNS  Lambda  ECR  IAM                    │
└──────────────────────────────────────────────────────────────────────┘
```

### Two-Plane Design

| Plane | Role |
|---|---|
| **Control Plane** | AI decision engine — agents vote, coordinator resolves, action queued |
| **Execution Plane** | Network layer — DPI sniffs traffic, enforces iptables rules |

The planes communicate exclusively over the private VPC network via REST. No credentials on the wire — IAM role-based access throughout.

---

## Detection Capabilities

### Deep Packet Inspector

The DPI engine runs five parallel analysis modules on every packet:

| Module | What it detects |
|---|---|
| **TCP fingerprinting** | Identifies hping3, nmap, raw sockets by window size and TCP option signatures |
| **HTTP inspection** | Bots missing User-Agent, HTTP/1.0 tools, absent Sec-Fetch browser headers |
| **DNS analysis** | ANY-query amplification, PTR reverse scanning, high-entropy DGA malware domains |
| **Payload scanning** | SQL injection, XSS, path traversal, Log4Shell, ShellShock, SSRF, command injection |
| **Behavioral profiling** | SYN/ACK ratio, machine-regular inter-packet timing (CV < 0.05), port diversity scoring |

Every verdict carries a confidence score — HIGH, MEDIUM, or LOW — that scales the RL reward signal and gates BLOCK_ON_SIGHT enforcement for critical attack types.

### Classic IDS (threshold-based)

| Attack | Detection | Threshold |
|---|---|---|
| SYN Flood | TCP SYN packets / src / sec | 20 pps |
| UDP Flood | UDP packets / src / sec | 20 pps |
| ICMP DDoS | ICMP packets / src / 2s | 10 pps |
| HTTP Flood | TCP :80 packets / sec (non-SYN) | 20 pps |
| Port Scan | Unique dst ports / src / 2s | 5 ports |
| Land Attack | src IP == dst IP | 1 packet |

---

## Reinforcement Learning Design

### Agents

| Agent | alpha | epsilon | Role |
|---|---|---|---|
| `traffic_agent` | 0.10 | 0.30 | High exploration — discovers novel attack patterns |
| `ids_agent` | 0.05 | 0.15 | Conservative — stable, reliable intrusion decisions |
| `response_agent` | 0.20 | 0.10 | Fast learner — exploits known good responses |

### State Space

Each state is a 4-tuple discretized from raw telemetry:

```
(packet_rate_bucket, cpu_bucket, bandwidth_bucket, attack_type)
 low|medium|high      low|high    low|high           string
```

### Action Space

```
block_ip  →  raise_alert  →  unblock_ip  →  do_nothing
```

### Coordination

Priority arbitration resolves agent votes:
- `block_ip` wins if any agent votes for it
- `unblock_ip` requires >= 2 votes — prevents premature unblocking
- `raise_alert` wins if no blocking vote exists
- `BLOCK_ON_SIGHT` overrides `do_nothing` for HIGH-confidence critical attacks

### Reward Shaping

```
reward = base_reward × confidence_multiplier
         (2.0 block / 0.5 alert / -2.0 nothing) × (HIGH=1.5 / MED=1.0 / LOW=0.5)
```

### Q-Table Persistence

Q-tables persist to `/app/qtables/` every 50 updates and are backed up hourly to S3. Zero learning loss across container restarts or instance reboots.

---

## AWS Infrastructure

| Service | Resource | Purpose |
|---|---|---|
| EC2 | t4g.small | Control plane |
| EC2 | t4g.micro | Execution plane |
| ECR | macds-control-plane | Docker image registry |
| DynamoDB | macds-attack-history | Attack log with type, IP, action, confidence, detail |
| S3 | macds-qtables | Hourly Q-table backups |
| CloudWatch | macds-ids-logs | Log streaming and metric filters |
| SNS | macds-attack-alerts | Email alerts on attack detection |
| Lambda | macds-auto-trainer | Calls /api/train on attack spike |
| IAM | macds-ec2-role | Role-based access — no hardcoded credentials |
| VPC | 10.0.0.0/16 | Private subnet, Elastic IPs, security groups |

### Self-Healing Loop

```
Attack spike detected
    → CloudWatch alarm fires (threshold: >= 3 attacks/min)
    → SNS triggers Lambda
    → Lambda calls POST /api/train?rounds=200
    → Agents retrain in-process on live data
    → Block rate improves with no human intervention
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Returns {"status":"ok","mode":"DPI"} |
| `POST` | `/api/logs` | Ingest attack event — agents vote and act |
| `GET` | `/api/action` | Poll next enforcement action (FIFO) |
| `GET` | `/api/verdicts?limit=N` | Last N AI decisions with confidence and detail |
| `POST` | `/api/train?rounds=N` | Multi-scenario in-process training |
| `GET` | `/api/status` | Agent epsilons and pending action queue |
| `GET` | `/docs` | Swagger UI |

---

## Quickstart

### Prerequisites

- Docker Desktop
- Mininet (`sudo apt install mininet hping3 nmap`)
- Python 3.10+

### Local

```bash
# 1. Start control plane
cd control_plane
docker-compose up -d --build
curl http://localhost:8000/health

# 2. Pre-train agents
curl -X POST "http://localhost:8000/api/train?rounds=500"

# 3. Start Mininet (Terminal 1)
sudo mn --custom execution_plane/topology/attacker_topo.py \
        --topo attacktopo --mac

# 4. Start DPI (Terminal 2)
source ~/macds-venv/bin/activate
sudo CONTROL_PLANE_URL=http://<HOST_IP>:8000 \
  python3 execution_plane/ids/deep_packet_inspector.py

# 5. Launch attack (Mininet CLI)
mininet> h3 hping3 -S -p 80 --flood 10.0.0.4
```

### Cloud (AWS)

```bash
# Build and push image
cd control_plane
aws ecr get-login-password --region ap-south-1 | \
  docker login --username AWS --password-stdin <ACCOUNT>.dkr.ecr.ap-south-1.amazonaws.com

docker buildx build --platform linux/arm64 -t macds-control-plane . --load
docker tag macds-control-plane:latest <ECR_URI>:latest
docker push <ECR_URI>:latest

# Deploy on EC2 #1
docker pull <ECR_URI>:latest
docker run -d --name macds_control_plane --restart unless-stopped \
  -p 8000:8000 -v ~/qtables:/app/qtables <ECR_URI>:latest

# Run DPI on EC2 #2
sudo CONTROL_PLANE_URL=http://<EC2_1_PRIVATE_IP>:8000 \
  python3 execution_plane/ids/deep_packet_inspector.py
```

Full step-by-step AWS setup: [`aws/README.md`](aws/README.md)

---

## Repository Structure

```
MACDS/
├── control_plane/
│   ├── api/
│   │   └── main.py                    # FastAPI + agent orchestration + DynamoDB
│   ├── macds/agents/
│   │   └── multi_agent.py             # Q-learning agents + priority coordinator
│   ├── qtables/                       # Persisted Q-tables (JSON)
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── requirements.txt
├── execution_plane/
│   ├── ids/
│   │   ├── deep_packet_inspector.py   # DPI — TCP / HTTP / DNS / payload / behavior
│   │   └── h4_ids.py                 # Classic threshold-based IDS
│   ├── topology/
│   │   └── attacker_topo.py          # Mininet 4-host topology
│   └── communication/
│       └── client.py                 # Control plane client + iptables enforcement
├── aws/
│   ├── README.md                     # Complete AWS deployment guide
│   └── dashboard.py                  # Live web dashboard (reads DynamoDB)
├── docs/figures/                     # Architecture and results diagrams
└── test_flow.py                      # End-to-end integration tests
```

---

## Results

| Metric | Result |
|---|---|
| Detection latency | < 1 second end-to-end |
| Peak attack rate handled | 2,168 pps (UDP flood) |
| TCP fingerprint precision | hping3 identified by window=512 + missing SACK/TS options |
| Multi-scenario block rate | 52.2% — optimal for 4-scenario training mix |
| DPI attack types covered | 16 attack types across network, application, and DNS layers |
| Q-table convergence | < 500 training rounds |
| S3 backup frequency | Every 1 hour |
| Self-healing trigger | >= 3 attacks/min → Lambda retrains agents automatically |

> The 52.2% block rate is the theoretical optimum for multi-scenario training — only 50% of training scenarios require block_ip as the correct action. 100% would indicate overfitting to flood attacks only.

---

## License

[MIT](LICENSE)
