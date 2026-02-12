![Python](https://img.shields.io/badge/Python-3.10-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Research--Prototype-orange)
![Platform](https://img.shields.io/badge/platform-Ubuntu%2020.04+-orange)

# MACDS: Multi-Agent Autonomous Cyber Defense System

- MACDS is a modular, lifecycle-driven cyber defense architecture designed to autonomously detect, mitigate, and recover from network-based attacks in real time.
- Unlike traditional IDS solutions that stop at detection, MACDS implements a full closed-loop defense lifecycle:  
Detection → Mitigation → Recovery → Stability

The system is architected using strict separation of concerns to preserve realistic network behavior while enabling scalable, containerized coordination logic.

---

## Overview

MACDS is a lifecycle-driven cyber defense architecture that separates detection and decision-making into two independent but interoperable planes:

- **Execution Plane** — Realistic network emulation and intrusion detection (Mininet-based)
- **Control Plane** — multi-agent lifecycle coordination based  defense orchestration (Dockerized)

The system supports real-time detection, adaptive response, and cross-container execution control.
This repository contains the full reproducible implementation.

---

## Design Principles

- Separation of execution and orchestration
- Event-driven state transitions
- Reversible mitigation
- Deterministic lifecycle behavior
- Operational metric-first evaluation

 --- 

# Why MACDS?

Most intrusion detection systems:
- Focus on classification accuracy
- Ignore mitigation orchestration
- Lack recovery modeling
- Do not measure operational impact
MACDS is built around operational resilience.

---

## System Architecture
MACDS uses a two-plane architecture:
```text
┌─────────────────────────────┐
│        Control Plane        │
│  (Docker Multi-Agent RL)    │
│                             │
│  Sensor → Detector →        │
│  Responder → Recovery       │
└─────────────┬───────────────┘
              │
        docker exec bridge
              │
┌─────────────▼───────────────┐
│        Execution Plane      │
│     (Mininet Emulation)     │
│                             │
│  Attacker → Victim (IDS)    │
│  Real Packet Inspection     │
└─────────────────────────────┘
```
Execution Plane
- Runs real protocol stacks
- Uses Mininet for realistic network emulation
- Performs kernel-level mitigation
- Preserves timing and enforcement realism

Control Plane
- Containerized via Docker Compose
- Multi-agent lifecycle orchestration
- Event-driven state transitions
- No packet-level interference

Control-plane logic never processes raw packets, preserving execution-plane timing fidelity

---

# Core Features
- Real-time intrusion detection
- Autonomous mitigation enforcement
- Explicit recovery modeling
- Reversible blocking logic
- Structured lifecycle event logging
- Online + offline processing modes
- Fully containerized deployment
- Deterministic behavior under load

---

# Defense Lifecycle Model

Each traffic source is modeled as a finite-state process:
> Normal → UnderAttack → Mitigated → Normal

Mitigation is:
- Idempotent
- Source-scoped
- Automatically withdrawn after sustained recovery window
- Resistant to oscillation
This prevents long-lived false blocking and service degradation.

---

## Execution Plane (Mininet)
> Located in: execution_plane

Implements:

- Custom Mininet topology
- Live network traffic emulation
- Victim host with stateful IDS
- Kernel-level mitigation using packet filtering
- Attack simulation:
  - ICMP flood
  - TCP SYN flood
  - UDP flood
  - Vertical port scan
  - Horizontal scan
- Structured lifecycle event logging
- Optional dashboard interface

The execution plane preserves realistic protocol stacks and enforcement timing.

---

## Control Plane (Dockerized Multi-Agent System)
> Located in: control_plane

Implements:

- Modular multi-agent coordination:
  - Sensor Agent
  - Detector Agent
  - Responder Agent
  - Recovery Agent
  - Analysis Agent
- Explicit lifecycle state modeling
- Automated mitigation orchestration
- Reversible recovery logic
- Containerized deployment via Docker Compose
- Reproducible experimental execution

Run:

```bash
cd control_plane
docker compose up --build

# Optional execution bridge:
ENABLE_DOCKER_EXEC=1 docker compose up
```
The execution bridge allows the control plane to perform real mitigation actions inside the execution plane.

---

## Running Execution Plane

The execution plane simulates network topology and attack traffic using Mininet.

### System Requirements

- Ubuntu 20.04+ (Recommended)
- Python 3.9+
- Mininet
- Root privileges (sudo required)

### Install Mininet

```bash
sudo apt update
sudo apt install mininet
```

### Install Python Dependencies

From project root:
```bash
pip install -r requirements.txt
```
### Running the Execution Plane
```bash
cd execution_plane
sudo python3 network_topology.py
```
### Attack Simulation Example
```bash
sudo python3 attack_simulation.py
```

---

# Evaluation Approach

MACDS supports:
- Online (live execution) mode
- Offline (PCAP replay) mode

Operational metrics measured:
- Detection latency
- Response latency
- Service downtime
- Recovery time
- Lifecycle stability

Evaluation is system-level and deployment-oriented rather than classifier-centric.

---

# Scope

MACDS focuses on:
- Network-layer attacks
- Transport-layer flooding
- Scanning behavior
- Metadata-observable anomalies

It does not target:
- Payload inspection
- Host compromise
- Distributed reflection attacks
- Application-layer semantic abuse

---
