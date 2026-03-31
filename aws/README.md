# MACDS AWS Deployment

## Architecture

| Component | Service | IP |
|---|---|---|
| Control Plane | EC2 t4g.small | REDACTED |
| Execution Plane | EC2 t4g.micro | REDACTED |
| Grafana Dashboard | EC2 t4g.micro | REDACTED |
| Docker Registry | ECR | REDACTED.dkr.ecr.ap-south-1.amazonaws.com |
| Attack History | DynamoDB | macds-attack-history |
| Q-table Backups | S3 | macds-qtables-REDACTED |
| Email Alerts | SNS | macds-attack-alerts |
| Auto-trainer | Lambda | macds-auto-trainer |
| Monitoring | CloudWatch | macds-ids-logs |

## Quick Start

### 1. Start Control Plane (EC2 #1)
```bash
ssh -i ~/.ssh/macds-key.pem ubuntu@REDACTED
docker ps  # verify macds_control_plane is running
curl http://localhost:8000/health
```

### 2. Start Execution Plane (EC2 #2)
```bash
ssh -i ~/.ssh/macds-key.pem ubuntu@REDACTED

# Terminal 1 — Start Mininet
sudo mn --custom ~/MACDS-main/execution_plane/topology/attacker_topo.py --topo attacktopo --mac

# Terminal 2 — Start IDS
cd ~/MACDS-main && source ~/macds-venv/bin/activate
sudo CONTROL_PLANE_URL=http://10.0.1.222:8000 ~/macds-venv/bin/python3 execution_plane/ids/h4_ids.py
```

### 3. Train Agents
```bash
curl -X POST "http://REDACTED:8000/api/train?rounds=500"
```

### 4. Launch Attack (Mininet CLI)
```
h3 hping3 -S -p 80 --flood 10.0.0.4
```

### 5. View Live Dashboard
Open: http://REDACTED:9000

## Update Docker Image
```bash
cd control_plane
docker buildx build --platform linux/arm64 -t macds-control-plane . --load
docker tag macds-control-plane:latest REDACTED.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest
docker push REDACTED.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest

# On EC2 #1
docker pull REDACTED.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest
docker stop macds_control_plane && docker rm macds_control_plane
docker run -d --name macds_control_plane --restart unless-stopped -p 8000:8000 -v ~/qtables:/app/qtables REDACTED.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest
```

## AWS Resource IDs
- VPC: REDACTED
- Subnet: REDACTED
- Security Group (Control): REDACTED
- Security Group (Execution): REDACTED
- Security Group (Grafana): REDACTED
- EC2 Control: REDACTED
- EC2 Execution: REDACTED
- EC2 Grafana: REDACTED
