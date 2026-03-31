# MACDS AWS Deployment

## Architecture

| Component | Service | IP |
|---|---|---|
| Control Plane | EC2 t4g.small | 15.206.238.18 |
| Execution Plane | EC2 t4g.micro | 13.205.228.1 |
| Grafana Dashboard | EC2 t4g.micro | 3.108.240.174 |
| Docker Registry | ECR | 904690835691.dkr.ecr.ap-south-1.amazonaws.com |
| Attack History | DynamoDB | macds-attack-history |
| Q-table Backups | S3 | macds-qtables-904690835691 |
| Email Alerts | SNS | macds-attack-alerts |
| Auto-trainer | Lambda | macds-auto-trainer |
| Monitoring | CloudWatch | macds-ids-logs |

## Quick Start

### 1. Start Control Plane (EC2 #1)
```bash
ssh -i ~/.ssh/macds-key.pem ubuntu@15.206.238.18
docker ps  # verify macds_control_plane is running
curl http://localhost:8000/health
```

### 2. Start Execution Plane (EC2 #2)
```bash
ssh -i ~/.ssh/macds-key.pem ubuntu@13.205.228.1

# Terminal 1 — Start Mininet
sudo mn --custom ~/MACDS-main/execution_plane/topology/attacker_topo.py --topo attacktopo --mac

# Terminal 2 — Start IDS
cd ~/MACDS-main && source ~/macds-venv/bin/activate
sudo CONTROL_PLANE_URL=http://10.0.1.222:8000 ~/macds-venv/bin/python3 execution_plane/ids/h4_ids.py
```

### 3. Train Agents
```bash
curl -X POST "http://15.206.238.18:8000/api/train?rounds=500"
```

### 4. Launch Attack (Mininet CLI)
```
h3 hping3 -S -p 80 --flood 10.0.0.4
```

### 5. View Live Dashboard
Open: http://15.206.238.18:9000

## Update Docker Image
```bash
cd control_plane
docker buildx build --platform linux/arm64 -t macds-control-plane . --load
docker tag macds-control-plane:latest 904690835691.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest
docker push 904690835691.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest

# On EC2 #1
docker pull 904690835691.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest
docker stop macds_control_plane && docker rm macds_control_plane
docker run -d --name macds_control_plane --restart unless-stopped -p 8000:8000 -v ~/qtables:/app/qtables 904690835691.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest
```

## AWS Resource IDs
- VPC: vpc-031fccd1ad1044d29
- Subnet: subnet-04aa652dd34f6cb77
- Security Group (Control): sg-0f85ecfdb6ac53be8
- Security Group (Execution): sg-06eabdf64c5acd779
- Security Group (Grafana): sg-01736a885983be556
- EC2 Control: i-0fedf8bb453efb8f9
- EC2 Execution: i-0104f39266cac44a7
- EC2 Grafana: i-0a340b250b4615525
