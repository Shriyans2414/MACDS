# MACDS AWS Deployment

## Architecture

| Component | Service | IP |
|---|---|---|
| Control Plane | EC2 t4g.small | <CONTROL_PLANE_PUBLIC_IP> |
| Execution Plane | EC2 t4g.micro | <EXECUTION_PLANE_PUBLIC_IP> |
| Grafana Dashboard | EC2 t4g.micro | <DASHBOARD_PUBLIC_IP> |
| Docker Registry | ECR | <AWS_ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com |
| Attack History | DynamoDB | macds-attack-history |
| Q-table Backups | S3 | macds-qtables-<AWS_ACCOUNT_ID> |
| Email Alerts | SNS | macds-attack-alerts |
| Auto-trainer | Lambda | macds-auto-trainer |
| Monitoring | CloudWatch | macds-ids-logs |

## Quick Start

### 1. Start Control Plane (EC2 #1)
```bash
ssh -i ~/.ssh/macds-key.pem ubuntu@<CONTROL_PLANE_PUBLIC_IP>
docker ps  # verify macds_control_plane is running
curl http://localhost:8000/health
```

### 2. Start Execution Plane (EC2 #2)
```bash
ssh -i ~/.ssh/macds-key.pem ubuntu@<EXECUTION_PLANE_PUBLIC_IP>

# Terminal 1 — Start Mininet
sudo mn --custom ~/MACDS-main/execution_plane/topology/attacker_topo.py --topo attacktopo --mac

# Terminal 2 — Start IDS
cd ~/MACDS-main && source ~/macds-venv/bin/activate
sudo CONTROL_PLANE_URL=http://<CONTROL_PLANE_PRIVATE_IP>:8000 ~/macds-venv/bin/python3 execution_plane/ids/h4_ids.py
```

### 3. Train Agents
```bash
curl -X POST "http://<CONTROL_PLANE_PUBLIC_IP>:8000/api/train?rounds=500"
```

### 4. Launch Attack (Mininet CLI)
```
h3 hping3 -S -p 80 --flood 10.0.0.4
```

### 5. View Live Dashboard
Open: http://<CONTROL_PLANE_PUBLIC_IP>:9000

## Update Docker Image
```bash
cd control_plane
docker buildx build --platform linux/arm64 -t macds-control-plane . --load
docker tag macds-control-plane:latest <AWS_ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest
docker push <AWS_ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest

# On EC2 #1
docker pull <AWS_ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest
docker stop macds_control_plane && docker rm macds_control_plane
docker run -d --name macds_control_plane --restart unless-stopped -p 8000:8000 -v ~/qtables:/app/qtables <AWS_ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/macds-control-plane:latest
```

## AWS Resource IDs
- VPC: <VPC_ID>
- Subnet: <SUBNET_ID>
- Security Group (Control): <SG_CONTROL_ID>
- Security Group (Execution): <SG_EXECUTION_ID>
- Security Group (Grafana): <SG_GRAFANA_ID>
- EC2 Control: <EC2_CONTROL_INSTANCE_ID>
- EC2 Execution: <EC2_EXECUTION_INSTANCE_ID>
- EC2 Grafana: <EC2_GRAFANA_INSTANCE_ID>
