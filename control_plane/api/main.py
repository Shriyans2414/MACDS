import threading
import boto3
from collections import OrderedDict
from fastapi import FastAPI, Query
from pydantic import BaseModel, Field
import time

from macds.agents.multi_agent import MultiAgentSystem

app = FastAPI(title="MACDS Control Plane API")

pending_actions: OrderedDict[str, str] = OrderedDict()
_lock = threading.Lock()
agents = MultiAgentSystem()

dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
table = dynamodb.Table("macds-attack-history")

class AttackLog(BaseModel):
    timestamp: float
    attack_type: str
    source_ip: str
    packet_rate: float = Field(default=500.0)
    cpu_usage: float = Field(default=80.0)
    bandwidth_usage: float = Field(default=90.0)

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/api/logs")
async def receive_log(log: AttackLog):
    current_state = {
        "packet_rate": log.packet_rate,
        "cpu_usage": log.cpu_usage,
        "bandwidth_usage": log.bandwidth_usage,
        "attack_type": log.attack_type.lower(),
    }

    if log.attack_type.lower() in ("none", ""):
        attacked_state = {
            "packet_rate": 500,
            "cpu_usage": 80,
            "bandwidth_usage": 90,
            "attack_type": "syn_flood",
        }
        agents.learn(attacked_state, "unblock_ip", reward=1.0, next_state=current_state)
        with _lock:
            pending_actions[log.source_ip] = "unblock_ip"
        return {"status": "success", "action_decided": "unblock_ip"}

    stable_state = {
        "packet_rate": 50,
        "cpu_usage": 20,
        "bandwidth_usage": 20,
        "attack_type": "none",
    }

    agent_actions = agents.act(current_state)
    final_action = agents.coordinate(agent_actions)

    reward = 2.0 if final_action == "block_ip" else (0.5 if final_action == "raise_alert" else -2.0)
    agents.learn(current_state, final_action, reward, next_state=stable_state)

    try:
        table.put_item(Item={
            "timestamp": str(log.timestamp),
            "attack_type": log.attack_type,
            "source_ip": log.source_ip,
            "action_decided": final_action,
            "packet_rate": str(log.packet_rate),
        })
    except Exception as e:
        print(f"[DynamoDB ERROR] {e}")

    if final_action != "do_nothing":
        with _lock:
            pending_actions[log.source_ip] = final_action

    return {"status": "success", "action_decided": final_action}

@app.get("/api/action")
async def get_action():
    with _lock:
        if pending_actions:
            target_ip = next(iter(pending_actions))
            action = pending_actions.pop(target_ip)
            return {"action": action, "target_ip": target_ip}
    return {"action": "none", "target_ip": ""}

@app.post("/api/train")
async def train_agents(rounds: int = Query(default=500, ge=1, le=5000)):
    attack_state = {
        "packet_rate": 2000,
        "cpu_usage": 80,
        "bandwidth_usage": 90,
        "attack_type": "syn_flood",
    }
    stable_state = {
        "packet_rate": 50,
        "cpu_usage": 20,
        "bandwidth_usage": 20,
        "attack_type": "none",
    }
    block_count = 0
    for _ in range(rounds):
        actions = agents.act(attack_state)
        final = agents.coordinate(actions)
        reward = 2.0 if final == "block_ip" else -2.0
        agents.learn(attack_state, final, reward, next_state=stable_state)
        if final == "block_ip":
            block_count += 1

    return {
        "rounds": rounds,
        "block_ip_count": block_count,
        "block_ip_rate": f"{block_count / rounds * 100:.1f}%",
        "message": "Agents trained in-process. Q-tables saved to /app/qtables/",
    }

@app.get("/api/status")
async def status():
    return {
        "pending_actions": dict(pending_actions),
        "agent_epsilons": {
            name: round(agent.epsilon, 4)
            for name, agent in agents.agents.items()
        },
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
