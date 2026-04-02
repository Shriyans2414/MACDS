import threading
import boto3
from collections import OrderedDict
from fastapi import FastAPI, Query
from pydantic import BaseModel, Field
# FIX: removed unused import time

from macds.agents.multi_agent import MultiAgentSystem
from collections import deque as _deque

CONFIDENCE_MULT = {"HIGH": 1.5, "MEDIUM": 1.0, "LOW": 0.5}
BLOCK_ON_SIGHT = {"SYN_FLOOD","UDP_FLOOD","ICMP_FLOOD","HTTP_FLOOD","LAND_ATTACK",
                  "SQL_INJECTION","XSS","PATH_TRAVERSAL","LOG4SHELL","SHELLSHOCK",
                  "CMD_INJECTION","SSRF","DNS_AMPLIFICATION","DNS_DGA","PORT_SCAN","CRAFT_ATTACK"}

_last_attack_state: dict[str, dict] = {} # FIX: Store prior attack state per IP

app = FastAPI(title="MACDS Control Plane API")

pending_actions: OrderedDict[str, str] = OrderedDict()
_lock = threading.Lock()
agents = MultiAgentSystem()

_verdicts: _deque = _deque(maxlen=500)
_vlock = threading.Lock()

try:
    dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
    table = dynamodb.Table("macds-attack-history")
    _dynamo_ok = True
except Exception:
    _dynamo_ok = False
    print("[WARN] DynamoDB unavailable")

class AttackLog(BaseModel):
    timestamp: float
    attack_type: str
    source_ip: str
    packet_rate: float = Field(default=500.0)
    cpu_usage: float = Field(default=80.0)
    bandwidth_usage: float = Field(default=90.0)
    confidence: str = Field(default="MEDIUM")
    detail: str = Field(default="")

@app.get("/health")
async def health():
    return {"status": "ok", "mode": "DPI"}

@app.post("/api/logs")
async def receive_log(log: AttackLog):
    current_state = {
        "packet_rate": log.packet_rate,
        "cpu_usage": log.cpu_usage,
        "bandwidth_usage": log.bandwidth_usage,
        "attack_type": log.attack_type.lower(),
    }

    mult = CONFIDENCE_MULT.get(log.confidence.upper(), 1.0)
    agent_actions_res = {}

    if log.attack_type.lower() in ("none", ""):
        attacked_state = _last_attack_state.get(log.source_ip) # FIX: get real prior state
        if not attacked_state: # FIX: fallback only if no prior state is known
            attacked_state = {
                "packet_rate": 500,
                "cpu_usage": 80,
                "bandwidth_usage": 90,
                "attack_type": "syn_flood",
            }
        agents.learn(attacked_state, "unblock_ip", reward=1.0 * mult, next_state=current_state)
        if log.source_ip in _last_attack_state: # FIX: clean up dict entry
            del _last_attack_state[log.source_ip] # FIX: clean up dict entry
        with _lock:
            pending_actions[log.source_ip] = "unblock_ip"
        final_action = "unblock_ip"
    else:
        _last_attack_state[log.source_ip] = current_state # FIX: save current attack state
        stable_state = {
            "packet_rate": 50,
            "cpu_usage": 20,
            "bandwidth_usage": 20,
            "attack_type": "none",
        }

        agent_actions = agents.act(current_state)
        agent_actions_res = agent_actions
        final_action = agents.coordinate(agent_actions)

        reward = (2.0 if final_action == "block_ip" else 0.5 if final_action == "raise_alert" else -2.0) * mult
        if log.confidence.upper() == "HIGH" and log.attack_type.upper() in BLOCK_ON_SIGHT and final_action == "do_nothing":
            final_action = "block_ip"

        agents.learn(current_state, final_action, reward, next_state=stable_state)

        if _dynamo_ok:
            try:
                table.put_item(Item={
                    "timestamp": str(log.timestamp),
                    "attack_type": log.attack_type,
                    "source_ip": log.source_ip,
                    "action_decided": final_action,
                    "packet_rate": str(log.packet_rate),
                    "confidence": log.confidence,
                    "detail": log.detail[:500]
                })
            except Exception as e:
                print(f"[DynamoDB ERROR] {e}")

        if final_action != "do_nothing":
            with _lock:
                pending_actions[log.source_ip] = final_action

    with _vlock:
        _verdicts.append({
            "timestamp": log.timestamp,
            "attack_type": log.attack_type,
            "source_ip": log.source_ip,
            "confidence": log.confidence,
            "detail": log.detail[:200],
            "action": final_action
        })

    resp = {"status": "success", "action_decided": final_action, "confidence": log.confidence}
    if agent_actions_res:
        resp["agents_voted"] = agent_actions_res
    return resp

@app.get("/api/action")
async def get_action():
    with _lock:
        if pending_actions:
            target_ip = next(iter(pending_actions))
            action = pending_actions.pop(target_ip)
            return {"action": action, "target_ip": target_ip}
    return {"action": "none", "target_ip": ""}

@app.get("/api/verdicts")
async def get_verdicts(limit: int = Query(default=50, ge=1, le=500)):
    with _vlock:
        items = list(_verdicts)[-limit:]
    return {"verdicts": list(reversed(items)), "total": len(items)}

@app.post("/api/train")
async def train_agents(rounds: int = Query(default=500, ge=1, le=5000)):
    scenarios = [
        ({"packet_rate":2000,"cpu_usage":80,"bandwidth_usage":90,"attack_type":"syn_flood"}, "block_ip", 2.0),
        ({"packet_rate":500, "cpu_usage":60,"bandwidth_usage":70,"attack_type":"sql_injection"}, "block_ip", 2.0),
        ({"packet_rate":100, "cpu_usage":30,"bandwidth_usage":30,"attack_type":"port_scan"}, "raise_alert", 1.0),
        ({"packet_rate":50,  "cpu_usage":20,"bandwidth_usage":20,"attack_type":"none"}, "do_nothing", 0.5),
    ]
    stable_state = {
        "packet_rate": 50,
        "cpu_usage": 20,
        "bandwidth_usage": 20,
        "attack_type": "none",
    }
    block_count = 0
    for i in range(rounds):
        state, correct, reward = scenarios[i % 4]
        actions = agents.act(state)
        final = agents.coordinate(actions)
        actual_reward = reward if final == correct else -1.0
        agents.learn(state, final, actual_reward, next_state=stable_state)
        if final == "block_ip":
            block_count += 1

    agents.save_all("/app/qtables") # FIX: flush q-tables once after training completes

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
