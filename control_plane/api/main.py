import threading
from collections import OrderedDict

from fastapi import FastAPI, Query
from pydantic import BaseModel, Field
import time

from macds.agents.multi_agent import MultiAgentSystem

app = FastAPI(title="MACDS Control Plane API")

# FIFO ordered dict — oldest pending action served first.
# Lock required: FastAPI runs handlers in a thread pool.
pending_actions: OrderedDict[str, str] = OrderedDict()
_lock = threading.Lock()

# Single shared agents instance — ALL endpoints use this object.
# Training via /api/train updates THIS object's Q-tables in memory.
agents = MultiAgentSystem()


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
    """
    Receives an attack log from the Execution Plane.
    If attack is active: agents vote and queue the action.
    If attack resolved: queue unblock immediately.
    """
    current_state = {
        "packet_rate": log.packet_rate,
        "cpu_usage": log.cpu_usage,
        "bandwidth_usage": log.bandwidth_usage,
        "attack_type": log.attack_type.lower(),
    }

    if log.attack_type.lower() in ("none", ""):
        # Attack resolved — teach agents unblocking after attack is good
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

    # Attack ongoing — stable state is what we're aiming for
    stable_state = {
        "packet_rate": 50,
        "cpu_usage": 20,
        "bandwidth_usage": 20,
        "attack_type": "none",
    }

    agent_actions = agents.act(current_state)
    final_action = agents.coordinate(agent_actions)

    # block_ip is the correct response during an attack
    reward = 2.0 if final_action == "block_ip" else (0.5 if final_action == "raise_alert" else -2.0)
    agents.learn(current_state, final_action, reward, next_state=stable_state)

    if final_action != "do_nothing":
        with _lock:
            pending_actions[log.source_ip] = final_action

    return {"status": "success", "action_decided": final_action}


@app.get("/api/action")
async def get_action():
    """
    Execution plane polls this to retrieve and clear the next pending action.
    FIFO: oldest queued action is returned first.
    """
    with _lock:
        if pending_actions:
            target_ip = next(iter(pending_actions))
            action = pending_actions.pop(target_ip)
            return {"action": action, "target_ip": target_ip}
    return {"action": "none", "target_ip": ""}


@app.post("/api/train")
async def train_agents(rounds: int = Query(default=500, ge=1, le=5000)):
    """
    Train the LIVE agents object in-process.
    This is the ONLY correct way to train — docker exec creates a separate
    Python process with its own MultiAgentSystem that doesn't affect the API.
    Call this endpoint ONCE after startup to pre-train before real attacks.
    """
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
    """Show current agent epsilon values and pending action queue."""
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
