import os
import json
import random
from collections import defaultdict


# ============================================================
# Q-LEARNING AGENT
# ============================================================

class QLearningAgent:
    """
    Tabular Q-learning agent with epsilon decay and JSON persistence.
    """

    def __init__(
        self,
        name: str,
        actions: list,
        alpha: float = 0.1,
        gamma: float = 0.9,
        epsilon: float = 0.2,
        epsilon_min: float = 0.01,
        epsilon_decay: float = 0.9995,
    ):
        self.name = name
        self.actions = actions
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.q_table: dict = defaultdict(lambda: {a: 0.0 for a in actions})

    def discretize_state(self, state: dict) -> tuple:
        packet_rate = state.get("packet_rate", 0)
        cpu_usage = state.get("cpu_usage", 0)
        bandwidth = state.get("bandwidth_usage", 0)
        attack_type = state.get("attack_type", "none").lower()

        if packet_rate < 120:
            packet_bucket = "low"
        elif packet_rate < 300:
            packet_bucket = "medium"
        else:
            packet_bucket = "high"

        cpu_bucket = "high" if cpu_usage > 70 else "low"
        bw_bucket = "high" if bandwidth > 80 else "low"

        return (packet_bucket, cpu_bucket, bw_bucket, attack_type)

    def select_action(self, state: dict) -> str:
        s = self.discretize_state(state)
        if random.random() < self.epsilon:
            return random.choice(self.actions)
        return max(self.q_table[s], key=self.q_table[s].get)

    def update(self, state: dict, action: str, reward: float, next_state: dict):
        s = self.discretize_state(state)
        s_next = self.discretize_state(next_state)

        best_next_q = max(self.q_table[s_next].values())
        self.q_table[s][action] += self.alpha * (
            reward + self.gamma * best_next_q - self.q_table[s][action]
        )
        # Decay epsilon after every update — agents explore less over time
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        serializable = {str(k): v for k, v in self.q_table.items()}
        with open(path, "w") as f:
            json.dump({"epsilon": self.epsilon, "q_table": serializable}, f)

    def load(self, path: str):
        if not os.path.exists(path):
            return
        with open(path, "r") as f:
            data = json.load(f)
        self.epsilon = data.get("epsilon", self.epsilon)
        for k, v in data.get("q_table", {}).items():
            key = tuple(k.strip("()").replace("'", "").split(", "))
            self.q_table[key] = v


# ============================================================
# MULTI-AGENT SYSTEM
# ============================================================

QTABLE_DIR = "/app/qtables"


class MultiAgentSystem:
    """
    Three Q-learning agents with different hyperparameters vote on actions.
    Coordinator resolves votes by priority: block_ip > unblock_ip > raise_alert > do_nothing.
    Q-tables persist to /app/qtables/ (volume-mounted to Mac disk).
    """

    def __init__(self):
        actions = [
            "do_nothing",
            "raise_alert",
            "block_ip",
            "unblock_ip",
        ]

        # Different hyperparameters = independent voting behaviour
        self.agents = {
            "traffic_agent": QLearningAgent(
                "traffic_agent", actions, alpha=0.1, epsilon=0.3
            ),
            "ids_agent": QLearningAgent(
                "ids_agent", actions, alpha=0.05, epsilon=0.15
            ),
            "response_agent": QLearningAgent(
                "response_agent", actions, alpha=0.2, epsilon=0.1
            ),
        }

        # Load previously saved Q-tables if they exist
        self.load_all(QTABLE_DIR)

    def act(self, state: dict) -> dict:
        return {name: agent.select_action(state) for name, agent in self.agents.items()}

    def coordinate(self, actions: dict) -> str:
        """
        Priority-based conflict resolution.
        block_ip beats everything. unblock_ip and raise_alert are secondary.
        """
        vals = set(actions.values())
        if "block_ip" in vals:
            return "block_ip"
        if "unblock_ip" in vals:
            return "unblock_ip"
        if "raise_alert" in vals:
            return "raise_alert"
        return "do_nothing"

    def learn(self, state: dict, action: str, reward: float, next_state: dict):
        for agent in self.agents.values():
            agent.update(state, action, reward, next_state)
        self.save_all(QTABLE_DIR)

    def save_all(self, directory: str):
        os.makedirs(directory, exist_ok=True)
        for name, agent in self.agents.items():
            agent.save(os.path.join(directory, f"{name}.json"))

    def load_all(self, directory: str):
        for name, agent in self.agents.items():
            agent.load(os.path.join(directory, f"{name}.json"))
