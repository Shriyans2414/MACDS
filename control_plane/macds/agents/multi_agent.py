import random
from collections import defaultdict


# ============================================================
# Q-LEARNING AGENT
# ============================================================

class QLearningAgent:
    """
    Tabular Q-learning agent for cyber defense decisions.
    """

    def __init__(
        self,
        name,
        actions,
        alpha=0.1,     # learning rate
        gamma=0.9,     # discount factor
        epsilon=0.2,   # exploration rate
    ):
        self.name = name
        self.actions = actions
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon

        # Q-table: state -> action -> Q-value
        self.q_table = defaultdict(lambda: {a: 0.0 for a in actions})

    # --------------------------------------------------------
    # STATE DISCRETIZATION (VERY IMPORTANT)
    # --------------------------------------------------------
    def discretize_state(self, state):
        """
        Convert continuous environment state into discrete bins
        suitable for tabular Q-learning.
        """

        packet_rate = state.get("packet_rate", 0)
        cpu_usage = state.get("cpu_usage", 0)
        bandwidth = state.get("bandwidth_usage", 0)
        attack_type = state.get("attack_type", "none")

        # ---- packet rate buckets ----
        if packet_rate < 120:
            packet_bucket = "low"
        elif packet_rate < 200:
            packet_bucket = "medium"
        else:
            packet_bucket = "high"

        # ---- CPU bucket ----
        cpu_bucket = "high" if cpu_usage > 70 else "low"

        # ---- bandwidth bucket ----
        bw_bucket = "high" if bandwidth > 80 else "low"

        # Final discrete state
        return (packet_bucket, cpu_bucket, bw_bucket, attack_type)

    # --------------------------------------------------------
    # ACTION SELECTION (ε-GREEDY)
    # --------------------------------------------------------
    def select_action(self, state):
        s = self.discretize_state(state)

        # Exploration
        if random.random() < self.epsilon:
            return random.choice(self.actions)

        # Exploitation
        return max(self.q_table[s], key=self.q_table[s].get)

    # --------------------------------------------------------
    # Q-LEARNING UPDATE
    # --------------------------------------------------------
    def update(self, state, action, reward, next_state):
        s = self.discretize_state(state)
        s_next = self.discretize_state(next_state)

        best_next_q = max(self.q_table[s_next].values())

        self.q_table[s][action] += self.alpha * (
            reward
            + self.gamma * best_next_q
            - self.q_table[s][action]
        )


# ============================================================
# MULTI-AGENT SYSTEM
# ============================================================

class MultiAgentSystem:
    """
    Multi-agent coordination system using Q-learning agents.

    Flow:
      Environment State
          ↓
      Each Agent selects action (Q-learning)
          ↓
      Coordinator resolves conflicts
          ↓
      Final action executed on Docker
    """

    def __init__(self):
        actions = [
            "do_nothing",
            "raise_alert",
            "block_ip",
            "recover_ip",
            "unblock_ip",
        ]

        # Independent learning agents
        self.agents = {
            "traffic_agent": QLearningAgent("traffic_agent", actions),
            "ids_agent": QLearningAgent("ids_agent", actions),
            "response_agent": QLearningAgent("response_agent", actions),
        }

    # --------------------------------------------------------
    # AGENT ACTION PROPOSAL
    # --------------------------------------------------------
    def act(self, state):
        """
        Each agent independently proposes an action.
        """
        actions = {}
        for name, agent in self.agents.items():
            actions[name] = agent.select_action(state)
        return actions

    # --------------------------------------------------------
    # COORDINATION / CONFLICT RESOLUTION
    # --------------------------------------------------------
    def coordinate(self, actions):
        """
        Resolve multiple agent actions into a single system action.
        Priority-based policy.
        """

        # Highest priority: active mitigation
        if "block_ip" in actions.values():
            return "block_ip"

        # Controlled recovery after mitigation
        if "recover_ip" in actions.values():
            return "recover_ip"

        # Full unblock if stable
        if "unblock_ip" in actions.values():
            return "unblock_ip"

        # Alerting (non-destructive)
        if "raise_alert" in actions.values():
            return "raise_alert"

        return "do_nothing"

    # --------------------------------------------------------
    # LEARNING UPDATE (SHARED REWARD)
    # --------------------------------------------------------
    def learn(self, state, action, reward, next_state):
        """
        All agents learn from the same global reward.
        """
        for agent in self.agents.values():
            agent.update(state, action, reward, next_state)
