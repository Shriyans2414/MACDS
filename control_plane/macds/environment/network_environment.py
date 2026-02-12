import random
import numpy as np
from macds.environment.docker_monitor import detect_attack



class NetworkEnvironment:
    """
    Hybrid Cyber Network Environment

    - Real attack detection from Mininet/Docker
    - Attack type classification (ddos / portscan)
    - Simulated impact dynamics
    - Designed for multi-agent learning
    """

    def __init__(self, seed=42):
        random.seed(seed)
        np.random.seed(seed)

        # ---------------- NETWORK TOPOLOGY ----------------
        self.servers = ["server_1"]
        self.clients = ["client_1", "client_2", "client_3"]

        # ---------------- TIME ----------------
        self.time_step = 0

        # ---------------- ATTACK STATE ----------------
        self.active_attack = None        # "ddos", "portscan", None
        self.attack_severity = 1.0       # numeric, always float

        # ---------------- NETWORK METRICS ----------------
        self.packet_rate = 0
        self.failed_logins = 0
        self.connection_entropy = 0.0
        self.cpu_usage = 0.0
        self.bandwidth_usage = 0.0

        # ---------------- HISTORY LOGS ----------------
        self.history = {
            "packet_rate": [],
            "failed_logins": [],
            "connection_entropy": [],
            "cpu_usage": [],
            "bandwidth_usage": [],
            "attack": [],
            "reward": [],
        }

        self.reset()

    # --------------------------------------------------
    # RESET ENVIRONMENT
    # --------------------------------------------------
    def reset(self):
        self.time_step = 0
        self.active_attack = None
        self.attack_severity = 1.0

        self.packet_rate = random.randint(80, 120)
        self.failed_logins = random.randint(0, 2)
        self.connection_entropy = round(random.uniform(1.0, 2.0), 2)
        self.cpu_usage = round(random.uniform(10, 30), 2)
        self.bandwidth_usage = round(random.uniform(20, 40), 2)

        self._log_state(0.0)
        return self.get_state()

    # --------------------------------------------------
    # STEP FUNCTION (CORE LOOP)
    # --------------------------------------------------
    def step(self, action="do_nothing"):
        self.time_step += 1

        # ===== REAL ATTACK DETECTION =====
        event = detect_attack()

        if event:
            self.active_attack = event.get("attack")
            rate = event.get("rate", 0.0)

            # Convert rate → bounded severity
            try:
                rate = float(rate)
            except (TypeError, ValueError):
                rate = 0.0

            self.attack_severity = min(2.0, 1.0 + rate / 500.0)
        else:
            self.active_attack = None
            self.attack_severity = 1.0

        # ===== NORMAL TRAFFIC FLUCTUATIONS =====
        self.packet_rate += random.randint(-5, 5)
        self.failed_logins += random.choice([0, 0, 1])
        self.connection_entropy += random.uniform(-0.05, 0.05)

        # ===== APPLY ATTACK EFFECTS =====
        if self.active_attack:
            self._apply_attack_effects()

        # ===== CLAMP VALUES =====
        self.packet_rate = max(0, self.packet_rate)
        self.failed_logins = max(0, self.failed_logins)
        self.connection_entropy = max(0.5, self.connection_entropy)

        # ===== SYSTEM LOAD ESTIMATION =====
        self.cpu_usage = min(100, round(self.packet_rate * 0.2, 2))
        self.bandwidth_usage = min(100, round(self.packet_rate * 0.3, 2))

        # ===== REWARD =====
        reward = self._calculate_reward(action)

        self._log_state(reward)

        next_state = self.get_state()
        done = self.time_step >= 20

        return next_state, reward, done

    # --------------------------------------------------
    # ATTACK EFFECTS (SEVERITY-AWARE)
    # --------------------------------------------------
    def _apply_attack_effects(self):
        severity = float(self.attack_severity)

        if self.active_attack == "ddos":
            self.packet_rate += int(severity * random.randint(40, 80))
            self.connection_entropy += severity * random.uniform(0.2, 0.5)

        elif self.active_attack == "portscan":
            self.connection_entropy += severity * random.uniform(0.6, 1.2)
            self.packet_rate += int(severity * random.randint(10, 25))

    # --------------------------------------------------
    # REWARD FUNCTION
    # --------------------------------------------------
    def _calculate_reward(self, action):
        reward = 0.0

        # ---- Successful mitigation ----
        if self.active_attack and self.packet_rate < 200:
            reward += 5.0

        # ---- System stability ----
        if self.cpu_usage < 70 and self.bandwidth_usage < 80:
            reward += 1.0

        # ---- False positives ----
        if not self.active_attack and action != "do_nothing":
            reward -= 3.0

        # ---- Overreaction penalty ----
        if action == "block_ip" and not self.active_attack:
            reward -= 5.0

        return reward

    # --------------------------------------------------
    # OBSERVABLE STATE
    # --------------------------------------------------
    def get_state(self):
        return {
            "packet_rate": self.packet_rate,
            "failed_logins": self.failed_logins,
            "connection_entropy": round(self.connection_entropy, 2),
            "cpu_usage": self.cpu_usage,
            "bandwidth_usage": self.bandwidth_usage,
            "attack_type": self.active_attack or "none",
        }

    # --------------------------------------------------
    # LOGGING
    # --------------------------------------------------
    def _log_state(self, reward):
        self.history["packet_rate"].append(self.packet_rate)
        self.history["failed_logins"].append(self.failed_logins)
        self.history["connection_entropy"].append(
            round(self.connection_entropy, 2)
        )
        self.history["cpu_usage"].append(self.cpu_usage)
        self.history["bandwidth_usage"].append(self.bandwidth_usage)
        self.history["attack"].append(self.active_attack)
        self.history["reward"].append(reward)
