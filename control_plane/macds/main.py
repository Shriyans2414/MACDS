import time
import os
import pickle
import subprocess
from pathlib import Path

from macds.environment.network_environment import NetworkEnvironment
from macds.agents.multi_agent import MultiAgentSystem

# ---------------- PATH SETUP ----------------
BASE_DIR = Path(__file__).resolve().parent
ANALYSIS_DIR = BASE_DIR / "analysis"

LOG_PATH = ANALYSIS_DIR / "run_logs.pkl"
SPEED_PATH = ANALYSIS_DIR / "training_speed.pkl"
CONTROL_PATH = ANALYSIS_DIR / "training_control.pkl"

ANALYSIS_DIR.mkdir(exist_ok=True)

# ---------------- CONSTANTS ----------------
SERVER_CONTAINER = "macds_server"
EXEC_SCRIPT_PATH = "/opt/macds_exec/execute_action.sh"
ATTACKER_IP = "172.18.0.5"  # fixed attacker IP for demo


# ---------------- HELPERS ----------------
def get_speed():
    try:
        if SPEED_PATH.exists():
            with open(SPEED_PATH, "rb") as f:
                return pickle.load(f)
    except Exception:
        pass
    return 0.5


def is_paused():
    try:
        if CONTROL_PATH.exists():
            with open(CONTROL_PATH, "rb") as f:
                return pickle.load(f)
    except Exception:
        pass
    return False


# ---------------- EXECUTION BRIDGE ----------------
def execute_defense(action, target_ip):
    """
    Executes real system defense inside Docker container.
    Disabled by default unless ENABLE_DOCKER_EXEC=1 is set.
    """

    # ---- Standalone mode (default) ----
    if os.environ.get("ENABLE_DOCKER_EXEC") != "1":
        return "EXECUTION_DISABLED"

    # ---- Only execute valid defense actions ----
    if action not in ["block_ip", "unblock_ip", "recover_ip"]:
        return "NO_EXECUTION"

    try:
        result = subprocess.run(
            [
                "docker",
                "exec",
                SERVER_CONTAINER,
                EXEC_SCRIPT_PATH,
                action,
                target_ip,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return f"EXECUTION_FAILED: {result.stderr.strip()}"

    except Exception as e:
        return f"EXECUTION_ERROR: {str(e)}"


# ---------------- TRAINING LOOP ----------------
def run_training():
    env = NetworkEnvironment()
    agents = MultiAgentSystem()

    episode_rewards = []
    action_timeline = []
    execution_logs = []

    print("\n--- TRAINING STARTED ---\n")

    for episode in range(1, 101):

        state = env.reset()
        total_reward = 0.0

        for step in range(20):

            while is_paused():
                time.sleep(0.5)

            # -------- AGENT DECISION --------
            actions = agents.act(state)
            final_action = agents.coordinate(actions)

            # -------- EXECUTE DEFENSE --------
            exec_status = execute_defense(final_action, ATTACKER_IP)
            print("Execution status:", exec_status)

            # -------- ENVIRONMENT UPDATE --------
            next_state, reward, done = env.step(final_action)
            agents.learn(state, final_action, reward, next_state)

            state = next_state
            total_reward += reward

            print("Detected attack:", state.get("attack_type", "unknown"))

            # -------- LOGGING --------
            action_timeline.append({
                "episode": episode,
                "step": step,
                "action": final_action,
            })

            execution_logs.append({
                "episode": episode,
                "step": step,
                "action": final_action,
                "execution_status": exec_status,
                "target_ip": ATTACKER_IP,
            })

            # -------- ATOMIC LOG WRITE --------
            tmp_path = LOG_PATH.with_suffix(".tmp")
            with open(tmp_path, "wb") as f:
                pickle.dump(
                    {
                        "history": env.history,
                        "episode_rewards": episode_rewards + [total_reward],
                        "actions": action_timeline,
                        "execution": execution_logs,
                    },
                    f,
                )

            os.replace(tmp_path, LOG_PATH)

            time.sleep(get_speed())

        episode_rewards.append(total_reward)
        print(f"Episode {episode:03d} | Total Reward: {total_reward:.2f}")

    print("\n--- TRAINING COMPLETE ---\n")


# ---------------- MAIN ENTRY ----------------
def main(mode="run"):
    if mode == "run":
        run_training()
    elif mode == "test":
        print("Test mode not yet implemented.")
    else:
        raise ValueError(f"Unknown mode: {mode}")


if __name__ == "__main__":
    main()
