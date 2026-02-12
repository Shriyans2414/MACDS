from macds.environment.network_environment import NetworkEnvironment
import time

env = NetworkEnvironment()

print("Starting environment test...")
print("Start/stop hping3 to see changes\n")

while True:
    state, reward, done = env.step("do_nothing")
    print(
        "Attack:", env.active_attack,
        "| Packet rate:", state["packet_rate"],
        "| Reward:", reward
    )
    time.sleep(2)
