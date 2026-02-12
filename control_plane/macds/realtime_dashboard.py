import streamlit as st
import pickle
import time
import os
import pandas as pd

# ---------------- PATHS ----------------
LOG_PATH = "analysis/run_logs.pkl"
CONTROL_PATH = "analysis/training_control.pkl"
SPEED_PATH = "analysis/training_speed.pkl"

os.makedirs("analysis", exist_ok=True)

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="MACDS | Cyber Defense Control Center",
    layout="wide"
)

# ---------------- HEADER ----------------
st.markdown(
    """
    <h1 style='text-align:center;'>🛡️ MACDS — Cyber Defense Control Center</h1>
    <p style='text-align:center; color:gray;'>
    Real-Time Detection • Multi-Agent Decisions • Autonomous Enforcement
    </p>
    """,
    unsafe_allow_html=True
)

# ---------------- SIDEBAR ----------------
st.sidebar.markdown("## ⚙️ System Control")

training_speed = st.sidebar.slider(
    "⏱️ System Step Delay (seconds)",
    0.05, 1.0, 0.2, 0.05
)

st.sidebar.markdown("---")
col1, col2 = st.sidebar.columns(2)
pause_btn = col1.button("⏸ Pause System")
resume_btn = col2.button("▶ Resume System")

with open(SPEED_PATH, "wb") as f:
    pickle.dump(training_speed, f)

if pause_btn:
    with open(CONTROL_PATH, "wb") as f:
        pickle.dump(True, f)

if resume_btn:
    with open(CONTROL_PATH, "wb") as f:
        pickle.dump(False, f)

# ---------------- MAIN PLACEHOLDER ----------------
container = st.empty()

# ---------------- LIVE LOOP ----------------
while True:
    try:
        if not os.path.exists(LOG_PATH):
            time.sleep(0.3)
            continue

        with open(LOG_PATH, "rb") as f:
            data = pickle.load(f)

    except Exception:
        time.sleep(0.3)
        continue

    history = pd.DataFrame(data.get("history", {}))
    actions = pd.DataFrame(data.get("actions", []))
    execution = pd.DataFrame(data.get("execution", []))
    rewards = data.get("episode_rewards", [])

    with container.container():

        # ---------------- SYSTEM STATUS ----------------
        st.markdown("## 📊 Live System Status")

        if not history.empty:
            last_attack = history["attack"].iloc[-1] or "none"

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("📦 Packet Rate", int(history["packet_rate"].iloc[-1]))
            c2.metric("🖥️ CPU Usage (%)", round(history["cpu_usage"].iloc[-1], 2))
            c3.metric("🌐 Bandwidth (%)", round(history["bandwidth_usage"].iloc[-1], 2))
            c4.metric("🚨 Detected Attack", last_attack.upper())
        else:
            st.info("Waiting for system data...")

        st.markdown("---")

        # ---------------- NETWORK TELEMETRY ----------------
        st.markdown("## 📈 Network Telemetry")

        if not history.empty:
            st.line_chart(
                history[["packet_rate", "cpu_usage", "bandwidth_usage"]],
                height=300
            )
        else:
            st.info("No telemetry yet.")

        st.markdown("---")

        # ---------------- LEARNING PERFORMANCE ----------------
        st.markdown("## 🧠 Learning Performance")

        if rewards:
            st.line_chart(rewards, height=220)
        else:
            st.info("Learning data not available yet.")

        st.markdown("---")

        # ---------------- AGENT DECISIONS ----------------
        st.markdown("## 🤖 Agent Decisions")

        if not actions.empty:
            st.bar_chart(actions["action"].value_counts())
        else:
            st.info("No agent actions yet.")

        st.markdown("---")

        # ---------------- EXECUTION ENGINE ----------------
        st.markdown("## ⚙️ Enforcement Engine (Real Actions)")

        if not execution.empty:
            st.dataframe(
                execution.tail(15)[
                    ["episode", "step", "action", "execution_status", "target_ip"]
                ],
                width="stretch"
            )
        else:
            st.info("No enforcement actions logged.")

        st.markdown("---")

        # ---------------- FOOTER ----------------
        st.caption(
            "MACDS • Multi-Agent Cyber Defense System • Docker-based Autonomous Security"
        )

    time.sleep(0.5)
