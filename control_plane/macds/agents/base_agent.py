import random

class BaseAgent:
    """
    Base Agent Interface for the Cyber Defense System.
    This agent can:
    - Observe the environment
    - Choose an action
    - Act on the environment

    NO learning, NO RL, NO neural networks.
    """

    def __init__(self, agent_id, action_space):
        """
        agent_id: string identifier (e.g., 'traffic_agent')
        action_space: list of allowed actions
        """
        self.agent_id = agent_id
        self.action_space = action_space

    # Observe the environment
    def observe(self, environment):
        """
        Fetch observable state from the environment.
        """
        state = environment.get_state()
        return state

    # Choose an action 
    def select_action(self, state):
        """
        Select an action.
        Currently random – intelligence comes later.
        """
        action = random.choice(self.action_space)
        return action

    # Act on the environment
    def act(self, environment, action):
        """
        Execute the chosen action on the environment.
        """
        # For Step 2, actions are placeholders
        # Real effects will be added later
        if action == "do_nothing":
            pass

        elif action == "raise_alert":
            print(f"[{self.agent_id}] Alert raised.")

        elif action == "block_ip":
            print(f"[{self.agent_id}] IP blocking requested.")

        elif action == "isolate_node":
            print(f"[{self.agent_id}] Node isolation requested.")
