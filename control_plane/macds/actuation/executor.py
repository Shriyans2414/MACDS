class ActionExecutor:
    """
    Executes or safely simulates the system-level
    action plan produced in Step 3.
    """

    def execute(self, action_plan):
        """
        action_plan: dict
            Output from DecisionMapper.map()

        Returns:
            dict describing execution outcome
        """

        if not action_plan.get("executable", False):
            return {
                "executed": False,
                "reason": action_plan.get("reason", "Not executable")
            }

        system_action = action_plan.get("system_action")
        target = action_plan.get("target", None)

        # -------- Simulated execution --------
        if system_action == "noop":
            result = "No operation performed"

        elif system_action == "alert":
            result = "Alert triggered for monitoring team"

        elif system_action == "firewall_block":
            result = f"Simulated firewall block for IP {target}"

        elif system_action == "host_isolation":
            result = f"Simulated isolation for node {target}"

        else:
            return {
                "executed": False,
                "reason": "Unknown system action"
            }

        # Execution result (safe simulation)
        return {
            "executed": True,
            "system_action": system_action,
            "target": target,
            "result": result
        }
