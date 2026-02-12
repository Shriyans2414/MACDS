class DecisionMapper:
    """
    Maps a validated AI decision into a concrete
    system-level action plan (execution blueprint).
    """

    def map(self, decision_packet, validation_result):
        """
        decision_packet: dict
            {
                "action": <str>,
                "context": <dict or None>
            }

        validation_result: dict
            Output from DecisionValidator.validate()

        Returns:
            dict representing a system-level action plan
        """

        if not validation_result.get("valid", False):
            return {
                "executable": False,
                "reason": "Decision not valid"
            }

        action = decision_packet["action"]
        context = decision_packet.get("context", {})

        # Default mapping structure
        action_plan = {
            "executable": True,
            "original_action": action,
            "system_action": None,
            "target": None,
            "scope": None,
            "context": context
        }

        # -------- Mapping rules --------
        if action == "do_nothing":
            action_plan.update({
                "system_action": "noop",
                "scope": "none"
            })

        elif action == "raise_alert":
            action_plan.update({
                "system_action": "alert",
                "scope": "monitoring"
            })

        elif action == "block_ip":
            action_plan.update({
                "system_action": "firewall_block",
                "target": context.get("ip", "UNKNOWN"),
                "scope": "network"
            })

        elif action == "isolate_node":
            action_plan.update({
                "system_action": "host_isolation",
                "target": context.get("node", "UNKNOWN"),
                "scope": "endpoint"
            })

        else:
            return {
                "executable": False,
                "reason": "No mapping rule defined"
            }

        return action_plan
