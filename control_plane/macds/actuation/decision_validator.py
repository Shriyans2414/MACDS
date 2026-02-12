class DecisionValidator:
    """
    Interprets and validates a received defense decision
    before any execution is attempted.
    """

    def __init__(self):
        # Allowed high-level actions
        self.allowed_actions = {
            "do_nothing",
            "raise_alert",
            "block_ip",
            "isolate_node"
        }

    def validate(self, decision_packet):
        """
        decision_packet: dict
            Expected format:
            {
                "action": <str>,
                "context": <dict or None>
            }

        Returns:
            dict with validation result
        """

        if not decision_packet or "action" not in decision_packet:
            return {
                "valid": False,
                "reason": "Missing or malformed decision"
            }

        action = decision_packet["action"]

        # Check if action is known
        if action not in self.allowed_actions:
            return {
                "valid": False,
                "reason": f"Unknown action: {action}"
            }

        # Safety policy (simulation-safe)
        # Real enforcement is intentionally blocked
        if action in {"block_ip", "isolate_node"}:
            return {
                "valid": True,
                "level": "restricted",
                "note": "Execution limited to simulation / stub"
            }

        return {
            "valid": True,
            "level": "safe",
            "note": "Non-intrusive action"
        }