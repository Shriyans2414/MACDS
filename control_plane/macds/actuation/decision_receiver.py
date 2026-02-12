class DecisionReceiver:
    """
    Receives the final defense decision from Layer 1.
    No execution happens here.
    """

    def __init__(self):
        self.last_decision = None

    def receive(self, decision, context=None):
        """
        Receive decision from Layer 1.

        decision: str
            Example: 'do_nothing', 'raise_alert', 'block_ip', 'isolate_node'

        context: dict (optional)
            Additional info such as IP, node, severity
        """
        self.last_decision = {
            "action": decision,
            "context": context
        }

        return self.last_decision
