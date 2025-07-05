"""Main Dolev-Strong protocol implementation."""

import logging
import uuid

from .models import Configuration
from .nodes import Node
from .strategy import get_network_strategy


class DolevStrong:
    """Main Dolev-Strong protocol implementation."""

    def __init__(self, config: Configuration):
        self.logger = logging.getLogger("DolevStrong")
        self.config = config

        # Message log for visualization - NOT part of the actual algorithm
        self.message_log: list[dict] = []

        # Set up strategy based on malicious_strategy
        strategy = get_network_strategy(config.malicious_strategy)

        # Create sender and nodes using strategy
        self.sender = strategy.create_sender(config.input_msg)
        self.nodes = strategy.create_nodes(
            config.node_count, config.malicious_count, config.malicious_node_strategy
        )

        # Log the network setup
        self.logger.info(strategy.get_description(config.malicious_count))

        # Set node peers
        self.sender.peers = self.nodes
        for i, n in enumerate(self.nodes):
            n.peers = [self.sender] + self.nodes[:i] + self.nodes[i + 1 :]

        # Set up visualization callbacks - NOT part of the actual algorithm
        self._setup_visualization_callbacks()

        self.logger.info(
            f"Configuration: {config.node_count} nodes, "
            f"{config.malicious_count} malicious, "
            f"{config.n_rounds} rounds"
        )

    def _setup_visualization_callbacks(self) -> None:
        """Set up message callbacks for visualization - NOT part of actual algorithm."""
        for node in self.all_nodes:
            node.set_message_callback(self._log_message_for_visualization)

    def _log_message_for_visualization(
        self, sender_id: uuid.UUID, receiver_id: uuid.UUID, message: str, round_num: int
    ) -> None:
        """Log a message for visualization - NOT part of the actual algorithm."""
        self.message_log.append(
            {
                "sender": sender_id,
                "receiver": receiver_id,
                "message": message,
                "round": round_num,
            }
        )

    def get_message_log(self) -> list[dict]:
        """Get the message log for visualization - NOT part of the actual algorithm."""
        return self.message_log.copy()

    @property
    def all_nodes(self) -> list[Node]:
        """Get all nodes in the network (sender + followers)."""
        return [self.sender] + self.nodes

    def run(self) -> None:
        """Run the complete Dolev-Strong protocol simulation."""
        self.logger.info("Starting Dolev-Strong protocol simulation")

        for r in range(self.config.n_rounds + 1):
            self.logger.info(f"Starting round {r}")
            if r == 0:
                self.sender.run(r)
            else:
                for n in self.all_nodes:
                    n.run(r)
            self.logger.info(f"Completed round {r}")

        # Output results
        self.logger.info("Final results:")
        for i, n in enumerate(self.all_nodes):
            self.logger.info(f"Node {i}: {n}")
