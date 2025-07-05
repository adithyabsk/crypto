"""Node implementations for Dolev-Strong protocol."""

import logging
import uuid

from .models import MaliciousNodeStrategy, MessageCallback
from .primitives import SignedMessage, generate_keypair, register_public_key


class Node:
    """Base honest node implementation."""

    is_malicious = False

    def __init__(self) -> None:
        self.node_id = uuid.uuid4()
        self.extracted_msg: set[str] = set()
        self.inbox: list[SignedMessage] = []
        self.peers: list[Node] | None = None
        self.logger = logging.getLogger(f"Node-{str(self.node_id)[:8]}")

        # Visualization callback - NOT required for the actual algorithm
        self._message_callback: MessageCallback | None = None
        self._current_round: int = 0

        # Generate cryptographic keys
        self.private_key, self.public_key = generate_keypair()
        register_public_key(self.node_id, self.public_key)

    def set_message_callback(self, callback: MessageCallback | None) -> None:
        """Set callback for message visualization - NOT part of the actual algorithm."""
        self._message_callback = callback

    def set_current_round(self, round_num: int) -> None:
        """Set current round for visualization - NOT part of the actual algorithm."""
        self._current_round = round_num

    def receive_msg(self, signed_message: SignedMessage) -> None:
        """Receive a message from another node."""
        self.logger.debug(f"Received message: {signed_message.message}")
        self.inbox.append(signed_message)

    def broadcast(self, signed_message: SignedMessage) -> None:
        """Broadcast a message to all peer nodes."""
        self.logger.debug(f"Broadcasting message: {signed_message.message}")

        # Notify visualization callback if present - NOT part of actual algorithm
        if self._message_callback and self.peers:
            for peer in self.peers:
                self._message_callback(
                    self.node_id,
                    peer.node_id,
                    signed_message.message,
                    self._current_round,
                )

        # Actual algorithm: broadcast to all peers
        if self.peers:
            for node in self.peers:
                node.receive_msg(signed_message)

    def _check_peer_nodes(self) -> None:
        """Validate that peer nodes have been set."""
        if self.peers is None:
            raise ValueError("peer nodes must be set before running node")

    def run(self, n_round: int) -> None:
        """Run the Dolev-Strong protocol for a given round."""
        self.logger.debug(f"Running round {n_round}")
        self._current_round = n_round
        self._check_peer_nodes()

        for msg in self.inbox:
            valid, n_sigs = SignedMessage.verify(msg)
            if valid and n_sigs == n_round and msg.message not in self.extracted_msg:
                self.extracted_msg.add(msg.message)
                msg = SignedMessage.sign(msg, self.node_id, self.private_key)
                self.broadcast(msg)

        # Clear inbox after processing
        self.inbox = []

    def output(self) -> str | int:
        """Get the node's output (consensus value)."""
        if len(self.extracted_msg) == 1:
            return list(self.extracted_msg)[0]
        else:
            return 0

    def __str__(self) -> str:
        return f"Node<malicious: {self.is_malicious}, output: {self.output()}>"


class Sender(Node):
    """Honest sender node that initiates the protocol."""

    def __init__(self, input_msg: str):
        super().__init__()
        self.logger = logging.getLogger(f"Sender-{str(self.node_id)[:8]}")
        self.receive_msg(SignedMessage(input_msg))

    def initial_broadcast(self, message: SignedMessage) -> None:
        """Perform the initial broadcast in round 0."""
        self.logger.info(f"Initial broadcast: {message.message}")
        self.broadcast(message)
        # Send message to self and clear/reset inbox
        self.inbox = []
        self.receive_msg(message)

    def run(self, n_round: int) -> None:
        """Run sender logic for the given round."""
        if n_round == 0:
            self.logger.info(f"Sender starting round {n_round}")
            self._current_round = n_round
            self._check_peer_nodes()

            # Process initial messages
            for msg in tuple(self.inbox):
                msg = SignedMessage.sign(msg, self.node_id, self.private_key)
                self.initial_broadcast(msg)
        else:
            super().run(n_round)


class MaliciousSender(Node):
    """Malicious sender that sends different messages to different nodes."""

    is_malicious = True
    malicious_message = SignedMessage("Malicious Message")

    def __init__(self, input_msg: str):
        super().__init__()
        self.logger = logging.getLogger(f"MaliciousSender-{str(self.node_id)[:8]}")
        self.input_msg = SignedMessage(input_msg)

    def run(self, n_round: int) -> None:
        """Run malicious sender logic."""
        if n_round == 0:
            self.logger.info(f"Malicious sender starting round {n_round}")

            # Sign both real and malicious messages
            real_msg = SignedMessage.sign(
                self.input_msg, self.node_id, self.private_key
            )
            malicious_msg = SignedMessage.sign(
                self.malicious_message, self.node_id, self.private_key
            )

            # Send different messages to different halves of the network
            if self.peers:
                half_point = len(self.peers) // 2

                self.logger.info(f"Sending real message to first {half_point} nodes")
                for node in self.peers[:half_point]:
                    node.receive_msg(real_msg)

                self.logger.info(
                    "Sending malicious message to remaining "
                    f"{len(self.peers) - half_point} nodes"
                )
                for node in self.peers[half_point:]:
                    node.receive_msg(malicious_msg)

            # Send malicious message to self
            self.inbox = []
            self.receive_msg(malicious_msg)
        else:
            super().run(n_round)


class MaliciousNode(Node):
    """Malicious follower node with configurable attack strategy."""

    is_malicious = True

    def __init__(
        self, strategy: MaliciousNodeStrategy = MaliciousNodeStrategy.SEND_HALF
    ):
        super().__init__()
        self.strategy = strategy
        self.logger = logging.getLogger(f"MaliciousNode-{str(self.node_id)[:8]}")

    def run(self, n_round: int) -> None:
        """Run malicious node logic based on strategy."""
        self.logger.info(
            f"Malicious node running round {n_round} with strategy {self.strategy.name}"
        )
        self._check_peer_nodes()

        for msg in self.inbox:
            valid, n_sigs = SignedMessage.verify(msg)
            if valid and n_sigs == n_round and msg.message not in self.extracted_msg:
                self.extracted_msg.add(msg.message)
                msg = SignedMessage.sign(msg, self.node_id, self.private_key)

                if self.strategy == MaliciousNodeStrategy.DROP_ALL:
                    self.logger.info("Malicious node dropping all messages")
                    continue

                elif self.strategy == MaliciousNodeStrategy.SEND_HALF:
                    if self.peers:
                        half_point = len(self.peers) // 2
                        self.logger.info(
                            f"Maliciously forwarding message to only {half_point} peers"
                        )
                        for node in self.peers[:half_point]:
                            node.receive_msg(msg)
                        self.logger.info(
                            "Dropping message for remaining "
                            f"{len(self.peers) - half_point} peers"
                        )

        self.inbox = []


class CoordinatedMaliciousSender(Node):
    """Coordinated malicious sender that works with malicious followers."""

    is_malicious = True

    def __init__(self, input_msg: str, coordinated_nodes: set[uuid.UUID]):
        super().__init__()
        self.logger = logging.getLogger(f"CoordMaliciousSender-{str(self.node_id)[:8]}")
        self.input_msg = SignedMessage(input_msg)
        self.fake_message_1 = SignedMessage("Coordinated Fake A")
        self.fake_message_2 = SignedMessage("Coordinated Fake B")
        self.coordinated_nodes = coordinated_nodes

    def run(self, n_round: int) -> None:
        """Run coordinated malicious sender logic."""
        if n_round == 0:
            self.logger.info("Coordinated malicious sender starting attack")

            # Sign all messages
            real_msg = SignedMessage.sign(
                self.input_msg, self.node_id, self.private_key
            )
            fake_msg_1 = SignedMessage.sign(
                self.fake_message_1, self.node_id, self.private_key
            )
            fake_msg_2 = SignedMessage.sign(
                self.fake_message_2, self.node_id, self.private_key
            )

            if self.peers:
                # Separate honest and malicious nodes
                honest_nodes = [n for n in self.peers if not n.is_malicious]
                malicious_nodes = [n for n in self.peers if n.is_malicious]

                # Send different conflicting messages to different groups
                third = max(1, len(honest_nodes) // 3)

                self.logger.info(f"Sending real message to {third} honest nodes")
                for node in honest_nodes[:third]:
                    node.receive_msg(real_msg)

                self.logger.info(f"Sending fake message A to {third} honest nodes")
                for node in honest_nodes[third : 2 * third]:
                    node.receive_msg(fake_msg_1)

                self.logger.info(
                    "Sending fake message B to remaining "
                    f"{len(honest_nodes) - 2 * third} honest nodes"
                )
                for node in honest_nodes[2 * third :]:
                    node.receive_msg(fake_msg_2)

                # Coordinate with malicious nodes
                self.logger.info("Coordinating with malicious follower nodes")
                for node in malicious_nodes:
                    node.receive_msg(real_msg)
                    node.receive_msg(fake_msg_1)
                    node.receive_msg(fake_msg_2)

            # Send to self
            self.inbox = []
            self.receive_msg(fake_msg_1)
        else:
            super().run(n_round)


class CoordinatedMaliciousNode(Node):
    """Coordinated malicious follower node."""

    is_malicious = True

    def __init__(self, coordinated_sender_id: uuid.UUID | None = None):
        super().__init__()
        self.coordinated_sender_id = coordinated_sender_id
        self.logger = logging.getLogger(f"CoordMaliciousNode-{str(self.node_id)[:8]}")

    def run(self, n_round: int) -> None:
        """Run coordinated malicious follower logic."""
        self.logger.info(f"Coordinated malicious node running round {n_round}")
        self._check_peer_nodes()

        for msg in self.inbox:
            valid, n_sigs = SignedMessage.verify(msg)
            if valid and n_sigs == n_round and msg.message not in self.extracted_msg:
                self.extracted_msg.add(msg.message)
                signed_msg = SignedMessage.sign(msg, self.node_id, self.private_key)

                if self.peers:
                    honest_peers = [p for p in self.peers if not p.is_malicious]

                    if len(honest_peers) > 0:
                        # Strategic forwarding based on message content
                        if "Coordinated Fake A" in msg.message:
                            half = len(honest_peers) // 2
                            self.logger.info(
                                "Strategically forwarding Fake A to "
                                f"{half} honest nodes"
                            )
                            for node in honest_peers[:half]:
                                node.receive_msg(signed_msg)

                        elif "Coordinated Fake B" in msg.message:
                            half = len(honest_peers) // 2
                            self.logger.info(
                                "Strategically forwarding Fake B to "
                                f"{len(honest_peers) - half} honest nodes"
                            )
                            for node in honest_peers[half:]:
                                node.receive_msg(signed_msg)

                        else:
                            # Limit spread of real message
                            self.logger.info(
                                "Limiting spread of real message to few nodes"
                            )
                            subset_size = min(2, len(honest_peers) // 3)
                            for node in honest_peers[:subset_size]:
                                node.receive_msg(signed_msg)

                    # Always forward to other malicious nodes
                    for peer in self.peers:
                        if peer.is_malicious and peer != self:
                            peer.receive_msg(signed_msg)

        self.inbox = []
