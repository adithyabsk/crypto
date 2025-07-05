#!/usr/bin/env python

import logging
import uuid
from abc import ABC, abstractmethod
from collections import namedtuple
from dataclasses import dataclass
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

public_key_store: dict[uuid.UUID, RSAPublicKey] = {}
"""Maps node_id to a public key"""


Signature = namedtuple("Signature", ["signature", "node_id"])


class SignedMessage:
    def __init__(self, message, *, signatures: tuple[Signature, ...] | None = None):
        self.message = message
        self.signatures: tuple[Signature] = () if signatures is None else signatures

    def to_bytes(self):
        return self.message.encode("ascii")

    # Note: this is a static method because in the real world, nodes would be
    # doing the signing and verifying so this step could not be "cached" for
    # example. However, it makes more sense for the simulation to group this
    # code together here.
    @staticmethod
    def sign(signed_message: "SignedMessage", node_id, private_key):
        s = private_key.sign(
            signed_message.to_bytes(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return SignedMessage(
            signed_message.message,
            signatures=signed_message.signatures + (Signature(s, node_id),),
        )

    @staticmethod
    def _verify_signature(message: bytes, signature: Signature):
        public_key = public_key_store.get(signature.node_id)
        if public_key is None:
            return False
        try:
            public_key.verify(
                signature.signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def verify(signed_message: "SignedMessage"):
        unique = set()
        for s in signed_message.signatures:
            if not SignedMessage._verify_signature(signed_message.to_bytes(), s):
                return False, None
            unique.add(s.node_id)
        return True, len(unique)


class Node:
    is_malicious = False

    def __init__(self) -> None:
        self.node_id = uuid.uuid4()
        self.extracted_msg = set()
        self.inbox: list[SignedMessage] = []
        self.peers: list[Node] | None = None
        self.logger = logging.getLogger(f"Node-{str(self.node_id)[:8]}")

        # generate private key
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        public_key_store[self.node_id] = self.public_key

    def receive_msg(self, signed_message: "SignedMessage"):
        self.logger.debug(f"Received message: {signed_message.message}")
        self.inbox.append(signed_message)

    def broadcast(self, signed_message: "SignedMessage"):
        self.logger.debug(f"Broadcasting message: {signed_message.message}")
        for node in self.peers:
            # this could be done a network, but this is a simulation
            node.receive_msg(signed_message)

    def _check_peer_nodes(self):
        if self.peers is None:
            raise ValueError("peer nodes must be set before running node")

    def run(self, n_round: int):
        self.logger.debug(f"Running round {n_round}")
        self._check_peer_nodes()
        for msg in self.inbox:
            valid, n_sigs = SignedMessage.verify(msg)
            if valid and n_sigs == n_round and msg.message not in self.extracted_msg:
                self.extracted_msg.add(msg.message)
                msg = SignedMessage.sign(msg, self.node_id, self.private_key)
                self.broadcast(msg)

        # clear inbox
        self.inbox = []

    def __str__(self):
        # instead of an output function, we can just update the state of the
        # node represented as a string
        return f"Node<malicious: {self.is_malicious}, output: {self.output()}>"

    def output(self):
        if len(self.extracted_msg) == 1:
            return list(self.extracted_msg)[0]
        else:
            return 0


# TODO: the implementation here is confusing, making the code be able to use
#       broadcast is probably not worth it and should just use the default
#       setup.
class Sender(Node):
    def __init__(self, input_msg):
        super().__init__()
        self.logger = logging.getLogger(f"Sender-{str(self.node_id)[:8]}")
        self.receive_msg(SignedMessage(input_msg))

    def initial_broadcast(self, message: "SignedMessage"):
        self.logger.info(f"Initial broadcast: {message.message}")
        self.broadcast(message)
        # send message to self
        # clear the sender's inbox
        self.inbox = []
        # receive the new message
        self.receive_msg(message)

    def run(self, n_round: int):
        if n_round == 0:
            self.logger.info(f"Sender starting round {n_round}")
            self._check_peer_nodes()
            # inbox needs to be converted to a tuple so that the self referential
            # send does not cause an infinite loop
            for msg in tuple(self.inbox):
                # don't need to verify, just broadcast
                msg = SignedMessage.sign(msg, self.node_id, self.private_key)
                self.initial_broadcast(msg)
        else:
            super().run(n_round)


class MaliciousNodeStrategy(Enum):
    DROP_ALL = 0  # Don't forward any messages
    SEND_HALF = 1  # Only forward to half the peers


class MaliciousStrategy(Enum):
    NONE = 0
    SENDER_ONLY = 1
    FOLLOWER_NODES_ONLY = 2
    SENDER_FOLLOWER_COORDINATED = 3


class MaliciousSender(Node):
    is_malicious = True
    malicious_message = SignedMessage("Malicious Message")

    def __init__(self, input_msg):
        super().__init__()
        self.logger = logging.getLogger(f"MaliciousSender-{str(self.node_id)[:8]}")
        self.input_msg = SignedMessage(input_msg)

    def run(self, n_round: int):
        if n_round == 0:
            self.logger.info(f"Malicious sender starting round {n_round}")
            real_msg = SignedMessage.sign(
                self.input_msg, self.node_id, self.private_key
            )
            malicious_msg = SignedMessage.sign(
                self.malicious_message, self.node_id, self.private_key
            )

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

            # send message to self
            # clear the sender's inbox
            self.inbox = []
            # receive the new message
            self.receive_msg(malicious_msg)
        else:
            super().run(n_round)


class CoordinatedMaliciousSender(Node):
    is_malicious = True

    def __init__(self, input_msg, coordinated_nodes):
        super().__init__()
        self.logger = logging.getLogger(f"CoordMaliciousSender-{str(self.node_id)[:8]}")
        self.input_msg = SignedMessage(input_msg)
        self.fake_message_1 = SignedMessage("Coordinated Fake A")
        self.fake_message_2 = SignedMessage("Coordinated Fake B")
        self.coordinated_nodes = coordinated_nodes  # Set of malicious node IDs

    def run(self, n_round: int):
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

            # Separate honest and malicious nodes
            honest_nodes = [n for n in self.peers if not n.is_malicious]
            malicious_nodes = [n for n in self.peers if n.is_malicious]

            # Strategy: Send different conflicting messages
            # to different groups of honest nodes
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

            # Coordinate with malicious nodes - give them all conflicting messages
            # so they can amplify the confusion
            self.logger.info("Coordinating with malicious follower nodes")
            for node in malicious_nodes:
                node.receive_msg(real_msg)
                node.receive_msg(fake_msg_1)
                node.receive_msg(fake_msg_2)

            # Send to self (sender keeps one of the fake messages)
            self.inbox = []
            self.receive_msg(fake_msg_1)
        else:
            super().run(n_round)


class MaliciousNode(Node):
    is_malicious = True

    def __init__(
        self, strategy: MaliciousNodeStrategy = MaliciousNodeStrategy.SEND_HALF
    ):
        super().__init__()
        self.strategy = strategy
        self.logger = logging.getLogger(f"MaliciousNode-{str(self.node_id)[:8]}")

    def run(self, n_round: int):
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
                    # Malicious behavior: Don't forward any messages
                    self.logger.info("Malicious node dropping all messages")
                    return

                elif self.strategy == MaliciousNodeStrategy.SEND_HALF:
                    # Malicious behavior: Only forward to some nodes (Byzantine fault)
                    # This simulates network partitioning or selective message dropping
                    half_point = len(self.peers) // 2

                    self.logger.info(
                        f"Maliciously forwarding message to only {half_point} peers"
                    )
                    for node in self.peers[:half_point]:
                        node.receive_msg(msg)

                    # Don't forward to the remaining peers
                    self.logger.info(
                        "Dropping message for remaining "
                        f"{len(self.peers) - half_point} peers"
                    )
                    return

        # clear inbox
        self.inbox = []


class CoordinatedMaliciousNode(Node):
    is_malicious = True

    def __init__(self, coordinated_sender_id):
        super().__init__()
        self.coordinated_sender_id = coordinated_sender_id
        self.logger = logging.getLogger(f"CoordMaliciousNode-{str(self.node_id)[:8]}")

    def run(self, n_round: int):
        self.logger.info(f"Coordinated malicious node running round {n_round}")
        self._check_peer_nodes()

        for msg in self.inbox:
            valid, n_sigs = SignedMessage.verify(msg)
            if valid and n_sigs == n_round and msg.message not in self.extracted_msg:
                self.extracted_msg.add(msg.message)
                signed_msg = SignedMessage.sign(msg, self.node_id, self.private_key)

                # Coordination strategy: Try to maximize confusion by selectively
                # forwarding different conflicting messages to prevent consensus
                honest_peers = [p for p in self.peers if not p.is_malicious]

                if len(honest_peers) > 0:
                    # Strategic forwarding based on message content
                    if "Coordinated Fake A" in msg.message:
                        # Forward fake A to first half of honest nodes
                        half = len(honest_peers) // 2
                        self.logger.info(
                            f"Strategically forwarding Fake A to {half} honest nodes"
                        )
                        for node in honest_peers[:half]:
                            node.receive_msg(signed_msg)

                    elif "Coordinated Fake B" in msg.message:
                        # Forward fake B to second half of honest nodes
                        half = len(honest_peers) // 2
                        self.logger.info(
                            "Strategically forwarding Fake B to "
                            f"{len(honest_peers) - half} honest nodes"
                        )
                        for node in honest_peers[half:]:
                            node.receive_msg(signed_msg)

                    else:
                        # For the real message, limit its spread to create inconsistency
                        self.logger.info("Limiting spread of real message to few nodes")
                        # Only forward to a small subset to prevent it from
                        # gaining majority
                        subset_size = min(2, len(honest_peers) // 3)
                        for node in honest_peers[:subset_size]:
                            node.receive_msg(signed_msg)

                # Always forward to other malicious nodes to maintain coordination
                for peer in self.peers:
                    if peer.is_malicious and peer != self:
                        peer.receive_msg(signed_msg)

        self.inbox = []


class NetworkSetupStrategy(ABC):
    """Abstract base class for different network setup strategies."""

    @abstractmethod
    def create_sender(self, input_msg: str) -> Node:
        """Create and return the sender node."""
        pass

    @abstractmethod
    def create_nodes(
        self,
        node_count: int,
        malicious_count: int,
        malicious_node_strategy: MaliciousNodeStrategy | None,
    ) -> list[Node]:
        """Create and return the follower nodes."""
        pass

    @abstractmethod
    def get_description(self, malicious_count: int) -> str:
        """Get a description of the network setup."""
        pass


class HonestNetworkStrategy(NetworkSetupStrategy):
    """Create a network with all honest nodes."""

    def create_sender(self, input_msg: str) -> Node:
        return Sender(input_msg)

    def create_nodes(
        self,
        node_count: int,
        malicious_count: int,
        malicious_node_strategy: MaliciousNodeStrategy | None,
    ) -> list[Node]:
        return [Node() for _ in range(node_count - 1)]

    def get_description(self, malicious_count: int) -> str:
        return "Created honest sender and all honest nodes"


class MaliciousSenderStrategy(NetworkSetupStrategy):
    """Create a network with only a malicious sender."""

    def create_sender(self, input_msg: str) -> Node:
        return MaliciousSender(input_msg)

    def create_nodes(
        self,
        node_count: int,
        malicious_count: int,
        malicious_node_strategy: MaliciousNodeStrategy | None,
    ) -> list[Node]:
        return [Node() for _ in range(node_count - 1)]

    def get_description(self, malicious_count: int) -> str:
        return "Created malicious sender and honest follower nodes"


class MaliciousFollowersStrategy(NetworkSetupStrategy):
    """Create a network with honest sender and malicious followers."""

    def create_sender(self, input_msg: str) -> Node:
        return Sender(input_msg)

    def create_nodes(
        self,
        node_count: int,
        malicious_count: int,
        malicious_node_strategy: MaliciousNodeStrategy | None,
    ) -> list[Node]:
        if not malicious_count:
            raise ValueError("Malicious count must be specified for this strategy")

        # Default to SEND_HALF if no strategy specified
        node_strategy = malicious_node_strategy or MaliciousNodeStrategy.SEND_HALF

        # Create malicious follower nodes
        malicious_nodes = [MaliciousNode(node_strategy) for _ in range(malicious_count)]

        # Create remaining honest nodes
        honest_nodes = [Node() for _ in range(node_count - 1 - malicious_count)]

        # Combine all nodes
        return malicious_nodes + honest_nodes

    def get_description(self, malicious_count: int) -> str:
        return (
            f"Created honest sender, {malicious_count} malicious follower nodes, "
            f"and {malicious_count} honest follower nodes"
        )


class CoordinatedAttackStrategy(NetworkSetupStrategy):
    """Create a coordinated attack with malicious sender and followers."""

    def __init__(self):
        self.coordinated_nodes = set()
        self.sender = None

    def create_sender(self, input_msg: str) -> Node:
        # Create coordinated malicious sender
        self.sender = CoordinatedMaliciousSender(input_msg, self.coordinated_nodes)
        return self.sender

    def create_nodes(
        self,
        node_count: int,
        malicious_count: int,
        malicious_node_strategy: MaliciousNodeStrategy | None,
    ) -> list[Node]:
        if not malicious_count or malicious_count < 2:
            raise ValueError(
                "Coordinated attack requires at least "
                "2 malicious nodes (sender + followers)"
            )

        nodes = []

        # Create coordinated malicious nodes first
        malicious_follower_count = malicious_count - 1  # -1 for malicious sender

        for _ in range(malicious_follower_count):
            malicious_node = CoordinatedMaliciousNode(None)  # Will set sender ID later
            self.coordinated_nodes.add(malicious_node.node_id)
            nodes.append(malicious_node)

        # Update malicious nodes with sender ID after sender is created
        if self.sender:
            for node in nodes:
                if isinstance(node, CoordinatedMaliciousNode):
                    node.coordinated_sender_id = self.sender.node_id

        # Create remaining honest nodes
        honest_count = node_count - 1 - malicious_follower_count
        honest_nodes = [Node() for _ in range(honest_count)]
        nodes.extend(honest_nodes)

        return nodes

    def get_description(self, malicious_count: int) -> str:
        malicious_follower_count = malicious_count - 1
        honest_count = malicious_count - 1 - malicious_follower_count
        return (
            f"Created coordinated attack: 1 malicious sender + "
            f"{malicious_follower_count} coordinated malicious followers + "
            f"{honest_count} honest nodes"
        )


@dataclass
class Configuration:
    node_count: int
    input_msg: str
    malicious_strategy: MaliciousStrategy = MaliciousStrategy.NONE
    malicious_node_strategy: MaliciousNodeStrategy | None = None
    n_rounds: int | None = None
    malicious_count: int | None = None

    def __post_init__(self):
        # Default malicious_count to 1 for SENDER_ONLY strategy
        if self.malicious_strategy == MaliciousStrategy.SENDER_ONLY:
            self.malicious_count = 1

        # Validate configuration
        if self.malicious_count is None:
            self.malicious_count = 0

        if self.malicious_count + 1 >= self.node_count:
            raise ValueError(
                "The number of malicious nodes (including the sender) cannot "
                "exceed the number of nodes - 1."
            )

        if self.n_rounds is None:
            self.n_rounds = self.malicious_count + 1

        if self.n_rounds < self.malicious_count + 1:
            raise ValueError(
                "The number of rounds must be greater than or equal to the number "
                "of malicious nodes + 1 for the protocol to converge."
            )


class DolevStrong:
    def __init__(self, config: Configuration):
        self.logger = logging.getLogger("DolevStrong")
        self.config = config

        # Set up strategy based on malicious_strategy
        strategy = self._get_network_strategy(config.malicious_strategy)

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

        self.logger.info(
            f"Configuration: {config.node_count} nodes, "
            f"{config.malicious_count} malicious, "
            f"{config.n_rounds} rounds"
        )

    def _get_network_strategy(
        self, malicious_strategy: MaliciousStrategy
    ) -> NetworkSetupStrategy:
        """Get the appropriate network setup strategy based on malicious_strategy."""
        if malicious_strategy == MaliciousStrategy.SENDER_ONLY:
            return MaliciousSenderStrategy()
        elif malicious_strategy == MaliciousStrategy.FOLLOWER_NODES_ONLY:
            return MaliciousFollowersStrategy()
        elif malicious_strategy == MaliciousStrategy.SENDER_FOLLOWER_COORDINATED:
            return CoordinatedAttackStrategy()
        else:
            return HonestNetworkStrategy()

    @property
    def all_nodes(self):
        return [self.sender] + self.nodes

    def run(self):
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


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    config = Configuration(
        node_count=5,
        input_msg="Hello World!",
        malicious_strategy=MaliciousStrategy.SENDER_ONLY,
    )
    ds = DolevStrong(config)
    ds.run()
