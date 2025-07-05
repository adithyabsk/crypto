"""Network setup strategies for different attack scenarios."""

from abc import ABC, abstractmethod

from .models import MaliciousNodeStrategy, MaliciousStrategy
from .nodes import (
    CoordinatedMaliciousNode,
    CoordinatedMaliciousSender,
    MaliciousNode,
    MaliciousSender,
    Node,
    Sender,
)


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

        return malicious_nodes + honest_nodes

    def get_description(self, malicious_count: int) -> str:
        return (
            f"Created honest sender, {malicious_count} malicious follower nodes, "
            f"and {malicious_count} honest follower nodes"
        )


class CoordinatedAttackStrategy(NetworkSetupStrategy):
    """Create a coordinated attack with malicious sender and followers."""

    def __init__(self):
        self.coordinated_nodes: set = set()
        self.sender: CoordinatedMaliciousSender | None = None

    def create_sender(self, input_msg: str) -> Node:
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
                "Coordinated attack requires at least 2 "
                "malicious nodes (sender + followers)"
            )

        nodes = []
        malicious_follower_count = malicious_count - 1  # -1 for malicious sender

        # Create coordinated malicious nodes
        for _ in range(malicious_follower_count):
            malicious_node = CoordinatedMaliciousNode()
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


def get_network_strategy(malicious_strategy: MaliciousStrategy) -> NetworkSetupStrategy:
    """Get the appropriate network setup strategy based on malicious_strategy."""
    if malicious_strategy == MaliciousStrategy.SENDER_ONLY:
        return MaliciousSenderStrategy()
    elif malicious_strategy == MaliciousStrategy.FOLLOWER_NODES_ONLY:
        return MaliciousFollowersStrategy()
    elif malicious_strategy == MaliciousStrategy.SENDER_FOLLOWER_COORDINATED:
        return CoordinatedAttackStrategy()
    else:
        return HonestNetworkStrategy()
