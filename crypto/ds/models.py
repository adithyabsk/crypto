"""Data models and configuration for Dolev-Strong protocol."""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

# Type hint for message callback - purely for visualization purposes
MessageCallback = Callable[[uuid.UUID, uuid.UUID, str, int], None]


class MaliciousNodeStrategy(Enum):
    """Strategy for malicious node behavior."""

    DROP_ALL = 0  # Don't forward any messages
    SEND_HALF = 1  # Only forward to half the peers


class MaliciousStrategy(Enum):
    """Overall malicious strategy for the network."""

    NONE = 0
    SENDER_ONLY = 1
    FOLLOWER_NODES_ONLY = 2
    SENDER_FOLLOWER_COORDINATED = 3


@dataclass
class Configuration:
    """Configuration for the Dolev-Strong protocol simulation."""

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
