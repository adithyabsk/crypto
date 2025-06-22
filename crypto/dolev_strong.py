#!/usr/bin/env python

import logging
import uuid
from collections import namedtuple
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


class MaliciousStrategy(Enum):
    NONE = 0
    SENDER_ONLY = 1
    FOLLOWER_NODES_ONLY = 2  # Not implemented
    SENDER_FOLLOWER_COORDINATED = 3  # Not implemented


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


class MaliciousNode(Node):
    is_malicious = True
    malicious_message = SignedMessage("Malicious Message")

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(f"MaliciousNode-{str(self.node_id)[:8]}")

    def run(self, n_round: int):
        self.logger.info(f"Malicious node running round {n_round}")
        self._check_peer_nodes()
        for msg in self.inbox:
            valid, n_sigs = SignedMessage.verify(msg)
            if valid and n_sigs == n_round and msg.message not in self.extracted_msg:
                self.extracted_msg.add(msg.message)
                msg = SignedMessage.sign(msg, self.node_id, self.private_key)
                self.broadcast(msg)


class DolevStrong:
    def __init__(
        self,
        node_count: int,
        input_msg: str,
        *,
        malicious_count: int | None = None,
        n_rounds: int | None = None,
        malicious_strategy: MaliciousStrategy | None = None,
    ):
        self.logger = logging.getLogger("DolevStrong")

        # set up nodes
        if malicious_strategy == MaliciousStrategy.SENDER_ONLY:
            self.sender = MaliciousSender(input_msg)
            self.logger.info("Created malicious sender")
        else:
            self.sender = Sender(input_msg)
            self.logger.info("Created honest sender")

        self.nodes = [Node() for _ in range(node_count - 1)]
        self.logger.info(f"Created {len(self.nodes)} additional nodes")

        # set node peers
        self.sender.peers = self.nodes
        for i, n in enumerate(self.nodes):
            n.peers = [self.sender] + self.nodes[:i] + self.nodes[i + 1 :]

        if malicious_strategy and malicious_count is None:
            raise ValueError(
                "If a malicious strategy is specified, the number of malicious "
                "nodes must also be specified"
            )

        self.malicious_count = 0 if malicious_count is None else malicious_count
        self.n_rounds = self.malicious_count + 1 if n_rounds is None else n_rounds
        self.malicious_strategy = (
            MaliciousStrategy.NONE if malicious_strategy is None else malicious_strategy
        )

        self.logger.info(
            f"Configuration: {node_count} nodes, "
            f"{self.malicious_count} malicious, "
            f"{self.n_rounds} rounds"
        )

        if (self.malicious_count + 1) >= node_count:
            raise ValueError(
                "The number of malicious nodes (including the sender) cannot "
                "exceed the number of nodes-1"
            )

        if self.n_rounds < (self.malicious_count + 1):
            raise ValueError(
                "In order for Dolev-Strong to converge, the number of rounds"
                "must be greater than or equal to the number of malicious "
                "nodes + 1"
            )

    @property
    def all_nodes(self):
        return [self.sender] + self.nodes

    def run(self):
        self.logger.info("Starting Dolev-Strong protocol simulation")
        for r in range(self.n_rounds + 1):
            self.logger.info(f"Starting round {r}")
            if r == 0:
                self.sender.run(r)
            else:
                for n in self.all_nodes:
                    n.run(r)
            self.logger.info(f"Completed round {r}")

        # output
        self.logger.info("Final results:")
        for i, n in enumerate(self.all_nodes):
            self.logger.info(f"Node {i}: {n}")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    in_str = "Hello World!"
    ds = DolevStrong(5, in_str, malicious_strategy=MaliciousStrategy.SENDER_ONLY)
    ds.run()
