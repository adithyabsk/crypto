"""Cryptographic primitives and message handling for Dolev-Strong protocol."""

import uuid
from collections import namedtuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

# Global public key store - in a real implementation this would be distributed
public_key_store: dict[uuid.UUID, RSAPublicKey] = {}
"""Maps node_id to a public key"""

Signature = namedtuple("Signature", ["signature", "node_id"])


class SignedMessage:
    """A message with cryptographic signatures from nodes."""

    def __init__(
        self, message: str, *, signatures: tuple[Signature, ...] | None = None
    ):
        self.message = message
        self.signatures: tuple[Signature, ...] = (
            () if signatures is None else signatures
        )

    def to_bytes(self) -> bytes:
        """Convert message to bytes for signing/verification."""
        return self.message.encode("ascii")

    @staticmethod
    def sign(
        signed_message: "SignedMessage", node_id: uuid.UUID, private_key
    ) -> "SignedMessage":
        """Sign a message with a node's private key."""
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
    def _verify_signature(message: bytes, signature: Signature) -> bool:
        """Verify a single signature against a message."""
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
    def verify(signed_message: "SignedMessage") -> tuple[bool, int | None]:
        """Verify message signatures and return validity and unique signer count."""
        unique = set()
        for s in signed_message.signatures:
            if not SignedMessage._verify_signature(signed_message.to_bytes(), s):
                return False, None
            unique.add(s.node_id)
        return True, len(unique)


def generate_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a new RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def register_public_key(node_id: uuid.UUID, public_key: RSAPublicKey) -> None:
    """Register a public key for a node ID."""
    public_key_store[node_id] = public_key
