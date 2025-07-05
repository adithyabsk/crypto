# Dolev-Strong Protocol Implementation

This repository contains a complete implementation of the Dolev-Strong consensus protocol with interactive visualization capabilities.

## Overview

The Dolev-Strong protocol is a Byzantine fault-tolerant consensus algorithm that allows a network of nodes to reach agreement on a value, even when some nodes are malicious. It guarantees that all honest nodes will either agree on the same value or output a default value (0), regardless of Byzantine failures.

### Key Properties

- **Byzantine Fault Tolerance**: Tolerates up to `f` malicious nodes in a network of `n` nodes
- **Deterministic**: Always produces the same result for the same inputs
- **Signature-based**: Uses cryptographic signatures to ensure message authenticity
- **Round-based**: Operates in `f + 1` rounds where `f` is the number of malicious nodes

### How It Works

```mermaid
graph TD
    A[Sender broadcasts signed message] --> B[Round 1: Nodes verify and re-sign]
    B --> C[Round 2: Nodes forward messages with 2 signatures]
    C --> D[Round f+1: Messages with f+1 signatures]
    D --> E[Decision: Single message → output it<br/>Multiple messages → output 0]
```

## Protocol Algorithm

1. **Initialization**: Each node generates a key pair and registers their public key
2. **Round 0**: Sender signs and broadcasts their input message
3. **Round k (1 ≤ k ≤ f+1)**: 
   - Each node processes messages with exactly k signatures
   - Verifies all signatures are valid and unique
   - Adds their own signature and broadcasts to all peers
4. **Decision**: After f+1 rounds, each node outputs:
   - The unique message if only one message was received
   - 0 if multiple different messages were received

## Protocol Flow Example

```mermaid
sequenceDiagram
    participant S as Sender
    participant N1 as Node 1
    participant N2 as Node 2
    participant N3 as Node 3
    
    Note over S,N3: Round 0
    S->>N1: sign(msg, S)
    S->>N2: sign(msg, S)
    S->>N3: sign(msg, S)
    
    Note over S,N3: Round 1
    N1->>N2: sign(msg, S, N1)
    N1->>N3: sign(msg, S, N1)
    N2->>N1: sign(msg, S, N2)
    N2->>N3: sign(msg, S, N2)
    N3->>N1: sign(msg, S, N3)
    N3->>N2: sign(msg, S, N3)
    
    Note over S,N3: Decision Phase
    Note over N1: Has 1 unique message → output msg
    Note over N2: Has 1 unique message → output msg
    Note over N3: Has 1 unique message → output msg
```

## Implementation Architecture

### Core Components

```mermaid
graph LR
    A[Configuration] --> B[DolevStrong]
    B --> C[NetworkStrategy]
    B --> D[Nodes]
    D --> E[Cryptographic Primitives]
    B --> F[Visualizer]
    
    subgraph "Node Types"
        G[Sender]
        H[Node]
        I[MaliciousSender]
        J[MaliciousNode]
    end
    
    D --> G
    D --> H
    D --> I
    D --> J
```

### File Structure

- **`models.py`**: Configuration classes and enums for different attack strategies
- **`primitives.py`**: Cryptographic operations (RSA signatures, verification)
- **`nodes.py`**: Node implementations (honest, malicious, coordinated attacks)
- **`strategy.py`**: Network setup strategies for different scenarios
- **`protocol.py`**: Main protocol orchestration
- **`vizualize.py`**: Interactive visualization with matplotlib

### Attack Scenarios

The implementation supports several malicious strategies:

```mermaid
graph TB
    A[Malicious Strategies] --> B[SENDER_ONLY]
    A --> C[FOLLOWER_NODES_ONLY]
    A --> D[SENDER_FOLLOWER_COORDINATED]
    A --> E[NONE - All Honest]
    
    B --> F[Sends different messages to different nodes]
    C --> G[Malicious followers drop or selectively forward]
    D --> H[Coordinated attack between sender and followers]
    E --> I[Baseline honest behavior]
```

### Visualization Features

The interactive visualizer provides:

- **Node representation**: Color-coded nodes (blue=honest sender, red=malicious sender, green=honest node, orange=malicious node)
- **Message flow**: Animated arrows showing message passing between nodes
- **Round control**: Slider to navigate through protocol rounds
- **Play/Pause**: Automatic animation of the protocol execution
- **Message tracking**: Display of messages received by each node
