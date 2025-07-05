"""Dolev Strong protocol functional tests."""


def test_dolev_all_honest():
    """Make sure protocol adheres to validity principle."""
    from crypto.ds import Configuration, DolevStrong

    config = Configuration(
        node_count=5,
        input_msg="Hello World!",
        malicious_strategy=None,  # All nodes are honest
    )
    ds = DolevStrong(config)
    ds.run()

    # Check that all nodes output the correct message
    for node in ds.all_nodes:
        assert node.output() == config.input_msg


def test_dolev_malicious_sender():
    """Make sure protocol adheres to consistency principle."""
    from crypto.ds import Configuration, DolevStrong, MaliciousStrategy

    config = Configuration(
        node_count=5,
        input_msg="Hello World!",
        malicious_strategy=MaliciousStrategy.SENDER_ONLY,  # Malicious sender
    )
    ds = DolevStrong(config)
    ds.run()

    # Check that honest nodes all output 0 (no consensus)
    for node in ds.nodes:  # Only check honest nodes (not the malicious sender)
        assert node.output() == 0


def test_dolev_malicious_followers_drop_all():
    """Test protocol with malicious follower nodes that drop all messages."""
    from crypto.ds import (
        Configuration,
        DolevStrong,
        MaliciousNodeStrategy,
        MaliciousStrategy,
    )

    config = Configuration(
        node_count=6,
        input_msg="Hello World!",
        malicious_count=2,
        malicious_strategy=MaliciousStrategy.FOLLOWER_NODES_ONLY,
        malicious_node_strategy=MaliciousNodeStrategy.DROP_ALL,
    )
    ds = DolevStrong(config)
    ds.run()

    # Even with nodes that drop all messages, honest sender should ensure consensus
    for node in ds.all_nodes:
        assert node.output() == config.input_msg


def test_dolev_malicious_followers_send_half():
    """Malicious follower nodes that only send to half their peers."""
    from crypto.ds import (
        Configuration,
        DolevStrong,
        MaliciousNodeStrategy,
        MaliciousStrategy,
    )

    config = Configuration(
        node_count=6,
        input_msg="Hello World!",
        malicious_count=2,
        malicious_strategy=MaliciousStrategy.FOLLOWER_NODES_ONLY,
        malicious_node_strategy=MaliciousNodeStrategy.SEND_HALF,
    )
    ds = DolevStrong(config)
    ds.run()

    # With honest sender, all nodes should agree on sender's message
    for node in ds.all_nodes:
        assert node.output() == config.input_msg


def test_dolev_extreme_malicious_followers():
    """Test with only one honest node (plus honest sender)."""
    from crypto.ds import Configuration, DolevStrong, MaliciousStrategy

    config = Configuration(
        node_count=5,  # 1 sender + 4 followers
        input_msg="Hello World!",
        malicious_count=3,  # 3 out of 4 followers are malicious
        malicious_strategy=MaliciousStrategy.FOLLOWER_NODES_ONLY,
    )
    ds = DolevStrong(config)
    ds.run()

    # Even with only 1 honest follower, if sender is honest,
    # all nodes should agree on sender's message
    for node in ds.all_nodes:
        assert node.output() == config.input_msg


def test_dolev_coordinated_attack():
    """Test coordinated attack between malicious sender and malicious followers."""
    from crypto.ds import Configuration, DolevStrong, MaliciousStrategy

    config = Configuration(
        node_count=8,  # 1 sender + 7 followers
        input_msg="Hello World!",
        malicious_count=4,  # 1 malicious sender + 3 malicious followers
        malicious_strategy=MaliciousStrategy.SENDER_FOLLOWER_COORDINATED,
    )
    ds = DolevStrong(config)
    ds.run()

    # Even with coordinated attack, Dolev-Strong should ensure that
    # honest nodes either all agree on the same value or all output default (0)
    honest_outputs = [node.output() for node in ds.all_nodes if not node.is_malicious]

    # All honest nodes should have the same output (Agreement property)
    assert len(set(honest_outputs)) == 1, f"Honest nodes disagreed: {honest_outputs}"

    # The output should be either 0 (no consensus due to conflicting messages)
    # or one of the valid messages (if protocol achieved consensus despite attack)
    honest_output = honest_outputs[0]
    valid_outputs = {0, config.input_msg, "Coordinated Fake A", "Coordinated Fake B"}
    assert honest_output in valid_outputs, f"Unexpected output: {honest_output}"


def test_dolev_coordinated_attack_minimal():
    """Test coordinated attack with minimal configuration (exactly at threshold)."""
    from crypto.ds import Configuration, DolevStrong, MaliciousStrategy

    config = Configuration(
        node_count=4,  # 1 sender + 3 followers
        input_msg="Hello World!",
        malicious_count=2,  # 1 malicious sender + 1 malicious follower
        malicious_strategy=MaliciousStrategy.SENDER_FOLLOWER_COORDINATED,
    )
    ds = DolevStrong(config)
    ds.run()

    # Check that honest nodes maintain agreement
    honest_outputs = [node.output() for node in ds.all_nodes if not node.is_malicious]
    assert len(set(honest_outputs)) == 1, f"Honest nodes disagreed: {honest_outputs}"

    # With fewer malicious nodes, protocol might still achieve consensus
    honest_output = honest_outputs[0]
    valid_outputs = {0, config.input_msg, "Coordinated Fake A", "Coordinated Fake B"}
    assert honest_output in valid_outputs, f"Unexpected output: {honest_output}"


def test_dolev_coordinated_attack_large_network():
    """Test coordinated attack in larger network to verify scalability."""
    from crypto.ds import Configuration, DolevStrong, MaliciousStrategy

    config = Configuration(
        node_count=12,  # 1 sender + 11 followers
        input_msg="Hello World!",
        malicious_count=6,  # 1 malicious sender + 5 malicious followers (exactly half)
        malicious_strategy=MaliciousStrategy.SENDER_FOLLOWER_COORDINATED,
    )
    ds = DolevStrong(config)
    ds.run()

    # Even with many coordinated malicious nodes, Agreement should hold
    honest_outputs = [node.output() for node in ds.all_nodes if not node.is_malicious]
    assert len(set(honest_outputs)) == 1, f"Honest nodes disagreed: {honest_outputs}"

    honest_output = honest_outputs[0]
    valid_outputs = {0, config.input_msg, "Coordinated Fake A", "Coordinated Fake B"}
    assert honest_output in valid_outputs, f"Unexpected output: {honest_output}"
