"""Dolev Strong protocol functional tests."""


def test_dolev_all_honest():
    """Make sure protocol adheres to validity principle."""
    from crypto.dolev_strong import DolevStrong

    in_str = "Hello World!"
    n_nodes = 5
    ds = DolevStrong(n_nodes, in_str)
    ds.run()

    # Check that all nodes output the correct message
    for node in ds.all_nodes:
        assert node.output() == in_str


def test_dolev_malicious_sender():
    """Make sure protocol adheres to consistency principle."""
    from crypto.dolev_strong import DolevStrong, MaliciousStrategy

    in_str = "Hello World!"
    n_nodes = 5
    ds = DolevStrong(
        n_nodes,
        in_str,
        malicious_count=1,
        malicious_strategy=MaliciousStrategy.SENDER_ONLY,
    )
    ds.run()

    # Check that honest nodes all output 0 (no consensus)
    for node in ds.nodes:  # Only check honest nodes (not the malicious sender)
        assert node.output() == 0


def test_dolev_malicious_followers_drop_all():
    """Test protocol with malicious follower nodes that drop all messages."""
    from crypto.dolev_strong import (
        DolevStrong,
        MaliciousNodeStrategy,
        MaliciousStrategy,
    )

    in_str = "Hello World!"
    n_nodes = 6
    malicious_count = 2

    ds = DolevStrong(
        n_nodes,
        in_str,
        malicious_count=malicious_count,
        malicious_strategy=MaliciousStrategy.FOLLOWER_NODES_ONLY,
        malicious_node_strategy=MaliciousNodeStrategy.DROP_ALL,
    )
    ds.run()

    # Even with nodes that drop all messages, honest sender should ensure consensus
    for node in ds.all_nodes:
        assert node.output() == in_str


def test_dolev_malicious_followers_send_half():
    """Malicious follower nodes that only send to half their peers."""
    from crypto.dolev_strong import (
        DolevStrong,
        MaliciousNodeStrategy,
        MaliciousStrategy,
    )

    in_str = "Hello World!"
    n_nodes = 6
    malicious_count = 2

    ds = DolevStrong(
        n_nodes,
        in_str,
        malicious_count=malicious_count,
        malicious_strategy=MaliciousStrategy.FOLLOWER_NODES_ONLY,
        malicious_node_strategy=MaliciousNodeStrategy.SEND_HALF,
    )
    ds.run()

    # With honest sender, all nodes should agree on sender's message
    for node in ds.all_nodes:
        assert node.output() == in_str


def test_dolev_extreme_malicious_followers():
    """Test with only one honest node (plus honest sender)."""
    from crypto.dolev_strong import DolevStrong, MaliciousStrategy

    in_str = "Hello World!"
    n_nodes = 5  # 1 sender + 4 followers
    malicious_count = 3  # 3 out of 4 followers are malicious

    ds = DolevStrong(
        n_nodes,
        in_str,
        malicious_count=malicious_count,
        malicious_strategy=MaliciousStrategy.FOLLOWER_NODES_ONLY,
    )
    ds.run()

    # Even with only 1 honest follower, if sender is honest,
    # all nodes should agree on sender's message
    for node in ds.all_nodes:
        assert node.output() == in_str


def test_dolev_coordinated_attack():
    """Test coordinated attack between malicious sender and malicious followers."""
    from crypto.dolev_strong import DolevStrong, MaliciousStrategy

    in_str = "Hello World!"
    n_nodes = 8  # 1 sender + 7 followers
    malicious_count = 4  # 1 malicious sender + 3 malicious followers

    ds = DolevStrong(
        n_nodes,
        in_str,
        malicious_count=malicious_count,
        malicious_strategy=MaliciousStrategy.SENDER_FOLLOWER_COORDINATED,
    )
    ds.run()

    # Even with coordinated attack, Dolev-Strong should ensure that
    # honest nodes either all agree on the same value or all output default (0)
    honest_outputs = [node.output() for node in ds.all_nodes if not node.is_malicious]

    # All honest nodes should have the same output (Agreement property)
    assert len(set(honest_outputs)) == 1, f"Honest nodes disagreed: {honest_outputs}"

    # The output should be either 0 (no consensus due to conflicting messages)
    # or one of the valid messages (if protocol achieved consensus despite attack)
    honest_output = honest_outputs[0]
    valid_outputs = {0, in_str, "Coordinated Fake A", "Coordinated Fake B"}
    assert honest_output in valid_outputs, f"Unexpected output: {honest_output}"

    print(f"Coordinated attack test passed. Honest nodes agreed on: {honest_output}")


def test_dolev_coordinated_attack_minimal():
    """Test coordinated attack with minimal configuration (exactly at threshold)."""
    from crypto.dolev_strong import DolevStrong, MaliciousStrategy

    in_str = "Hello World!"
    n_nodes = 4  # 1 sender + 3 followers
    malicious_count = 2  # 1 malicious sender + 1 malicious follower

    ds = DolevStrong(
        n_nodes,
        in_str,
        malicious_count=malicious_count,
        malicious_strategy=MaliciousStrategy.SENDER_FOLLOWER_COORDINATED,
    )
    ds.run()

    # Check that honest nodes maintain agreement
    honest_outputs = [node.output() for node in ds.all_nodes if not node.is_malicious]
    assert len(set(honest_outputs)) == 1, f"Honest nodes disagreed: {honest_outputs}"

    # With fewer malicious nodes, protocol might still achieve consensus
    honest_output = honest_outputs[0]
    valid_outputs = {0, in_str, "Coordinated Fake A", "Coordinated Fake B"}
    assert honest_output in valid_outputs, f"Unexpected output: {honest_output}"

    print(f"Minimal coordinated attack test passed. Output: {honest_output}")


def test_dolev_coordinated_attack_large_network():
    """Test coordinated attack in larger network to verify scalability."""
    from crypto.dolev_strong import DolevStrong, MaliciousStrategy

    in_str = "Hello World!"
    n_nodes = 12  # 1 sender + 11 followers
    malicious_count = 6  # 1 malicious sender + 5 malicious followers (exactly half)

    ds = DolevStrong(
        n_nodes,
        in_str,
        malicious_count=malicious_count,
        malicious_strategy=MaliciousStrategy.SENDER_FOLLOWER_COORDINATED,
    )
    ds.run()

    # Even with many coordinated malicious nodes, Agreement should hold
    honest_outputs = [node.output() for node in ds.all_nodes if not node.is_malicious]
    assert len(set(honest_outputs)) == 1, f"Honest nodes disagreed: {honest_outputs}"

    honest_output = honest_outputs[0]
    valid_outputs = {0, in_str, "Coordinated Fake A", "Coordinated Fake B"}
    assert honest_output in valid_outputs, f"Unexpected output: {honest_output}"

    print(f"Large network coordinated attack test passed. Output: {honest_output}")
