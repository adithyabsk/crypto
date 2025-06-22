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
