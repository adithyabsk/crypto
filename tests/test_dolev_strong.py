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
