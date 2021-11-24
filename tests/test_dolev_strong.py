"""Dolev Strong protocol functional tests."""


def test_dolev_all_honest(capsys):
    """Make sure protocol adheres to validity principle."""
    from crypto.dolev_strong import DolevStrong

    in_str = "Hello World!"
    n_nodes = 5
    ds = DolevStrong(n_nodes, in_str)
    ds.run()

    captured = capsys.readouterr()
    assert captured.out.count(in_str) == 5


def test_dolev_malicious_sender(capsys):
    """Make sure protocol adheres to consistency principle."""
    from crypto.dolev_strong import DolevStrong, MaliciousStrategy

    in_str = "Hello World!"
    n_nodes = 5
    ds = DolevStrong(n_nodes, in_str, malicious_strategy=MaliciousStrategy.SENDER_ONLY)
    ds.run()

    captured = capsys.readouterr()
    assert captured.out.count(in_str) == 0
    for line in captured.out.splitlines():
        if "malicious: False" in line:
            assert "0" in line
