# A cryptography playground

Tested on:

- Python: 3.13.2

## Dolev-Strong

The Dolev-Strong protocol implements a means of solving the Byzantine General
problem in a synchronous setting. The protocol is described in
[_Authenticated Algorithms for Byzantine Agreement_](https://doi.org/10.1137/0212045).
[This is a python simulation]()
of the protocol.

### Run the Protocol Tests

To run the tests

```bash
make test
```

Run test with logging output

```bash
uv run pytest --log-cli-level=DEBUG --capture=tee-sys -k test_dolev_malicious_sender
```

### Simulation

To see the simulated output in the all honest case

```bash
uv run crypto/dolev_strong.py
```

Visualization

```bash
uv run crypto/visualization.py
```

# TODOs

- [x] Implement all honest test case
- [x] Implement malicious sender test case
- [ ] Implement Malicious Node attack
- [ ] Implement Sender / Node Coordinated attack
- [ ] Link to the blog post
