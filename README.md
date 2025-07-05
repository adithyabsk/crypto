# A Cryptography playground

Tested on:

- Python: 3.13.2

## Dolev-Strong

The Dolev-Strong protocol implements a means of solving the Byzantine General
problem in a synchronous setting. The protocol is described in
[_Authenticated Algorithms for Byzantine Agreement_](https://doi.org/10.1137/0212045).
[This is a python simulation]()
of the protocol.

Please see [detailed docs here](./crypto/ds/README.md)

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
uv run entrypoints/simulate.py
```

Visualization

```bash
uv run entrypoints/run_vzualize.py
```

Web visualization

```bash
uv run python -m http.server
# in another terminal
open "http://localhost:8000/web"
```

# TODOs

- [x] Implement all honest test case
- [x] Implement malicious sender test case
- [x] Implement Malicious Node attack
- [x] Implement Sender / Node Coordinated attack
- [x] Refactor to use configuration pattern
- [x] Refactor into folder (`ds`) and split into separate files
  - strategy, primitives, models, protocol
- [ ] Walk through implementation
- [ ] Walk through test cases
- [ ] Walk through paper again
- [ ] Clean up animation (e.g. legend)
- [ ] Write / link to the blog post
