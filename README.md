# A cryptography playground

## Dolev-Strong

The Dolev-Strong protocol implements a means of solving the Byzantine General
problem in a synchronous setting. The protocol is described in
[_Authenticated Algorithms for Byzantine Agreement_](https://doi.org/10.1137/0212045).
[This is a python simulation]()
of the protocol.

### Run the Protocol Tests

To run the tests

```shell
pytest -k dolev
```

To see the simulated output in the all honest case

```shell
python crypto/dolev_strong.py
```

# TODOs

- [x] Implement all honest test case
- [x] Implement malicious sender test case
- [ ] Implement Malicious Node attack
- [ ] Implement Sender / Node Coordinated attack
- [ ] Link to the blog post
