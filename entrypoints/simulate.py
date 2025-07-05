#!/usr/bin/env python
"""Legacy entry point for Dolev-Strong protocol - use ds package instead."""

import logging

from crypto.ds import Configuration, DolevStrong, MaliciousStrategy

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    config = Configuration(
        node_count=5,
        input_msg="Hello World!",
        malicious_strategy=MaliciousStrategy.SENDER_ONLY,
    )
    ds = DolevStrong(config)
    ds.run()
