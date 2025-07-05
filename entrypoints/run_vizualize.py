import logging

from crypto.ds import Configuration, DolevStrongVisualizer, MaliciousStrategy

logger = logging.getLogger(__name__)


# Convenience function for easy visualization
def main():
    """Create and run a visualized Dolev-Strong protocol simulation."""

    config = Configuration(
        node_count=5,
        input_msg="Hello World!",
        malicious_strategy=MaliciousStrategy.SENDER_ONLY,
    )

    logger.info("=== Malicious Sender Scenario ===")
    logger.info(f"Creating Dolev-Strong visualization with {config.node_count} nodes")
    logger.info(f"Input message: '{config.input_msg}'")
    logger.info(f"Malicious strategy: {config.malicious_strategy}")

    visualizer = DolevStrongVisualizer(config)
    visualizer.show_visualization()
    return visualizer


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    main()
