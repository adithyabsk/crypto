import logging

import matplotlib.pyplot as plt
from matplotlib_pyodide.browser_backend import TimerWasm
from pyscript import current_target, document

from crypto.dolev_strong import Configuration, MaliciousStrategy
from crypto.visualization import DolevStrongVisualizer

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("WebVisualizer")


class Timer(TimerWasm):
    def __init__(self, interval=None):
        self._timer = None
        super().__init__(interval=interval)


# Configure matplotlib to suppress warnings
plt.set_loglevel(level="warning")


def create_visualization():
    """Create and return a web-based Dolev-Strong visualization."""
    logger.info("Creating web-based Dolev-Strong visualization")

    # Create the configuration for the simulation
    config = Configuration(
        node_count=5,
        input_msg="Hello World!",
        malicious_strategy=MaliciousStrategy.SENDER_ONLY,
    )

    # Create the visualizer for web environment
    visualizer = DolevStrongVisualizer(config, is_web_environment=True)

    # Run simulation to collect data
    visualizer.run_simulation()

    # Create web-compatible animation
    ani = visualizer.create_web_animation(timer_class=Timer)

    return ani


# Main function
try:
    logger.info("Starting Dolev-Strong web visualization")
    animation = create_visualization()

    # Convert animation to HTML
    html = animation.to_jshtml()

    # Get the target element where the visualization will be displayed
    element = document.getElementById(current_target())
    if element.tagName == "SCRIPT":
        element = getattr(element, "target", element)

    element.replaceChildren()

    # Add a title
    title_element = document.createElement("h2")
    title_element.textContent = "Dolev-Strong Protocol Visualization"
    element.appendChild(title_element)

    # Add description
    desc_element = document.createElement("p")
    desc_element.innerHTML = """
    This visualization shows the Dolev-Strong protocol with a malicious sender.
    The animation cycles through each round, showing message passing between nodes.
    <br><br>
    <strong>Legend:</strong><br>
    🔵 Blue = Honest Sender | 🔴 Red = Malicious Sender<br>
    🟢 Green = Honest Node | 🟠 Orange = Malicious Node<br>
    Blue arrows = Honest messages | Red arrows = Malicious messages
    """
    element.appendChild(desc_element)

    # Add the animation
    script_element = document.createRange().createContextualFragment(html)
    element.append(script_element)

    logger.info("Visualization created successfully")

except Exception as e:
    logger.error(f"Error creating visualization: {e}")
    # Display error message
    element = document.getElementById(current_target())
    if element.tagName == "SCRIPT":
        element = getattr(element, "target", element)

    error_element = document.createElement("div")
    error_element.innerHTML = (
        f"<h3>Error creating visualization:</h3><p style='color: red;'>{str(e)}</p>"
    )
    element.appendChild(error_element)
