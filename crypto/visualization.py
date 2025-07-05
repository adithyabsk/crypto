"""Visualization module for Dolev-Strong protocol simulation."""

import logging
import uuid

import matplotlib.patches as patches
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.animation import FuncAnimation
from matplotlib.widgets import Button, Slider

from crypto.dolev_strong import Configuration, DolevStrong

plt.set_loglevel(level="warning")


class DolevStrongVisualizer:
    """Visualizes the Dolev-Strong protocol message passing."""

    def __init__(
        self, dolev_strong_instance, fig=None, ax=None, is_web_environment=False
    ):
        # Set up logging
        self.logger = logging.getLogger("DolevStrongVisualizer")
        self.logger.info("Initializing DolevStrongVisualizer")

        self.ds = dolev_strong_instance
        self.is_web_environment = is_web_environment

        # Create figure and axes if not provided
        if fig is None or ax is None:
            self.fig, self.ax = plt.subplots(figsize=(14, 10))
        else:
            self.fig, self.ax = fig, ax

        # Make room for controls at the bottom (not needed for web environment)
        if not is_web_environment:
            plt.subplots_adjust(bottom=0.25)

        self.node_positions = self._calculate_node_positions()
        self.current_round = 0

        # Track slider update source
        self._slider_update_from_animation = False
        self._user_interacting_with_slider = False

        # Create UI controls only if not in web environment
        self.round_slider = None
        self.play_button = None
        self.animation = None
        self.is_playing = False

        if not is_web_environment:
            self._create_controls()

        self.logger.info(f"Initialization complete. n_rounds: {self.ds.config.n_rounds}")

    def _create_controls(self):
        """Create slider and button controls for interactive use."""
        # Create slider for round control
        ax_slider = plt.axes([0.2, 0.1, 0.5, 0.03])
        self.round_slider = Slider(
            ax_slider,
            "Round",
            0,
            self.ds.config.n_rounds,
            valinit=0,
            valfmt="%d",
            valstep=1,
        )
        self.round_slider.on_changed(self.update_round)

        # Create play/pause button
        ax_button = plt.axes([0.75, 0.1, 0.1, 0.04])
        self.play_button = Button(ax_button, "Play")
        self.play_button.on_clicked(self.toggle_animation)

    def _calculate_node_positions(self) -> dict[uuid.UUID, tuple[float, float]]:
        """Calculate positions for nodes in a circle layout."""
        n_nodes = len(self.ds.all_nodes)
        positions = {}

        # Place nodes in a circle
        for i, node in enumerate(self.ds.all_nodes):
            angle = 2 * np.pi * i / n_nodes - np.pi / 2  # Start from top
            x = 3 * np.cos(angle)
            y = 3 * np.sin(angle)
            positions[node.node_id] = (x, y)

        return positions

    def _draw_nodes(self):
        """Draw all nodes with different colors for sender/malicious."""
        self.ax.clear()
        self.ax.set_xlim(-5, 5)
        self.ax.set_ylim(-4, 4)
        self.ax.set_aspect("equal")
        self.ax.set_title(f"Dolev-Strong Protocol - Round {self.current_round}")

        for i, node in enumerate(self.ds.all_nodes):
            x, y = self.node_positions[node.node_id]

            # Choose color based on node type
            if node == self.ds.sender:
                color = "red" if node.is_malicious else "blue"
                label = f"S{i}"
                node_type = "Sender"
            else:
                color = "orange" if node.is_malicious else "green"
                label = f"N{i}"
                node_type = "Node"

            # Draw node
            circle = plt.Circle((x, y), 0.3, color=color, alpha=0.7)
            self.ax.add_patch(circle)

            # Add label
            self.ax.text(
                x, y, label, ha="center", va="center", fontweight="bold", color="white"
            )

            # Show extracted messages below node
            if hasattr(node, "extracted_msg") and node.extracted_msg:
                msg_text = f"Messages: {', '.join(list(node.extracted_msg)[:2])}"
                if len(node.extracted_msg) > 2:
                    msg_text += "..."
                self.ax.text(
                    x,
                    y - 0.7,
                    msg_text,
                    ha="center",
                    va="center",
                    fontsize=8,
                    bbox={
                        "boxstyle": "round,pad=0.1",
                        "facecolor": "white",
                        "alpha": 0.8,
                    },
                )

            # Show node info
            status = "Malicious" if node.is_malicious else "Honest"
            info_text = f"{node_type}\n{status}"
            self.ax.text(
                x,
                y + 0.6,
                info_text,
                ha="center",
                va="center",
                fontsize=8,
                bbox={
                    "boxstyle": "round,pad=0.1",
                    "facecolor": "lightblue",
                    "alpha": 0.8,
                },
            )

    def _draw_message(
        self,
        from_pos: tuple[float, float],
        to_pos: tuple[float, float],
        message: str,
        color: str = "black",
        alpha: float = 0.8,
    ):
        """Draw an arrow representing a message between nodes."""
        dx = to_pos[0] - from_pos[0]
        dy = to_pos[1] - from_pos[1]

        # Shorten arrow to not overlap with nodes
        length = np.sqrt(dx**2 + dy**2)
        if length == 0:
            return

        dx_norm = dx / length
        dy_norm = dy / length

        start_x = from_pos[0] + 0.35 * dx_norm
        start_y = from_pos[1] + 0.35 * dy_norm
        end_x = to_pos[0] - 0.35 * dx_norm
        end_y = to_pos[1] - 0.35 * dy_norm

        arrow = patches.FancyArrowPatch(
            (start_x, start_y),
            (end_x, end_y),
            arrowstyle="->",
            mutation_scale=15,
            color=color,
            alpha=alpha,
            linewidth=2,
        )
        self.ax.add_patch(arrow)

        # Add message label at midpoint
        mid_x = (start_x + end_x) / 2
        mid_y = (start_y + end_y) / 2

        # Truncate long messages
        display_msg = message[:15] + "..." if len(message) > 15 else message

        self.ax.text(
            mid_x,
            mid_y,
            display_msg,
            ha="center",
            va="center",
            fontsize=7,
            bbox={"boxstyle": "round,pad=0.1", "facecolor": "yellow", "alpha": 0.9},
            rotation=np.degrees(np.arctan2(dy, dx)) if abs(dx) > abs(dy) else 0,
        )

    def log_message(
        self, sender_id: uuid.UUID, receiver_id: uuid.UUID, message: str, round_num: int
    ):
        """Log a message for visualization."""
        self.message_log.append(
            {
                "sender": sender_id,
                "receiver": receiver_id,
                "message": message,
                "round": round_num,
            }
        )

    def visualize_round(self, round_num: int):
        """Visualize a specific round."""
        self.current_round = round_num
        self._draw_nodes()

        # Get messages for this round from DolevStrong's message log
        message_log = self.ds.get_message_log()
        round_messages = [msg for msg in message_log if msg["round"] == round_num]

        for msg in round_messages:
            try:
                from_pos = self.node_positions[msg["sender"]]
                to_pos = self.node_positions[msg["receiver"]]

                # Color code messages
                color = "red" if "Malicious" in msg["message"] else "blue"
                self._draw_message(from_pos, to_pos, msg["message"], color)
            except KeyError:
                # Handle case where node might not be found
                continue

        self.create_legend()

        # Add round information
        info_text = f"Round {round_num}/{self.ds.config.n_rounds}\n"
        info_text += f"Total messages this round: {len(round_messages)}"
        self.ax.text(
            -4.5,
            3.5,
            info_text,
            fontsize=12,
            bbox={"boxstyle": "round,pad=0.3", "facecolor": "lightcyan", "alpha": 0.9},
        )

    def create_legend(self):
        """Add a legend to explain the visualization."""
        legend_elements = [
            plt.Line2D(
                [0],
                [0],
                marker="o",
                color="w",
                markerfacecolor="blue",
                markersize=10,
                label="Honest Sender",
            ),
            plt.Line2D(
                [0],
                [0],
                marker="o",
                color="w",
                markerfacecolor="red",
                markersize=10,
                label="Malicious Sender",
            ),
            plt.Line2D(
                [0],
                [0],
                marker="o",
                color="w",
                markerfacecolor="green",
                markersize=10,
                label="Honest Node",
            ),
            plt.Line2D(
                [0],
                [0],
                marker="o",
                color="w",
                markerfacecolor="orange",
                markersize=10,
                label="Malicious Node",
            ),
            plt.Line2D([0], [0], color="blue", linewidth=2, label="Honest Message"),
            plt.Line2D([0], [0], color="red", linewidth=2, label="Malicious Message"),
        ]
        self.ax.legend(
            handles=legend_elements, loc="upper right", bbox_to_anchor=(1.15, 1)
        )

    def update_round(self, val):
        """Update visualization when slider changes."""
        if self.round_slider is None:
            return

        round_num = int(self.round_slider.val)

        if self._slider_update_from_animation:
            self.logger.debug(f"Slider updated by animation to round {round_num}")
        else:
            self.logger.info(f"Slider manually updated to round {round_num}")
            self._user_interacting_with_slider = True

            # If user touches slider while playing, pause animation
            if self.is_playing:
                self.logger.info(
                    "User touched slider while playing - auto-pausing animation"
                )
                if self.animation:
                    self.animation.pause()
                self.play_button.label.set_text("Play")
                self.is_playing = False

        self.visualize_round(round_num)
        plt.draw()

        # Reset user interaction flag after a short delay
        if self._user_interacting_with_slider:
            self._user_interacting_with_slider = False

    def toggle_animation(self, event):
        """Toggle between play and pause."""
        self.logger.info(
            "Play/Pause button pressed. "
            f"Current state - is_playing: {self.is_playing}, "
            f"animation exists: {self.animation is not None}"
        )

        if self.is_playing:
            if self.animation:
                self.logger.info("Pausing animation")
                self.animation.pause()
            else:
                self.logger.warning("is_playing=True but animation is None")
            self.play_button.label.set_text("Play")
            self.is_playing = False
            self.logger.info(f"Animation paused. is_playing: {self.is_playing}")
        else:
            if self.animation is None:
                self.logger.info("Creating new animation")
                self.animation = self.create_auto_animation()
                self.logger.info(f"Animation created: {self.animation}")
            else:
                self.logger.info("Resuming existing animation")
                self.animation.resume()
                # When resuming, also trigger immediate frame update
                self.logger.info("Triggering immediate frame on resume")
                current_frame = int(self.round_slider.val)
                self._slider_update_from_animation = True
                self.round_slider.set_val(current_frame)
                self._slider_update_from_animation = False

            self.play_button.label.set_text("Pause")
            self.is_playing = True
            self.logger.info(
                f"Animation should now be running. is_playing: {self.is_playing}"
            )

    def create_auto_animation(self, event_source=None):
        """Create automatic animation that updates the slider.

        Args:
            event_source: Optional timer for animation (for web support)
        """
        self.logger.info("Creating FuncAnimation")

        def animate(frame):
            current_round = frame % (self.ds.config.n_rounds + 1)
            self.logger.debug(
                f"Animation frame {frame}, setting round to {current_round}"
            )

            # For web environment, just update visualization directly
            if self.is_web_environment or self.round_slider is None:
                self.visualize_round(current_round)
                return []

            # For desktop environment, update through slider
            self._slider_update_from_animation = True
            self.round_slider.set_val(current_round)
            self._slider_update_from_animation = False

            return []

        # Create animation with provided event source or default
        ani = FuncAnimation(
            self.fig,
            animate,
            frames=range(self.ds.config.n_rounds + 1),
            interval=1000,
            repeat=True,
            blit=False,
            event_source=event_source,
        )

        self.logger.info(f"FuncAnimation created: {ani}")
        self.logger.info(f"Animation event_source: {ani.event_source}")

        # Force the animation to start by triggering the first frame
        self.logger.info("Triggering first animation frame manually")
        animate(0)  # Manually call the first frame

        # Also force a canvas draw to ensure it's visible
        self.fig.canvas.draw_idle()

        return ani

    def create_web_animation(self, timer_class=None):
        """Create animation specifically for web environment.

        Args:
            timer_class: Timer class to use for web environment
        """
        if timer_class is None:
            self.logger.warning("No timer class provided for web animation")
            return self.create_auto_animation()

        timer = timer_class(interval=1500)
        return self.create_auto_animation(event_source=timer)

    def show_interactive_visualization(self):
        """Show interactive visualization with controls."""
        # Initial visualization
        self.visualize_round(0)

        # Show final outputs in a text box
        output_text = "Final Outputs:\n"
        for i, node in enumerate(self.ds.all_nodes):
            output_text += f"Node {i}: {node.output()}\n"

        self.ax.text(
            -4.5,
            -3.5,
            output_text,
            fontsize=10,
            bbox={"boxstyle": "round,pad=0.3", "facecolor": "lightgray", "alpha": 0.9},
        )

        plt.tight_layout()
        plt.show()


# Simplified DolevStrong class for visualization
class VisualizableDolevStrong:
    """Extended DolevStrong class that supports visualization."""

    def __init__(self, config: Configuration, is_web_environment=False):
        # Initialize the DolevStrong instance with the provided configuration
        self.ds = DolevStrong(config)

        # Initialize the visualizer
        self.visualizer = DolevStrongVisualizer(
            self.ds, is_web_environment=is_web_environment
        )

        # Set up logging
        self.logger = logging.getLogger("VisualizableDolevStrong")


    def run_simulation(self):
        """Run the simulation to collect all data for visualization."""
        self.logger.info("Running Dolev-Strong simulation...")

        # Simply run the DolevStrong simulation - it will automatically log messages
        self.ds.run()

        # Log final results
        self.logger.info("Final Results:")
        for i, n in enumerate(self.ds.all_nodes):
            self.logger.info(f"{i}: {n}")

    def show_visualization(self):
        """Show the interactive visualization."""
        self.run_simulation()
        self.visualizer.show_interactive_visualization()


# Convenience function for easy visualization
def visualize_dolev_strong(config: Configuration, is_web_environment=False):
    """Create and run a visualized Dolev-Strong protocol simulation."""
    logger = logging.getLogger("visualize_dolev_strong")

    logger.info(f"Creating Dolev-Strong visualization with {config.node_count} nodes")
    logger.info(f"Input message: '{config.input_msg}'")
    logger.info(f"Malicious strategy: {config.malicious_strategy}")

    vds = VisualizableDolevStrong(config, is_web_environment=is_web_environment)
    vds.show_visualization()
    return vds


if __name__ == "__main__":
    from crypto.dolev_strong import MaliciousStrategy, Configuration

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    logger = logging.getLogger(__name__)

    logger.info("\n=== Malicious Sender Scenario ===")
    config = Configuration(
        node_count=5,
        input_msg="Hello World!",
        malicious_strategy=MaliciousStrategy.SENDER_ONLY,
    )
    visualize_dolev_strong(config)
