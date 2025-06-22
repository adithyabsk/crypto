import asyncio
import logging
import math
from datetime import datetime

from pyscript import document

from crypto.dolev_strong import DolevStrong, MaliciousStrategy
from crypto.visualization import VisualizableDolevStrong

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("InteractiveVisualizer")

# Global state
current_vds = None
current_round = 0
max_rounds = 0
auto_playing = False
auto_play_task = None
node_positions = {}
node_info = {}
message_log = []
node_id_to_index = {}


def display_output(content, append=False):
    """Helper function to display content in the output div."""
    output_element = document.querySelector("#output")
    if append:
        output_element.innerHTML += content
    else:
        output_element.innerHTML = content


def update_status(message, status_type="ready"):
    """Update the simulation status display."""
    status_element = document.querySelector("#simulation-status")
    status_element.innerHTML = message
    status_element.className = f"simulation-status status-{status_type}"


def update_round_display():
    """Update the round display and button states."""
    document.querySelector("#current-round").innerHTML = str(current_round)

    # Update button states
    prev_btn = document.querySelector("#prev-round")
    next_btn = document.querySelector("#next-round")

    if prev_btn and next_btn:
        prev_btn.disabled = current_round <= 0
        next_btn.disabled = current_round >= max_rounds


def get_form_values():
    """Extract values from the form inputs."""
    node_count = int(document.querySelector("#node-count").value)
    input_message = document.querySelector("#input-message").value
    strategy_str = document.querySelector("#malicious-strategy").value
    malicious_count = int(document.querySelector("#malicious-count").value)

    # Convert strategy string to enum
    if strategy_str == "NONE":
        strategy = MaliciousStrategy.NONE
        malicious_count = 0
    elif strategy_str == "SENDER_ONLY":
        strategy = MaliciousStrategy.SENDER_ONLY
    else:
        strategy = MaliciousStrategy.NONE
        malicious_count = 0

    return node_count, input_message, strategy, malicious_count


def calculate_node_positions(node_count):
    """Calculate positions for nodes in a circle layout."""
    positions = {}
    container = document.querySelector("#graph-container")
    container_width = container.clientWidth
    container_height = container.clientHeight

    # Calculate center and radius
    center_x = container_width / 2
    center_y = container_height / 2
    radius = min(center_x, center_y) - 80  # Leave margin

    # Place nodes in a circle
    for i in range(node_count):
        angle = (2 * math.pi * i) / node_count - math.pi / 2  # Start from top
        x = center_x + radius * math.cos(angle)
        y = center_y + radius * math.sin(angle)
        positions[i] = (x, y)

    return positions


def create_node_info(vds):
    """Extract node information from the simulation."""
    global node_id_to_index
    info = {}
    node_id_to_index = {}

    for i, node in enumerate(vds.ds.all_nodes):
        node_type = "sender" if node == vds.ds.sender else "node"
        is_malicious = node.is_malicious

        # Map node_id to index for message rendering
        node_id_to_index[node.node_id] = i

        info[i] = {
            "type": node_type,
            "is_malicious": is_malicious,
            "extracted_messages": list(node.extracted_msg),
            "node_id": node.node_id,
        }

    return info


def clear_graph():
    """Clear all nodes and messages from the graph."""
    container = document.querySelector("#graph-container")
    container.innerHTML = ""


def render_nodes():
    """Render all nodes on the graph."""
    container = document.querySelector("#graph-container")

    for node_id, (x, y) in node_positions.items():
        node_data = node_info[node_id]

        # Determine node class
        node_class = "node "
        if node_data["type"] == "sender":
            node_class += "node-sender-" + (
                "malicious" if node_data["is_malicious"] else "honest"
            )
        else:
            node_class += "node-" + (
                "malicious" if node_data["is_malicious"] else "honest"
            )

        # Create node element
        node_div = document.createElement("div")
        node_div.className = node_class
        node_div.id = f"node-{node_id}"
        node_div.innerHTML = f"N{node_id}"
        node_div.style.left = f"{x - 30}px"  # Center the node (60px width)
        node_div.style.top = f"{y - 30}px"  # Center the node (60px height)

        # Create label for extracted messages
        label_div = document.createElement("div")
        label_div.className = "node-label"
        label_div.id = f"label-{node_id}"

        # Position the label below the node
        label_div.style.left = f"{x - 60}px"  # Center the label (120px width)
        label_div.style.top = f"{y + 35}px"  # Below the node

        # Add elements to container
        container.appendChild(node_div)
        container.appendChild(label_div)

    # Update node labels with current data
    update_node_labels()


def update_node_labels():
    """Update the labels showing extracted messages for each node."""
    for node_id in node_positions:
        node_data = node_info[node_id]
        label = document.querySelector(f"#label-{node_id}")

        if current_round == 0:
            # Only the sender has an initial message
            if node_data["type"] == "sender" and node_data["extracted_messages"]:
                label.innerHTML = f"Msg: {node_data['extracted_messages'][0]}"
            else:
                label.innerHTML = "No msg yet"
        else:
            # Get messages extracted up to current round
            extracted = node_data["extracted_messages"]

            if extracted:
                # Show up to 2 messages to avoid clutter
                display_msgs = extracted[:2]
                msg_text = ", ".join(display_msgs)
                if len(extracted) > 2:
                    msg_text += "..."
                label.innerHTML = f"Msg: {msg_text}"
            else:
                label.innerHTML = "No msg yet"


def render_messages_for_round(round_num):
    """Render messages sent during the specified round."""
    container = document.querySelector("#graph-container")

    # Filter messages for this round
    round_messages = [msg for msg in message_log if msg["round"] == round_num]

    # Debug: show what we found
    display_output(
        f"<p>Debug: Found {len(round_messages)} messages for round {round_num}</p>",
        append=True,
    )

    for msg in round_messages:
        try:
            # Map from UUIDs to node indices
            sender_id = msg["sender"]
            receiver_id = msg["receiver"]

            # Get the node indices
            from_index = node_id_to_index.get(sender_id)
            to_index = node_id_to_index.get(receiver_id)

            if from_index is None or to_index is None:
                display_output(
                    f"<p>Debug: Could not find indices for sender {sender_id}"
                    f" or receiver {receiver_id}</p>",
                    append=True,
                )
                continue

            from_pos = node_positions[from_index]
            to_pos = node_positions[to_index]

            # Determine if message is valid (honest message vs malicious)
            valid = "Malicious" not in msg["message"]

            # Calculate line properties
            dx = to_pos[0] - from_pos[0]
            dy = to_pos[1] - from_pos[1]
            distance = math.sqrt(dx * dx + dy * dy)

            if distance == 0:
                continue  # Skip self-messages

            angle = math.atan2(dy, dx)

            # Adjust line endpoints to start/end at node edges
            start_x = from_pos[0] + 30 * math.cos(angle)
            start_y = from_pos[1] + 30 * math.sin(angle)
            end_x = to_pos[0] - 30 * math.cos(angle)
            end_y = to_pos[1] - 30 * math.sin(angle)

            adjusted_dx = end_x - start_x
            adjusted_dy = end_y - start_y
            adjusted_distance = math.sqrt(
                adjusted_dx * adjusted_dx + adjusted_dy * adjusted_dy
            )

            # Create line element
            line_div = document.createElement("div")
            line_div.className = (
                "message-line "
                f"{'message-line-valid' if valid else 'message-line-invalid'}"
            )
            line_div.style.width = f"{adjusted_distance}px"
            line_div.style.left = f"{start_x}px"
            line_div.style.top = f"{start_y}px"
            line_div.style.transform = f"rotate({angle}rad)"

            # Create arrow element
            arrow_div = document.createElement("div")
            arrow_div.className = (
                "message-arrow "
                f"{'message-arrow-valid' if valid else 'message-arrow-invalid'}"
            )
            arrow_div.style.left = f"{end_x - 6}px"
            arrow_div.style.top = f"{end_y - 5}px"
            arrow_div.style.transform = f"rotate({angle + math.pi / 2}rad)"

            container.appendChild(line_div)
            container.appendChild(arrow_div)

        except Exception as e:
            display_output(f"<p>Debug: Error rendering message: {e}</p>", append=True)
            logger.error(f"Error rendering message: {e}")


def visualize_current_round():
    """Update the visualization to show the current round."""
    clear_graph()
    render_nodes()
    if current_round > 0:
        render_messages_for_round(current_round)
    update_round_display()


def create_visualization(event):
    """Create the interactive visualization."""
    global \
        current_vds, \
        current_round, \
        max_rounds, \
        node_positions, \
        node_info, \
        message_log

    try:
        update_status("Creating visualization...", "running")
        display_output("<h3>Creating Interactive Visualization</h3>")

        node_count, input_message, strategy, malicious_count = get_form_values()

        # Validate inputs
        if malicious_count >= node_count:
            raise ValueError("Malicious count must be less than total nodes")

        display_output(
            f"<p>Configuration: {node_count} nodes, message: "
            f"'{input_message}', strategy: {strategy.name}</p>",
            append=True,
        )

        # Create visualizable simulation
        if strategy == MaliciousStrategy.NONE:
            current_vds = VisualizableDolevStrong(node_count, input_message)
        else:
            current_vds = VisualizableDolevStrong(
                node_count,
                input_message,
                malicious_strategy=strategy,
                malicious_count=malicious_count,
            )

        # Run the simulation to collect data
        display_output("<p>Running simulation to collect data...</p>", append=True)
        current_vds.run_simulation()

        # Calculate node positions
        node_positions = calculate_node_positions(node_count)

        # Extract node info
        node_info = create_node_info(current_vds)

        # Extract message log and debug it
        message_log = current_vds.visualizer.message_log
        display_output(
            f"<p>Debug: Total messages logged: {len(message_log)}</p>", append=True
        )

        # Show some sample messages for debugging
        if message_log:
            sample_msg = message_log[0]
            display_output(
                f"<p>Debug: Sample message structure: {list(sample_msg.keys())}</p>",
                append=True,
            )

        # Show controls
        document.querySelector("#round-controls").style.display = "flex"
        document.querySelector("#legend").style.display = "flex"

        # Initialize visualization
        current_round = 0
        max_rounds = current_vds.ds.n_rounds
        visualize_current_round()

        # Show final results
        display_output("<h4>Final Node Outputs:</h4>", append=True)
        for i, node in enumerate(current_vds.ds.all_nodes):
            node_type = "Sender" if node == current_vds.ds.sender else "Node"
            status = "Malicious" if node.is_malicious else "Honest"
            output_val = node.output()
            display_output(
                f"<p>{node_type} {i} ({status}): {output_val}</p>", append=True
            )

        update_status(
            "Visualization ready! Use controls to navigate "
            f"through {max_rounds + 1} rounds.",
            "complete",
        )

    except Exception as e:
        display_output(f"<p style='color: red;'>Error: {str(e)}</p>", append=True)
        update_status(f"Error: {str(e)}", "ready")
        logger.error(f"Visualization creation failed: {e}")


def run_basic_simulation(event):
    """Run a basic text-only simulation."""
    try:
        update_status("Running basic simulation...", "running")
        display_output("<h3>Basic Simulation Results</h3>")

        node_count, input_message, strategy, malicious_count = get_form_values()

        # Create and run simulation
        if strategy == MaliciousStrategy.NONE:
            ds = DolevStrong(node_count, input_message)
        else:
            ds = DolevStrong(
                node_count,
                input_message,
                malicious_strategy=strategy,
                malicious_count=malicious_count,
            )

        display_output(
            f"<p><strong>Configuration: {node_count} nodes, "
            f"message: '{input_message}'</strong></p>",
            append=True,
        )

        ds.run()

        # Display results
        display_output("<h4>Final Node Outputs:</h4>", append=True)
        for i, node in enumerate(ds.all_nodes):
            node_type = "Sender" if node == ds.sender else "Node"
            status = "Malicious" if node.is_malicious else "Honest"
            output_val = node.output()
            display_output(
                f"<p>{node_type} {i} ({status}): {output_val}</p>", append=True
            )

        update_status("Basic simulation complete", "complete")

    except Exception as e:
        display_output(f"<p style='color: red;'>Error: {str(e)}</p>", append=True)
        update_status(f"Error: {str(e)}", "ready")


def prev_round(event):
    """Go to previous round."""
    global current_round
    if current_round > 0:
        current_round -= 1
        visualize_current_round()


def next_round(event):
    """Go to next round."""
    global current_round
    if current_round < max_rounds:
        current_round += 1
        visualize_current_round()


async def auto_play_loop():
    """Auto-play through all rounds with delay."""
    global current_round, auto_playing

    while auto_playing and current_round < max_rounds:
        await asyncio.sleep(1.5)  # 1.5 second delay between rounds
        if auto_playing:  # Check again in case it was stopped
            current_round += 1
            visualize_current_round()

    # Auto-play finished or was stopped
    auto_playing = False
    document.querySelector("#auto-play").innerHTML = "▶ Auto Play"
    document.querySelector("#auto-status").innerHTML = ""


def toggle_auto_play(event):
    """Toggle auto-play mode."""
    global auto_playing, auto_play_task

    if not current_vds:
        return

    auto_playing = not auto_playing

    if auto_playing:
        document.querySelector("#auto-play").innerHTML = "⏸ Pause"
        document.querySelector("#auto-status").innerHTML = "Auto-playing..."
        # Start auto-play loop
        auto_play_task = asyncio.create_task(auto_play_loop())
    else:
        document.querySelector("#auto-play").innerHTML = "▶ Auto Play"
        document.querySelector("#auto-status").innerHTML = ""
        if auto_play_task:
            auto_play_task.cancel()


# Initialize
now = datetime.now()
display_output(
    f"<p>Interactive visualizer loaded at: {now.strftime('%m/%d/%Y, %H:%M:%S')}</p>"
)
display_output(
    "<p>Configure parameters above and click "
    "'Create Interactive Visualization' to begin.</p>",
    append=True,
)
logger.info("Interactive Dolev-Strong visualizer initialized")
