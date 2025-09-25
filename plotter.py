import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import json
import os

protocol_color_map = {
    "ETH": "#1f77b4",          # Blue
    "IP": "#ff7f0e",           # Orange
    "IPV6": "#2ca02c",         # Green
    "TCP": "#d62728",          # Red
    "UDP": "#9467bd",          # Purple
    "DNS": "#8c564b",          # Brown
    "HTTP": "#e377c2",         # Pink
    "TLS": "#7f7f7f",          # Gray
    "ICMP": "#bcbd22",         # Olive
    "QUIC": "#17becf",         # Cyan
    "GRE": "#aec7e8",          # Light blue
    "GTP": "#ffbb78",          # Light orange
    "PPTP": "#98df8a",         # Light green
    "L2TP": "#ff9896",         # Light red
    "MDNS": "#c5b0d5",         # Lavender
    "RTP": "#032a03",
    "MPLS": "#ddaf6e",
    "SIP": "#db1ca1",
    "STP": "#022528"
    # ... extend with many others ...
}


def plot_hist(stacks: list, counts: list, path_to_save: str):
    # Calculate total count
    total_count = sum(counts)
    
    # Calculate percentages
    percentages = {k: (counts[i] / total_count) * 100 for i , k in enumerate(stacks)}
    
    # Sort by percentage ascending
    sorted_items = sorted(percentages.items(), key=lambda x: x[1])
    
    # Extract sorted stacks and their percentages
    sorted_stacks = [item[0] for item in sorted_items]
    sorted_percentages = [item[1] for item in sorted_items]
    
    # Create simple labels: Stack 1, Stack 2, ...
    
    # Plot
    plt.figure(figsize=(10, 6))
    bars = plt.bar(sorted_stacks, sorted_percentages)
    plt.xlabel('Protocol Stack')
    plt.ylabel('Percentage (%)')
    plt.title('Histogram of Protocol Stack Percentages (Sorted Ascending)')
    
    # Add percentage labels on top of bars
    for bar, perc in zip(bars, sorted_percentages):
        height = bar.get_height()
        plt.annotate(f'{perc:.2f}%',
                     xy=(bar.get_x() + bar.get_width() / 2, height),
                     xytext=(0, 3),
                     textcoords="offset points",
                     ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(path_to_save)
    plt.close()

# iterations_combination.png
def plot_stack_matrix(matrix, output_path=None):
    stacks = list(matrix.keys())
    num_iterations = len(next(iter(matrix.values())))
    iterations = list(range(1, num_iterations + 1))

    # Prepare plot data
    bottom = [0] * num_iterations
    colors = plt.get_cmap('tab20').colors  # Get 20 distinct colors
    color_map = {stack: colors[i % len(colors)] for i, stack in enumerate(stacks)}

    plt.figure(figsize=(14, 7))

    for i, stack in enumerate(stacks):
        values = matrix[stack]
        plt.bar(iterations, values, bottom=bottom, color=color_map[stack], label=stack)
        bottom = [bottom[j] + values[j] for j in range(num_iterations)]

    plt.xlabel('Iteration Number')
    plt.ylabel('Packet Count')
    plt.title('Protocol Sequence Change Over Iterations')
    plt.xticks(iterations)
    plt.legend(title="Protocol Stacks", loc='upper left', bbox_to_anchor=(1.01, 1.0))
    plt.tight_layout()

    if output_path:
        plt.savefig(output_path)
        plt.close()
    else:
        plt.show()


"""def plot_protocol_stacks_from_jsons(json_files, path_to_save: str):
    protocol_counts_per_iteration = {}
    iteration_labels = []

    for idx, file in enumerate(json_files):
        with open(file, 'r') as f:
            data = json.load(f)

        iteration_label = f"Iter {idx+1}"
        iteration_labels.append(iteration_label)

        # Count all protocols
        for protocol, count in data.items():
            # Clean protocol string to friendly name
            cleaned_protocol = protocol.replace('[', '').replace(']', '').replace('<', '').replace('>', '').replace('Layer', '').replace(',', '→').strip()

            # Ensure protocol has a list to hold counts across iterations
            if cleaned_protocol not in protocol_counts_per_iteration:
                protocol_counts_per_iteration[cleaned_protocol] = []

            protocol_counts_per_iteration[cleaned_protocol].append(count)

    # Ensure all protocols have values for all iterations (fill missing with 0)
    max_iters = len(json_files)
    for counts in protocol_counts_per_iteration.values():
        while len(counts) < max_iters:
            counts.append(0)

    # Plotting
    protocols = list(protocol_counts_per_iteration.keys())
    iterations = np.arange(1, max_iters + 1)
    bottoms = np.zeros(len(iterations))

    plt.figure(figsize=(12, 7))

    for protocol in protocols:
        counts = protocol_counts_per_iteration[protocol]
        plt.bar(iterations, counts, bottom=bottoms, label=protocol)
        bottoms += np.array(counts)

    plt.xlabel('Iteration Number')
    plt.ylabel('Packet Count')
    plt.title('Protocol Sequence Change Over Iterations')
    plt.legend()
    plt.tight_layout()

    plt.savefig(path_to_save)
"""

# _layers.png
def plot_layer_stacks_from_enhanced_json(json_file, output_dir, stacks_per_plot=8):
    with open(json_file, 'r') as f:
        data = json.load(f)

    stack_items = list(data.items())
    num_plots = (len(stack_items) + stacks_per_plot - 1) // stacks_per_plot

    for plot_index in range(num_plots):
        fig, ax = plt.subplots(figsize=(16, 8))
        start = plot_index * stacks_per_plot
        end = min(start + stacks_per_plot, len(stack_items))
        group = stack_items[start:end]

        for local_idx, (stack_label, stack_info) in enumerate(group):
            protocols = list(reversed(stack_info['name'].split('-')))
            sizes = list(reversed(stack_info['size']))
            offsets = list(reversed(stack_info['offset']))
            size_flags = list(reversed(stack_info['isSizeEqual']))

            for j, (proto, size, offset, size_flag) in enumerate(zip(protocols, sizes, offsets, size_flags)):
                y = len(protocols) - 1 - j
                color = protocol_color_map.get(proto.upper(), "#cccccc")

                rect = patches.Rectangle(
                    (local_idx * 3, y),
                    2.5, 1,
                    linewidth=1,
                    edgecolor='black',
                    facecolor=color
                )
                ax.add_patch(rect)

                label_text = f"{proto} ({size},{offset})"
                ax.text(
                    local_idx * 3 + 1.25,
                    y + 0.5,
                    label_text,
                    ha='center',
                    va='center',
                    fontsize=9,
                    color='white',
                    weight='bold'
                )

                ax.text(
                    local_idx * 3 + 2.7,
                    y + 0.5,
                    f"{size_flag}",
                    ha='left',
                    va='center',
                    fontsize=9,
                    color='black'
                )

            ax.text(
                local_idx * 3 + 1.25,
                -1,
                stack_label,
                ha='center',
                va='center',
                fontsize=10
            )

        ax.set_xlim(-0.5, len(group) * 3)
        max_layers = max(len(stack_info['size']) for _, stack_info in group)
        ax.set_ylim(-1.5, max_layers + 1)
        ax.axis('off')
        plt.title(f'Protocol Layer Structure per Stack (Part {plot_index + 1})', fontsize=14)
        plt.tight_layout()

        output_file = f"{output_dir}_layer_stacks_{plot_index + 1}.png"
        plt.savefig(output_file)
        plt.close()

    print(f"Saved plot {plot_index + 1} to {output_file}")
