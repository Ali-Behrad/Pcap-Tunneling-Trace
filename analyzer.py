import pyshark
import sys
import os
import yaml
import logging
import json
from functools import reduce
from plotter import *
from pdml_handler import *

with open("config.yml", "r") as f:
    parser = yaml.safe_load(f)

pcap_dirs = parser["watchdog"]["pcap_dir"]
results_dir = parser["analyzer"]["results"]
analyzer_log_dir = parser["analyzer"]["log_dir"]

iteration_number_to_plot = parser["plotter"]["iteration_num"]
stacks_per_plot = parser["plotter"]["stacks_per_plot"]

file_iterator = 0

def init(filename):
    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(analyzer_log_dir, exist_ok=True)
    os.makedirs(results_dir + "/" + filename, exist_ok=True)

logging.basicConfig(
    filename=f"{analyzer_log_dir}/analyzer.log",
    filemode="a",
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def path_parser(file_path: str) -> str:
    return parser["watchdog"]["pcap_dir"] + "/" + file_path.split("/")[-1]

def get_file_name(file_path : str) -> str:
    return file_path.split("/")[-1].split(".")[0] # 2025-05-21_12-56-21_sliced_seqnum

def get_main_file_name(secondaryFileName: str): # TODO: CHECKED
    trimmed = secondaryFileName.split(".")[0] 
    sliced = trimmed.split("_") # ["2025-05-15", "13-12-33", "sliced", "seqnum"]

    return sliced[0] + "_" + sliced[1] # 2025-05-15_13-12-33

def parse_json_stacks_counts(frame: dict):
    stacks = [k for k in frame.keys()]

    counts = []

    for stack in frame.keys():
        counts.append(frame[stack]["count"])

    return stacks, counts

def get_stack_counts_from_pcap(pcap_path):
    # Run tshark and capture PDML in memory
    result = subprocess.run(
        ["tshark", "-r", pcap_path, "-T", "pdml"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True
    )

    # Parse the XML from stdout
    root = ET.fromstring(result.stdout)
    counter = Counter()

    for packet in root.findall("packet"):
        stack = []
        for proto in packet.findall("proto"):
            proto_name = proto.attrib.get("name", "").upper()
            if proto_name != "GENINFO" and proto_name != "FRAME":
                stack.append(proto_name)
        stack_key = "-".join(stack)
        counter[stack_key] += 1

    return counter

def build_stack_matrix(pcap_files):
    all_stacks = set()
    per_iteration_counts = []

    for pcap in pcap_files:
        counts = get_stack_counts_from_pcap(pcap)
        all_stacks.update(counts.keys())
        per_iteration_counts.append(counts)

    # Create normalized matrix
    all_stacks = sorted(all_stacks)
    matrix = {stack: [] for stack in all_stacks}

    for counts in per_iteration_counts:
        for stack in all_stacks:
            matrix[stack].append(counts.get(stack, 0))

    return matrix

def parse_pcap(file_path: str):
    global file_iterator

    logging.info(f"Started Reading {path_parser(file_path)}")

    filename = get_file_name(file_path)

    try:    
        packet_count = 0

        init(filename)

        logging.info("Generating PDML file...")

        pdml_creator(file_path, f"{results_dir}/{filename}/{filename}.pdml")
    
        logging.info("End of PDML file generation...")

        logging.info(f"Saving the resulted json in {results_dir + "/" + filename + "/" + filename + ".json"}")
        
        pdml_to_enhanced_stack_json_by_protocol(f"{results_dir}/{filename}/{filename}.pdml", f"{results_dir}/{filename}/{filename}.json")

        logging.info("Packet Processing Finished...")
        
        logging.info("Saving json completed...")

        frame = {}

        with open(f"{results_dir}/{filename}/{filename}.json", "r") as f:
            frame = json.load(f)
        
        packet_count = reduce(lambda acc, item: acc + item["count"], frame.values(), 0)
            
        logging.info(f"Found {packet_count} number of packets...")
        
        print(f"Found {packet_count} number of packets...", file=sys.stdout)

        if not packet_count:
            logging.error("Empty processed packet object. Exiting now...")
            sys.exit(1)
        
        logging.info("Started Plotting Process. Generating graphical outputs...")

        print(frame)

        stacks = parse_json_stacks_counts(frame)[0]
        counts = parse_json_stacks_counts(frame)[1]

        path_to_save_hist = results_dir + "/" + filename + "/" + filename + "_hist.png"
        path_to_save_stacks = results_dir + "/" + filename + "/" + filename

        plot_hist(stacks, counts, path_to_save=path_to_save_hist)

        plot_layer_stacks_from_enhanced_json(f"{results_dir}/{filename}/{filename}.json",  output_dir=path_to_save_stacks,  stacks_per_plot=stacks_per_plot)

        logging.info("Finished generating graphical outputs...")

        logging.info("Starting timestamps (iterations) analysis...")

        '''
            {
                "ETH-IP-UDP-DNS": [count_iter_1, count_iter_2, ...],
                "ETH-IP-TCP":     [count_iter_1, count_iter_2, ...],
                ...
            }
        '''
        iteration_pcaps = f"{pcap_dirs}/{filename}/iterations"
        pcap_files = [f"{iteration_pcaps}/{file}" for file in sorted(os.listdir(f"{pcap_dirs}/{filename}/iterations"))]
        
        iterations_matrix = build_stack_matrix(pcap_files)

        plot_stack_matrix(iterations_matrix, f"{results_dir}/{filename}/iterations.png")

        logging.info("Analysis of iterations completed. Graphical outputs generated...")

    except Exception as e:
        logging.error(str(e))
        print(str(e), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__" :
    if len(sys.argv) < 2:
        logging.error("NO file provided...")
        print("NO file provided...", file=sys.stderr)
        sys.exit(1)
    
    file_path = sys.argv[1] # ./captured_pcaps/2025-05-21_12-56-21/2025-05-21_12-56-21.pcap

    if not os.path.exists(file_path):
        logging.error(f"Error: File not found at {file_path}")
        print(f"Error: File not found at {file_path}", file=sys.stderr)
        sys.exit(1)
    
    if os.path.splitext(file_path)[1] != ".pcap":
        logging.error("Not a valid pcap File!")
        print("Not a valid pcap File!", file=sys.stderr)
        sys.exit(1)
    
    if os.path.getsize(file_path) < 100:
        logging.error("File is empty. Exiting Analyzing process")
        print("File is empty. Exiting Analyzing process", file=sys.stderr)
        sys.exit(1)
    
    parse_pcap(file_path)