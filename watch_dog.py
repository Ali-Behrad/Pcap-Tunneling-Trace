import logging 
# import pyshark
import subprocess
import datetime
import yaml
import os
import sys
import time 
import dpkt

if not os.path.exists("config.yml"):
    print("No Config File Found!!! Exiting the program")
    sys.exit(1)

with open("config.yml", "r") as f:
    parser = yaml.safe_load(f)

# Config Parser Section
interval = int(parser["watchdog"]["interval"])
pcap_save_dir = parser["watchdog"]["pcap_dir"]
log_dir = parser["watchdog"]["log_dir"]
interface = parser["watchdog"]["interface"]
iteration_duration = parser["watchdog"]["iteration_duration"]

buffer_size = parser["watchdog"]["buffer_size"]

def make_dirs():
    os.makedirs(log_dir, exist_ok=True)

make_dirs()

logging.basicConfig(
    filename=f"{log_dir}/watchdog_logs.log",
    filemode="a",
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def get_time():
    current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") # 2025-05-15_13-12-33.pcap
    
    return current_time


def slice_packets(pcap_path, output_dir):
    packet_buffer = []
    current_interval_start = None
    file_index = 0

    with open(pcap_path, 'rb') as f:
        pcap_reader = dpkt.pcap.Reader(f)

        for timestamp, packet in pcap_reader:
            if current_interval_start is None:
                current_interval_start = timestamp  

            if timestamp - current_interval_start >= iteration_duration:
                output_file = f"{output_dir}_sliced_{file_index}.pcap"
                print(f"Creating slice: {output_file}, containing {len(packet_buffer)} packets")
                with open(output_file, 'wb') as out_f:
                    pcap_writer = dpkt.pcap.Writer(out_f)
                    for pkt in packet_buffer:
                        pcap_writer.writepkt(pkt[1], pkt[0])  
                
                file_index += 1
                packet_buffer = []
                current_interval_start = timestamp  

            packet_buffer.append((timestamp, packet))

        if packet_buffer:
            output_file = f"{output_dir}_sliced_{file_index}.pcap"
            print(f"Creating last slice: {output_file}, containing {len(packet_buffer)} packets")
            with open(output_file, 'wb') as out_f:
                pcap_writer = dpkt.pcap.Writer(out_f)
                for pkt in packet_buffer:
                    pcap_writer.writepkt(pkt[1], pkt[0])


def run_analyzer(file_path: str):
    result = subprocess.run(
        ["python", "analyzer.py", file_path],
        capture_output = True,
        text = True
    )

    if result.returncode == 0:
        print("Analyzer is Done! Any messages from analyzer will be shown below: ")
        print(result.stdout)
        logging.info("Analysis Finished Successfully!")
    else :
        print("An error occurred!")
        logging.error(f"Analyzer Faced an Error. {result.stderr}")

def sniff():
    logging.info("Watch Dog Started! Sniffing Packets...")
    now = get_time()

    packet_dir = f"{pcap_save_dir}/{now}"

    os.makedirs(packet_dir + "/iterations", exist_ok=True)
    try:
        # 
        # capture = pyshark.LiveCapture(interface=interface, output_file=f"{packet_dir}/{now}.pcap")
        # capture.sniff(timeout=interval)
        # capture.close()
        # r = os.system(f"editcap -i {iteration_duration} {packet_dir}/{now}.pcap {packet_dir}/iterations/{now}_sliced.pcap")
        
        subprocess.run([
            "sudo" , "tcpdump", "-i", interface, "-G", str(interval), "-w" , f"{packet_dir}/{now}.pcap", "-B", str(buffer_size), "-W", str(1)
        ])

        logging.info("Started Slicing...")

        slice_packets(f"{packet_dir}/{now}.pcap", f"{packet_dir}/iterations/{now}")
        
        logging.info("End of slicing...")

        logging.info(f"Sniffing Finished. The results saved at {pcap_save_dir}/{now}.pcap")

    except Exception as e:
        print(e)
        logging.error(f"Error Occurred During Packet Sniffing. {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    sniff()