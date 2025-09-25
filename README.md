# Pcap-Tunneling-TraceA Python program to capture packets on a desired interface and find any possible tunneling in the packets

### How it works
#### This program is designed to sniff packets on a given interface and analyze the structure of the containing packets and also identify the possible existance of tunneling protocols.
#### The program also generates a full visual report of all available protocol stacks (e.g ETH/IP/TCP) and their corresponding frequency percentage.
#### It also provides the packet count change of each protocol during each timestamp (iteration). An iteration is a temporal portion of the entire captured pcap.
#### Finally, the entire captured pcap as well as all the sub-pcaps (related to the iterations) are saved an a full report of the main pcap is generated in the json and pdml format.

### How to run
#### 1. Packet Sniffer: The sniffer program is the watch_dog.py script. The related configuration of the parameters can be found inside the config.yaml file
#### 2. Analyzer: This is the main file responsible for report generation. It is suggested to tune the related configuration to your use.
#### 3. Results: Final visual and text results can be found under results folder.

<img width="1600" height="800" alt="2025-05-24_13-42-53_layer_stacks_1" src="https://github.com/user-attachments/assets/5682c9ae-60f4-4afa-84c0-00110b8d6588" />
<img width="1400" height="700" alt="iterations" src="https://github.com/user-attachments/assets/bce6d6b6-2c8b-4e0b-b95c-3019db44e7a2" />
<img width="1000" height="600" alt="2025-05-25_18-42-27_hist" src="https://github.com/user-attachments/assets/6bafdfd0-d789-4f05-b07b-57d46b7296ef" />
