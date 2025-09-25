from scapy.all import *
from scapy.utils import PcapReader, PcapWriter
import random
import sys
import time

#TODO: EXTRACT SIP AND RTP PACKETS

def generate_packets():
    rtp_header = bytes([
        0x80, 0x60,             # Version 2, Payload type 96 (dynamic)
        0x00, 0x01,             # Sequence Number: 1
        0x00, 0x00, 0x00, 0x01, # Timestamp: 1
        0x00, 0x00, 0x00, 0x01  # SSRC: 1
    ])
    rtp_payload = b'\x11\x22\x33\x44'
    rtp_packet = rtp_header + rtp_payload

    # pkt = Ether(dst="00:11:22:33:44:55", type=0x0800)/UDP(dport=5004)/IP(dst="8.8.8.8")/Raw(load=rtp_packet)
    pkt =  Ether(dst="00:11:22:33:44:55", type=0x0800)/IP(dst="8.8.8.8")/UDP(dport=5004)/GRE()/Ether(dst="00:11:22:33:44:55", type=0x0800)/IP(dst="8.8.8.8")
    return pkt

def inject_packets(target_pcap, new_pcap, custom_packets):
    original_packets = list(PcapReader(target_pcap))

    injection_points = sorted(
        random.sample(range(len(original_packets)), len(custom_packets)),
        reverse=True
    )

    for idx, packet in zip(injection_points, custom_packets):
        original_packets.insert(idx, packet)
    
    with PcapWriter(new_pcap) as writer:
        for pkt in original_packets:
            writer.write(pkt)


custom_packets = [generate_packets() for _ in range(15)]

inject_packets("./captured_pcaps/out.pcap", sys.argv[1], custom_packets)