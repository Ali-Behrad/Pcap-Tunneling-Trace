import xml.etree.ElementTree as ET
import subprocess
from collections import defaultdict
import json
import statistics

def pdml_creator(file_path : str, output_file : str) :
    with open(output_file, 'w') as f:
        subprocess.run([
                "tshark" , "-r", file_path, "-T", "pdml"
            ], stdout=f, check=True)

    print(f"PDML file generated: {output_file}")

def pdml_to_enhanced_stack_json_by_protocol(pdml_file, output_json_path):
    tree = ET.parse(pdml_file)
    root = tree.getroot()

    stack_packets = defaultdict(list) 
    protocol_stats = defaultdict(lambda: {'sizes': [], 'offsets': []})  

    for packet in root.findall('packet'):
        layers = []
        for proto in packet.findall('proto'):
            name = proto.attrib.get('name', '').upper()

            if name != "GENINFO" and name != "FRAME":
                pos = int(proto.attrib.get('pos', 0))
                size = int(proto.attrib.get('size', 0))
                layers.append({'name': name, 'offset': pos, 'size': size})
                protocol_stats[name]['sizes'].append(size)
                protocol_stats[name]['offsets'].append(pos)
        stack_key = tuple(layer['name'] for layer in layers)
        stack_packets[stack_key].append(layers)

    result_json = {}
    for i, (stack, packets) in enumerate(stack_packets.items(), start=1):
        stack_label = f"Stack {i}"
        count = len(packets)

        size_summary = []
        offset_summary = []
        is_size_equal = []
        is_offset_equal = []

        for proto_name in stack:
            sizes = protocol_stats[proto_name]['sizes']
            offsets = protocol_stats[proto_name]['offsets']

            size_eq = all(s == sizes[0] for s in sizes)
            offset_eq = all(o == offsets[0] for o in offsets)

            avg_size = sizes[0] if size_eq else round(statistics.mean(sizes))
            avg_offset = offsets[0] 

            size_summary.append(avg_size)
            offset_summary.append(avg_offset)
            is_size_equal.append(size_eq)
            is_offset_equal.append(offset_eq)

        result_json[stack_label] = {
            "name": "-".join(stack),
            "count": count,
            "size": size_summary,
            "offset": offset_summary,
            "isSizeEqual": is_size_equal,
            "isOffsetEqual": is_offset_equal
        }

    with open(output_json_path, 'w') as f:
        json.dump(result_json, f, indent=4)