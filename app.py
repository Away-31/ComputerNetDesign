from flask import Flask, render_template, request, redirect, url_for, send_file
from scapy.all import *
import os
import datetime
from scapy.layers.inet import IP, TCP, UDP
import tempfile

app = Flask(__name__)


def parse_pcap_file(pcap_file):
    """解析PCAP文件并提取IP数据包信息"""
    if not os.path.exists(pcap_file):
        return [], {}
    try:
        packets = rdpcap(pcap_file)
        ip_packet_count = 0
        protocol_count = {}
        packet_info = []
        for i, packet in enumerate(packets):
            if IP in packet:
                ip_packet_count += 1
                ip_layer = packet[IP]
                info = {
                    "packet_num": i + 1,
                    "capture_time": packet.time,
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "ip_version": ip_layer.version,
                    "ihl": ip_layer.ihl,
                    "tos": ip_layer.tos,
                    "total_len": ip_layer.len,
                    "id": ip_layer.id,
                    "flags": ip_layer.flags,
                    "frag": ip_layer.frag,
                    "ttl": ip_layer.ttl,
                    "proto": ip_layer.proto,
                    "tcp_info": None,
                    "udp_info": None,
                    "raw_data": None
                }

                if ip_layer.proto not in protocol_count:
                    protocol_count[ip_layer.proto] = 1
                else:
                    protocol_count[ip_layer.proto] += 1

                if TCP in packet:
                    tcp_layer = packet[TCP]
                    info["tcp_info"] = {
                        "sport": tcp_layer.sport,
                        "dport": tcp_layer.dport,
                        "seq": tcp_layer.seq,
                        "ack": tcp_layer.ack,
                        "dataofs": tcp_layer.dataofs,
                        "flags": tcp_layer.flags,
                        "window": tcp_layer.window
                    }
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    info["udp_info"] = {
                        "sport": udp_layer.sport,
                        "dport": udp_layer.dport,
                        "len": udp_layer.len
                    }

                if Raw in packet:
                    raw_data = packet[Raw].load
                    if len(raw_data) > 0:
                        hex_data = raw_data.hex()
                        formatted_hex = ""
                        for i in range(0, len(hex_data), 32):
                            formatted_hex += hex_data[i:i + 32] + "\n"
                        info["raw_data"] = formatted_hex

                packet_info.append(info)

        return packet_info, protocol_count

    except Exception as e:
        return [], {}


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'pcap_file' not in request.files:
            return redirect(request.url)
        file = request.files['pcap_file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            temp_dir = tempfile.mkdtemp()
            pcap_file_path = os.path.join(temp_dir, file.filename)
            file.save(pcap_file_path)
            packet_info, protocol_count = parse_pcap_file(pcap_file_path)
            return render_template('result.html', packet_info=packet_info, protocol_count=protocol_count)
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)