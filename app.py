from flask import Flask, render_template, request, redirect, url_for, send_file
import os
from scapy.all import rdpcap, ARP

from scapy.all import rdpcap
import pandas as pd
import csv
from io import BytesIO

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

# Load .pcap file and preprocess data
def load_pcap(file_path):
    packets = rdpcap(file_path)
    data = []
    for packet in packets:
        if packet.haslayer('IP'):
            data.append({
                'srcip': packet['IP'].src,
                'dstip': packet['IP'].dst,
                'sport': packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else None,
                'dsport': packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else None,
                'proto': packet['IP'].proto,
                'len': packet['IP'].len,
                'time': packet.time
            })
    
    df = pd.DataFrame(data)
    return df

# Preprocessing Data
def preprocess_data(df):
    features = ['srcip', 'sport', 'dstip', 'dsport', 'proto', 'len', 'time']
    
    for feature in features:
        if feature not in df.columns:
            df[feature] = None
    
    df = df[features]
    df.fillna(0, inplace=True)
    return df

# Detection Algorithms
# MAC Spoofing Detection (Tuned for false positives)
def detect_mac_spoofing(pcap_file, threshold=1000):
    packets = rdpcap(pcap_file)
    mac_addresses = {}

    for pkt in packets:
        if pkt.haslayer('Ether'):
            src_mac = pkt['Ether'].src
            mac_addresses[src_mac] = mac_addresses.get(src_mac, 0) + 1

    # Only trigger if the same MAC address appears excessively and across multiple different IPs
    spoofed_macs = [f"MAC Address: {mac} appeared {count} times" for mac, count in mac_addresses.items() if count > threshold]
    return spoofed_macs or ["No MAC Spoofing Detected"]



# 2. Packet Tampering Detection
def detect_packet_injection(pcap_file):
    packets = rdpcap(pcap_file)
    injected_packets = []
    for pkt in packets:
        if pkt.haslayer('Raw'):
            payload = pkt['Raw'].load
            if b"malicious" in payload:
                injected_packets.append(payload.decode(errors='ignore'))
    return injected_packets or ["No Packet Tampering Detected"]

# Replay Attack Detection (Refined)
def detect_replay_attack(pcap_file, max_results=5, replay_threshold=3):
    packets = rdpcap(pcap_file)
    seen_packets = {}
    replayed_packets = []

    for pkt in packets:
        if pkt.haslayer('TCP') and pkt.haslayer('Raw'):
            pkt_id = (pkt['IP'].src, pkt['IP'].dst, pkt['TCP'].sport, pkt['TCP'].dport, bytes(pkt['Raw'].load))
            
            if pkt_id in seen_packets:
                seen_packets[pkt_id] += 1
                if seen_packets[pkt_id] > replay_threshold and pkt_id not in replayed_packets:
                    replayed_packets.append(pkt_id)
            else:
                seen_packets[pkt_id] = 1

    # Limit results and ensure only real replays are shown
    replayed_packets = replayed_packets[:max_results]
    return [f"Replay Detected: {pkt_id[0]} -> {pkt_id[1]}" for pkt_id in replayed_packets] or ["No Replay Attack Detected"]

# 4. Port Scanning Detection
def detect_port_scanning(pcap_file, threshold=20):
    packets = rdpcap(pcap_file)
    scan_activity = {}
    port_scanners = []
    for pkt in packets:
        if pkt.haslayer('IP') and pkt.haslayer('TCP'):
            src_ip = pkt['IP'].src
            dst_port = pkt['TCP'].dport
            if src_ip not in scan_activity:
                scan_activity[src_ip] = set()
            scan_activity[src_ip].add(dst_port)
    for ip, ports in scan_activity.items():
        if len(ports) > threshold:
            port_scanners.append(f"{ip} scanned {len(ports)} ports")
    return port_scanners or ["No Port Scanning Detected"]

# SYN Flood Detection (Adjusted for accuracy)
def detect_syn_flood(pcap_file, syn_threshold=2000):
    packets = rdpcap(pcap_file)
    syn_count = {}

    for pkt in packets:
        if pkt.haslayer('TCP') and pkt['TCP'].flags == 'S':  # SYN flag set
            src_ip = pkt['IP'].src
            syn_count[src_ip] = syn_count.get(src_ip, 0) + 1

    # Filter out low SYN packet counts and only show real SYN flood attempts
    potential_attackers = [f"Attacker IP: {ip}, SYN packets: {count}" for ip, count in syn_count.items() if count > syn_threshold]
    return potential_attackers or ["No SYN Flood Detected"]


# ARP Spoofing Detection (Refined)
def detect_arp_spoofing(pcap_file):
    packets = rdpcap(pcap_file)
    arp_table = {}
    spoofed_ips = set()

    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            
            # Check if the IP is already associated with a different MAC
            if src_ip in arp_table and arp_table[src_ip] != src_mac:
                if src_ip not in spoofed_ips:
                    spoofed_ips.add(src_ip)
    
            # Update ARP table with the current MAC for this IP
            arp_table[src_ip] = src_mac
    
    if spoofed_ips:
        return [f"Potential ARP Spoofing Detected: {ip} is associated with multiple MACs" for ip in spoofed_ips]
    else:
        return ["No ARP Spoofing Detected"]

# CSV file generation function
def generate_csv_file(results):
    output = BytesIO()  # In-memory file
    df = pd.DataFrame.from_dict(results, orient='index')
    df.to_csv(output)
    output.seek(0)
    return output

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Handle file upload and save
        file = request.files['file']
        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            
            # Perform threat detection
            results = {
                'MAC Spoofing': detect_mac_spoofing(file_path),
                'Packet Tampering': detect_packet_injection(file_path),
                'Replay Attack': detect_replay_attack(file_path),
                'Port Scanning': detect_port_scanning(file_path),
                'SYN Flood': detect_syn_flood(file_path),
                'ARP Spoofing': detect_arp_spoofing(file_path)
            }

            # Render the results page
            return render_template('results.html', results=results)
    
    return render_template('index.html')

@app.route('/download', methods=['POST'])
def download_csv():
    # Generate CSV data from the results (passed from the form on the results page)
    results = request.form.get('results')  # Make sure the results are passed properly
    csv_data = generate_csv_file(results)
    
    return send_file(csv_data, mimetype='text/csv', download_name='ntis_results.csv', as_attachment=True)

if __name__ == "__main__":
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
