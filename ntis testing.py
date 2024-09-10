from flask import Flask, render_template, request, redirect, url_for, send_file
import os
import csv
from app import detect_mac_spoofing, detect_packet_tampering, detect_replay_attack, detect_port_scanning, detect_syn_flood, detect_arp_spoofing
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Define the Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Handle file upload and save
        file = request.files['file']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Run detection algorithms
        results = {
            'MAC Spoofing': detect_mac_spoofing(file_path),
            'Packet Tampering': detect_packet_tampering(file_path),
            'Replay Attack': detect_replay_attack(file_path),
            'Port Scanning': detect_port_scanning(file_path),
            'SYN Flood': detect_syn_flood(file_path),
            'ARP Spoofing': detect_arp_spoofing(file_path),
        }

        

        # Save results to a CSV file
        csv_file = f"{file.filename}_results.csv"
        with open(csv_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Attack Type', 'Detected'])
            for attack, detected in results.items():
                writer.writerow([attack, "Yes" if detected else "No"])

        # Automatically trigger download of CSV results
        return send_file(csv_file, as_attachment=True)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
