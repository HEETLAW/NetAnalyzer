# NetAnalyzer

NetAnalyzer is an advanced network packet analyzer designed to capture and analyze network packets. This tool provides real-time packet sniffing, packet analysis, and the option to export captured packets to a file for further examination.

---
## Key Features:

- Real-Time Packet Sniffing:
  - Captures network packets in real-time.
- Packet Analysis:
  - Analyzes captured packets to extract source and destination IP addresses, protocols, and payload data.
- Export Captured Packets:
  - Allows users to export captured packets to a file for further analysis.

---
## How to Get and Use NetAnalyzer

### Step 1: Clone the Repository

**Open Terminal**: Open your terminal (Command Prompt, PowerShell, or any terminal you use).

**Clone the Repository**: Use the `git clone` command followed by the URL of your GitHub repository.

```
git clone https://github.com/YOUR_USERNAME/NetAnalyzer.git
```

### Step 2: Navigate to the Repository Directory

```
cd NetAnalyzer
```

### Step 3: Ensure Required Dependencies are Installed

Ensure you have Python installed. Additionally, install the necessary Python packages using pip:

```
pip install scapy
```

### Step 4: Run the Script

You can now run the NetAnalyzer tool. Assuming your main script is named `netanalyzer.py`, you would run:

```
python netanalyzer.py
```

### Step 5: Using the Tool

Follow the command-line interface to use the NetAnalyzer functionalities:

- Enter the interface to sniff packets (e.g., eth0, wlan0).
- Enter the number of packets to sniff.
- Optionally, enter the protocol to filter (e.g., tcp, udp).
- Press 'y' to export captured packets to a file or 'n' to skip.

## Example Usage

```
=== NetAnalyzer ===
Enter the interface to sniff packets (e.g., eth0, wlan0): eth0
Enter the number of packets to sniff: 100
Enter the protocol to filter (optional, e.g., tcp, udp): tcp
[*] Sniffing packets on interface eth0...
[*] Packet Sniffing complete.
[*] Analyzing captured packets:
=================================
Source IP: 192.168.1.10 | Destination IP: 8.8.8.8 | Protocol: 6
Payload Data: b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n'
=================================
Do you want to export packet data? (y/n): y
Enter the filename to save the packet data: packets.txt
[*] Captured packets saved to packets.txt
```

---
