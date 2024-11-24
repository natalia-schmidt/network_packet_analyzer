
# Network Packet Analyzer

A ***Network Protocol Analyzer*** written in C that captures, processes, and analyzes packets directly from the network. This program breaks down network traffic into its fundamental layers (Ethernet, IP, and Transport) and provides detailed insights into the structure and contents of each packet.

## Features
- Captures network packets in real-time using raw sockets.
- Analyzes and displays:
  - Ethernet headers (source and destination MAC addresses).
  - IP headers (source and destination IP addresses, protocol type).
  - Transport headers (TCP/UDP ports and metadata).
  - Payload type detection (e.g., HTTP, image formats like JPEG and PNG).
- Filters out invalid packets and loopback traffic.
- Dynamically decodes and identifies common payloads.

---

## Getting Started
### Prerequisites
- A Unix-based operating system (e.g., Linux).
- GCC compiler to compile the program.
- Root privileges to access raw sockets.

### Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-protocol-analyzer.git
cd network-protocol-
```
2. Compile the program:
```bash
gcc -o protocol_analyzer main.c
```
3. Run the program with root privileges:
```bash
sudo ./protocol_analyzer
```

---

## Usage
The program runs continuously, capturing and displaying packet details in real-time. To stop the execution, use `Ctrl+C`.

### Example Output
If a packet is captured:
```yaml
[Ethernet]
Source MAC: 00:14:22:01:23:45
Destination MAC: 00:16:36:7A:8C:3D

[IP]
Source IP: 192.168.1.10
Destination IP: 172.217.11.206
Protocol: TCP

[TCP]
Source Port: 56789
Destination Port: 80 (HTTP)
Payload Type: HTTP Request
```

---

## How It Works
1. Packet Capture:
  The program uses a raw socket to intercept all incoming and outgoing packets visible to the network interface.

2. Packet Processing:
  Each packet is broken into its layers:
  - Ethernet Header: Contains MAC addresses and protocol type.
  - IP Header: Includes source/destination IPs and higher-layer protocol (e.g., TCP/UDP).
  - Transport Header: Shows ports and specific metadata for TCP/UDP protocols.
  - Payload: Attempts to classify data types (e.g., HTTP, JPEG).
3. Packet Display:
  Information from each layer is printed in a structured format for easy readability.

--- 

## Limitations
- Only works with unencrypted traffic (e.g., HTTP, not HTTPS).
- Requires root access to use raw sockets.
- Captures only packets visible to the local network interface.

## Future Improvements
- Add support for deeper protocol analysis (e.g., DNS, FTP).
- Include a graphical interface for packet visualization.
- Implement traffic filtering by IP, port, or protocol.

## Acknowledgments
- Inspired by popular tools like Wireshark and tcpdump.
- Created as a learning tool to understand network protocols.
