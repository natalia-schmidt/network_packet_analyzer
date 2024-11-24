
# Network Packet Analyzer

A lightweight network packet analyzer written in C that captures and decodes Ethernet, IP, TCP, and UDP packets. It detects packet payload types such as HTTP requests and images (JPEG, PNG).

## Features

- **Ethernet Header Parsing**:
  - Extracts source and destination MAC addresses.
  - Identifies the Ethernet protocol.

- **IP Header Decoding**:
  - Displays source and destination IP addresses.
  - Identifies the protocol (TCP, UDP, or others).

- **TCP/UDP Header Parsing**:
  - For TCP:
    - Extracts source and destination ports.
    - Displays sequence and acknowledgment numbers.
    - Detects HTTP requests and other payload types (e.g., images).
  - For UDP:
    - Extracts source and destination ports.
    - Displays packet length.

- **Payload Detection**:
  - Recognizes HTTP requests.
  - Identifies JPEG and PNG image files.
  - Reports other types of binary data.

## Requirements

- **Operating System**: Linux (required for raw socket functionality).
- **Privileges**: Root access to run the program.

## Compilation and Execution

1. Compile the program:
   ```bash
   gcc -o packet_analyzer main.c
   ```

2. Run the program with root privileges:
   ```bash
   sudo ./packet_analyzer
   ```

3. To stop capturing packets, press `Ctrl+C`.

## Output Example

When a valid packet is captured, the program displays the following details:

```plaintext
==============================
      Packet Captured
==============================
--- Ethernet Header ---
Destination MAC: 01:23:45:67:89:ab
Source MAC: ab:cd:ef:01:23:45
Protocol: 0x0800

--- IP Header ---
Source IP: 192.168.1.100
Destination IP: 192.168.1.1
Protocol: 6

--- TCP Protocol Detected ---
Source Port       : 443
Destination Port  : 51432
Sequence Number   : 12345678
Acknowledgment No : 87654321

Payload Type: HTTP Request
```

## How It Works

1. **Raw Socket**: Captures all network packets traversing the network interface.
2. **Ethernet Decoding**: Analyzes Ethernet frame headers to identify the protocol (e.g., IP).
3. **IP Decoding**: Extracts IP-level information such as addresses and protocols (TCP/UDP).
4. **Transport Layer Decoding**:
   - For TCP: Extracts ports, sequence numbers, and payload information.
   - For UDP: Extracts ports and length.
5. **Payload Analysis**: Identifies specific payload types (e.g., HTTP requests, JPEG/PNG images).

## License

This project is licensed under the MIT License. Feel free to modify and distribute it as needed.
