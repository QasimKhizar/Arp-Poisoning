# ARP Poisoning Tool

This is an ARP poisoning script written in Python using Scapy and multiprocessing. It allows an attacker to intercept network traffic between a victim and a gateway by sending spoofed ARP packets.

## Features
- Spoofs ARP packets to perform MITM (Man-in-the-Middle) attacks.
- Uses multiprocessing to simultaneously poison and sniff traffic.
- Captures network packets and saves them in a `.pcap` file for later analysis.
- Restores ARP tables after execution to minimize network disruption.

## Requirements
- Python 3
- Scapy

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/arp-poisoning-tool.git
   cd arp-poisoning-tool
   ```
2. Install required dependencies:
   ```bash
   pip install scapy
   ```

## Usage
Run the script with the following arguments:
```bash
sudo python3 arp_poison.py <victim_ip> <gateway_ip> <interface>
```
Example:
```bash
sudo python3 arp_poison.py 192.168.1.100 192.168.1.1 eth0
```

## How It Works
1. **Getting MAC Addresses**: The script sends ARP requests to retrieve the MAC addresses of the victim and gateway.
2. **Poisoning**: It sends ARP responses to both the victim and gateway, making them believe the attacker's machine is the other party.
3. **Sniffing**: The script captures packets flowing between the victim and gateway.
4. **Restoring**: When stopped, the script restores the original ARP tables.

## Disclaimer
This tool is intended for educational and ethical testing purposes only. Unauthorized use on networks without permission is illegal and punishable by law.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author
[Qasim Khizar](https://github.com/yourusername)


