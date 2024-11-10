# Packet Sniffer 🛠️

This **Packet Sniffer** is a C-based program developed as part of a Network Security class. It captures and analyzes network packets, providing detailed information about TCP, UDP, and IP headers, as well as payloads. The tool is a lightweight and functional example of packet sniffing, created to understand network traffic and security concepts.

---

## Features

- **Promiscuous Mode Capture**:
  - Captures packets on the specified network interface in promiscuous mode.
- **Protocol Parsing**:

  - Parses and displays details of IP, TCP, and UDP headers.
  - Extracts payload data from packets for inspection.

- **Real-Time Analysis**:

  - Inspects network traffic as it is captured.
  - Prints header information, such as source and destination IPs and ports, flags, and payloads.

- **Configurable Filters**:
  - Uses the Berkeley Packet Filter (BPF) to apply filtering expressions (e.g., capture only TCP packets on port 80).

---

## File Structure

- **`parse.h`**: Header file defining functions for parsing and analyzing packets.
- **`parse.c`**: Implements TCP, UDP, and payload parsing functions.
- **`sniff.c`**: Contains the main program logic, including pcap setup, packet filtering, and the packet capture loop.
- **`extra`**: Contains additional resources, utilities, or optional extensions for the program.

---

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/Steven-McGinnis/PacketSniff.git
   ```

2. **Navigate to the project directory**:

   ```bash
    cd PacketSniff
   ```

3. **Install Libpcap**:
   Ensure that the `libpcap` library is installed on your system. You can install it using the package manager of your choice:

   - **Debian/Ubuntu**:
     ```bash
     sudo apt-get install libpcap-dev
     ```

4. **Compile the Program**:
   Use `gcc` to compile the source files:

   ```bash
   gcc -o packet_sniffer sniff.c parse.c -lpcap
   ```

## Usage

1. **Run the Packet Sniffer: Execute the program with elevated privileges (required for capturing packets in promiscuous mode)**:

   ```bash
   sudo ./packet_sniffer
   ```

2. **View Captured Packets**:
   The program will begin capturing packets on the default network interface. You can view the parsed packet information in real-time.

   -Source and destination IP addresses.
   -Source and destination ports.
   -TCP/UDP flags.
   -Payload data.

3. **Modify Filters**:

   - You can customize the packet capture filter by editing the `filter_exp` variable in `sniff.c`. For example:
     ```c
     char filter_exp[] = "udp port 53"; // Capture only DNS traffic
     ```
   - Other examples:

     - Capture all HTTP traffic:
       ```c
       char filter_exp[] = "tcp port 80";
       ```
     - Capture all packets from a specific IP:
       ```c
       char filter_exp[] = "src host 192.168.1.1";
       ```

   - After editing the filter, recompile the program and rerun it.

---

## Example Output

### Sample TCP Packet

```bash
Source IP: 192.168.1.5
Destination IP: 192.168.1.10
Source Port: 34567
Destination Port: 80
Sequence Number: 12345678
Acknowledgment Number: 87654321
Flags: SYN ACK
Payload (34 bytes):
GET / HTTP/1.1
```

### Sample UDP Packet

```bash
Source IP: 10.0.0.2
Destination IP: 10.0.0.3
Source Port: 53
Destination Port: 12345
Payload (12 bytes):
......
```

---

## Example Output

### Port Scan Results:

```plaintext
Starting Port Scan
Port 22 Successfully Identified
Port 80 Successfully Identified
Port 443 Successfully Identified
Port 8080 Successfully Identified
Successful ports:
22
80
443
8080


```

Successful IP addresses:
192.168.0.1
192.168.0.100
192.168.0.200

---

## Limitations

- **Platform Dependency**: This tool is designed for Unix/Linux systems. For Windows, a compatible library like WinPcap or Npcap would be required.
- **Basic Filtering**: The capture filters are static and must be modified in the source code. Dynamic filter configuration at runtime is not currently supported.
- **No Persistent Storage**: The captured packet data is only displayed on the console and not stored for later analysis.

---

## Future Enhancements

- **Persistent Logging**: Add functionality to save captured packet details to a file (e.g., `.pcap` or `.txt` format).
- **Interactive Filters**: Enable users to input capture filters dynamically via the command line or a configuration file.
- **Multithreading**: Optimize performance by processing packets in parallel, especially for high-traffic environments.
- **Cross-Platform Compatibility**: Extend support for Windows by incorporating libraries like WinPcap or Npcap.
- **Visualization Tools**: Integrate packet visualization for easier analysis (e.g., using charts or flow diagrams).

---

## Acknowledgments

This project was created as part of a **Network Security** class to gain hands-on experience in network traffic analysis and packet inspection.

---

Feel free to explore, fork, and modify the project to suit your needs. Contributions and suggestions for improvement are welcome. Happy sniffing! 🚀

```

```
