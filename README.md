# Port Scanner with Vulnerability Detection

This is a simple port scanner that supports both TCP and UDP protocols, with the ability to detect potential vulnerabilities based on service banners. It allows you to scan a range of ports on a target IP address and check for known vulnerabilities based on the banner retrieved from the open ports.

## Features

- **TCP and UDP support**: You can scan both TCP and UDP ports, or choose to scan one protocol at a time.
- **Vulnerability detection**: The scanner checks the banners returned by the services running on the open ports for known vulnerabilities (e.g., CVE entries).
- **Banner retrieval**: The tool attempts to retrieve banners from various services (HTTP, FTP, SMTP, etc.) for analysis.
- **Multithreading**: The scanner uses threads to scan multiple ports simultaneously for improved performance.
- **JSON output**: Results can be saved in a JSON file for further analysis.

## Known Vulnerabilities

The scanner currently includes a set of known vulnerabilities for several common services, such as:

- **FTP**: `vsftpd 2.3.4` - CVE-2011-2523 (Backdoor in vsFTPd 2.3.4)
- **SSH**: `OpenSSH 7.2p2` - CVE-2016-0777 (Private key leak via roaming)
- **HTTP**: `Apache 2.4.49` - CVE-2021-41773 (Path traversal and code execution)

This list can be extended to include more services and vulnerabilities.

## Installation

Clone the repository:

     git clone https://github.com/yourusername/port-scanner.git
     cd port-scanner

## Usage

You can use the script via command line or through an interactive menu.

## Command Line Usage

Run the script with the following command:

    python port_scanner.py <target_ip> <start_port> <end_port> [--protocol TCP|UDP|BOTH] [--output     output.json
    
- <target_ip>: The IP address of the target to scan.
- <start_port>: The starting port number to scan.
- <end_port>: The ending port number to scan.
- --protocol: (Optional) The protocol to scan. Can be TCP, UDP, or BOTH. Default is TCP.
- --output: (Optional) The file to save the results in JSON format.

      python port_scanner.py 192.168.1.1 1 1024 --protocol BOTH --output results.json
  
This will scan both TCP and UDP ports from 1 to 1024 on IP address 192.168.1.1 and save the results in results.json.

## Interactive Menu

If you prefer to interact with the program, you can simply run:

    python port_scanner.py

The program will prompt you to select the scanning options through a menu:

1. Scan TCP Ports
2. Scan UDP Ports
3. Scan Both TCP and UDP Ports
4. Exit

You will also be prompted to enter the target IP address and port range.

## Output Format

The results will be displayed in the terminal, and if you choose to save the results to a file, they will be saved in the following JSON format:

    [
        {
            "ip": "192.168.1.1",
            "port": 80,
            "protocol": "TCP",
            "service": "HTTP",
            "banner": "HTTP/1.1 200 OK",
            "vulnerability": "CVE-2021-41773 - Path traversal and code execution"
        },
        ...
    ]

- ip: Target IP address.
- port: The port that was open.
- protocol: TCP or UDP.
- service: The service running on the port (e.g., HTTP, FTP).
- banner: The banner returned by the service (if available).
- vulnerability: Known vulnerabilities based on the banner (if applicable).

 ## Contributing

If you want to contribute to the project, feel free to fork the repository, submit issues, or create pull requests. You can help by adding more known vulnerabilities or improving the scanner's performance.
