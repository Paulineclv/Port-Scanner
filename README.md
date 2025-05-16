# 🔍 Port Scanner with Vulnerability Detection

This Python-based port scanner allows scanning a range of TCP and UDP ports on a target IP address. It also includes **banner grabbing** and **basic vulnerability detection** using known CVEs. The tool can be used via **command-line** or a **user-friendly interactive menu**.

---

## ✨ Features

-   **TCP and UDP support**: Scan TCP, UDP, or both protocols.
-   **Banner grabbing**: Attempts to retrieve banners from open ports (e.g., HTTP, FTP, SMTP).
-   **Vulnerability detection**: Compares retrieved banners with a known list of CVEs.
-   **Multithreaded scanning**: Faster port scanning using threading.
-   **Interactive or CLI mode**: Choose between guided input or full command-line arguments.
-   **JSON export**: Scan results can be saved to a JSON file.
-   **Timestamped logs**: Scans include the execution timestamp for easier tracking.
-   **Improved logging and output formatting**.

---

## 🛡️ Known Vulnerabilities Detected

The scanner currently checks for known vulnerabilities based on service banners. Examples include:

-   **FTP**: `vsftpd 2.3.4` — CVE-2011-2523 (Backdoor vulnerability)
-   **SSH**: `OpenSSH 7.2p2` — CVE-2016-0777 (Private key leak via roaming)
-   **HTTP**: `Apache 2.4.49` — CVE-2021-41773 (Path traversal and code execution)

> You can easily extend the list by updating the `known_vulnerabilities` dictionary in the code.

---

## 💻 Installation

```bash
git clone https://github.com/Paulineclv/Port-Scanner.git
cd Port-Scanner
```

---

## 🧪 Usage

### Option 1: Command-Line Mode

```bash
python port_scanner.py <target_ip> <start_port> <end_port> [--protocol TCP|UDP|BOTH] [--output output.json]
```

-   `<target_ip>`: Target IP address to scan
-   `<start_port>`: Start of the port range
-   `<end_port>`: End of the port range
-   `--protocol`: _(Optional)_ TCP, UDP, or BOTH (default is TCP)
-   `--output`: _(Optional)_ Save results to a JSON file

**Example:**

```bash
python port_scanner.py 192.168.1.1 1 1024 --protocol BOTH --output results.json
```

---

### Option 2: Interactive Menu Mode

Simply run the script:

```bash
python port_scanner.py
```

You will be prompted to:

1. Scan TCP Ports
2. Scan UDP Ports
3. Scan Both TCP and UDP Ports
4. Exit

The program will then ask for the IP address and port range.

---

## 📄 Output Format

Results are shown in the terminal and optionally saved in JSON format:

```json
[
    {
        "ip": "192.168.1.1",
        "port": 80,
        "protocol": "TCP",
        "service": "HTTP",
        "banner": "HTTP/1.1 200 OK",
        "vulnerability": "CVE-2021-41773 - Path traversal and code execution"
    }
]
```

**Fields:**

-   `ip`: Target IP address
-   `port`: Open port
-   `protocol`: TCP or UDP
-   `service`: Service name (if identified)
-   `banner`: Banner retrieved from the service
-   `vulnerability`: Matching known CVE (if applicable)

---

## 🤝 Contributing

Feel free to contribute by:

-   Improving banner parsing or fingerprinting
-   Adding more known vulnerabilities (CVEs)
-   Enhancing the scanning speed or detection logic

Fork the repo, open an issue, or submit a pull request!

---

## 🧠 Note

This tool is for educational or ethical testing purposes only. Always ensure you have permission to scan a target.
