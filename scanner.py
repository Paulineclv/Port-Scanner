import socket
import threading
import json
import argparse
import requests

KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    69: "TFTP",
    80: "HTTP",
    123: "NTP",
    161: "SNMP",
    443: "HTTPS",
    500: "IKE"
}

def detect_vulnerabilities(banner):
    # Improved list (example) - you can extend it
    known_vulnerabilities = {
        "ftp": {
            "vsftpd 2.3.4": "CVE-2011-2523 - Backdoor in vsFTPd 2.3.4",
        },
        "ssh": {
            "OpenSSH 7.2p2": "CVE-2016-0777 - Private key leakage via roaming",
        },
        "http": {
            "Apache 2.4.49": "CVE-2021-41773 - Path traversal and code execution",
            "Apache 2.4.50": "CVE-2021-42013 - RCE",
            "nginx 1.10.0": "CVE-2016-4450 - Buffer overflow via header",
        }
    }

    for service, versions in known_vulnerabilities.items():
        for version, cve in versions.items():
            if version.lower() in banner.lower():
                return f"[!] Vulnerability detected: {cve}"
    
    return None  # No known vulnerability found
    
# Banner retrieval function
def get_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(3)  # Increase timeout to 3 seconds
        s.connect((ip, port))
        
        # Send requests based on port to force a banner
        if port == 80:
            s.sendall(b"Get / HTTP/1.0\r\n\r\n")
        elif port == 25:
            s.sendall(b"HELO example.com\r\n")

        banner = s.recv(1024).decode(errors='ignore').strip()        
        s.close()
        return banner if banner else "Banner not retrieved"
    
    except socket.timeout:
        return f"Connection error: timeout for {ip}:{port}"
    except socket.gaierror:
        return f"Domain resolution error for {ip}:{port}"
    except Exception as e:
        return f"Error retrieving banner: {str(e)}"
    
# TCP port scanner with vulnerability detection
def scan_tcp(ip, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((ip, port))
        if result == 0:
            try:
                service = KNOWN_SERVICES.get(port, socket.getservbyport(port, "tcp") if port < 1024 else "Unknown")
            except OSError:
                service = "Unknown"
            banner = get_banner(ip, port)
            vulnerability = detect_vulnerabilities(banner)
            vuln_status = vulnerability if vulnerability else "No known vulnerability"
            print(f"[TCP] {ip}:{port} open ({service}) | {banner} | {vuln_status}")
            results.append({"ip": ip, "port": port, "protocol": "TCP", "service": service, "banner": banner, "vulnerability": vuln_status})    
        s.close()
    except socket.timeout:
        print(f"[TCP] {ip}:{port} timeout exceeded")
    except socket.gaierror:
        print(f"[TCP] domain resolution error for {ip}:{port}")
    except Exception as e:
        print(f"Error connecting to {ip}:{port} - {str(e)}")

# Basic UDP port scanner
def scan_udp(ip, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(b"",(ip, port))
        try:
            data, _ = s.recvfrom(1024)
            service = KNOWN_SERVICES.get(port, "Unknown")
            banner = data.decode(errors="ignore").strip() or "UDP response without banner"
            vulnerability = detect_vulnerabilities(banner)
            vuln_status = vulnerability if vulnerability else "No known vulnerability"
            print(f"[UDP] {ip}:{port} open ({service}) | {banner} | {vuln_status}")
            results.append({
                "ip": ip,
                "port": port,
                "protocol": "UDP",
                "service": service,
                "banner": banner,
                "vulnerability": vuln_status
            })
        except socket.timeout:
            print(f"[UDP] {ip}:{port} No response (could be closed or filtered)")
            # pass # No response, probably closed or filtered
        s.close()
    except socket.timeout:
        print(f"[UDP] {ip}:{port} timeout exceeded")
    except socket.gaierror:
        print(f"[UDP] Domain resolution error for {ip}:{port}")
    except Exception as e:
        print(f"UDP error {ip}:{port} - {str(e)}")

# Scan a range of ports
def scan_ports(ip, start_port, end_port, results, protocol="TCP"):
    print(f"\n{protocol.upper()} scan in progress on {ip} from {start_port} to {end_port}...\n")
    threads = []

    try:
        for port in range(start_port, end_port + 1):
            proto = protocol.upper()
            if proto == "TCP":
                t = threading.Thread(target=scan_tcp, args=(ip, port, results))
                threads.append(t)
                t.start()
            elif proto == "UDP":
                # Exclude ports 80 and 443 from UDP scan
                if port in [53, 123, 161, 514]:
                    t = threading.Thread(target=scan_udp, args=(ip, port, results))
                    threads.append(t)
                    t.start()
                elif port in [80, 443]:
                    print(f"[UDP] Port {port} : UDP is not commonly used here, scanning only in TCP.")
                else:
                    print(f"[UDP] Port {port} rarely used in UDP, skipping scan.")
            elif proto == "BOTH":
                t_tcp = threading.Thread(target=scan_tcp, args=(ip, port, results))
                t_udp = threading.Thread(target=scan_udp, args=(ip, port, results))

                # Optionally, display a warning for UDP scans on ports like 80 or 443
                if port in [80, 443]:
                    print(f"[BOTH] Port {port} : UDP rarely used, scanning anyway.")

                threads.extend([t_tcp, t_udp])
                t_tcp.start()
                t_udp.start()
            else:
                print(f"Unsupported protocol: {protocol}")
        
        for t in threads:
            t.join()

    except Exception as e:
        print(f"Error scanning ports: {str(e)}")

# Menu function
def display_menu():
    print("Welcome to the Port Scanner!")
    print("1. Scan TCP Ports")
    print("2. Scan UDP Ports")
    print("3. Scan Both TCP and UDP ports")
    print("4. Exit")

def get_user_choice():
    while True:
        choice = input("Please select an option (1-4): ")
        if choice in ['1', '2', '3', '4']:
            return choice
        else:
            print("Invalid option. Please try again.")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Port scanner with vulnerability detection")
    parser.add_argument("ip", help="Target IP address", nargs="?", default=None)
    parser.add_argument("start_port", type=int, nargs="?", default=None, help="Start port")
    parser.add_argument("end_port", type=int, nargs="?", default=None, help="End port")
    parser.add_argument("--protocol", choices=["TCP", "UDP", "BOTH"], default="TCP", help="Protocol to scan")
    parser.add_argument("--output", help="Export results to JSON", default=None)

    args = parser.parse_args()

    if args.ip is None or args.start_port is None or args.end_port is None:
        display_menu()
        choice = get_user_choice()

        if choice == "1":
            args.protocol = "TCP"
        elif choice == "2":
            args.protocol = "UDP"
        elif choice == "3":
            args.protocol = "BOTH"
        elif choice == "4":
            print("Exiting the scanner.")
            return

        # Ask the user for the IP and ports
        if args.ip is None:
            args.ip = input("Enter the target IP address: ")
        if args.start_port is None:
            args.start_port = int(input("Enter the starting port: "))
        if args.end_port is None:
            args.end_port = int(input("Enter the ending port: "))

    # Port validation
    if not (1 <= args.start_port <= 65535):
        print("Error: Start port must be between 1 and 65535.")
        return
    if not (1 <= args.end_port <= 65535):
        print("Error: End port must be between 1 and 65535.")
        return
    if args.start_port > args.end_port:
        print("Error: Start port cannot be greater than end port.")
        return

    # Start scanning the ports
    results = []
    scan_ports(args.ip, args.start_port, args.end_port, results, args.protocol)

    # If an output file is specified
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(f'\n Results saved in {args.output}')

if __name__ == "__main__":
    main()