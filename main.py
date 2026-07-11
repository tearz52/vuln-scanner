import socket
import re
import nmap
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# scans for open ports from desired range, and returns open ports into list to be used and output
def port_scan(target, start_port, end_port):
    print(f"Scanning target: {target} for open ports from {start_port} to {end_port} ...")

    open_ports = []

    def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        sock.close()

        if result == 0:
            return port
        else:
            return None

    with ThreadPoolExecutor(max_workers=100) as executor:

        futures = []

        for port in range(start_port, end_port):
            future = executor.submit(check_port,port)
            futures.append(future)

        for future in as_completed(futures):
            result = future.result()

            if result is not None:
                open_ports.append(result)

    return open_ports

# fetches the welcome banner on session connect
def grab_banner(target, port):

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((target, port))
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                return port, banner.strip()
        except Exception:
                return port, None

def banner_scan(target, open_ports):
    print(f"Attempting to grab banners from open ports:{open_ports}")

    banners = {}

    with ThreadPoolExecutor(max_workers=100) as executor:

        futures = []

        for port in open_ports:
            future = executor.submit(grab_banner, target, port)
            futures.append(future)

        for future in as_completed(futures):
            port, banner = future.result()

            banners[port] = {
                "banner": banner
            }


    return banners

def parse_banner(banner):

    # in the case of empty banners
    if not banner:
        return {
            "service": None,
            "product": None,
            "version": None
        }

    # expected output for Apache banners
    if "Apache" in banner:
        match = re.search(r"Apache/([\d.]+)", banner)

        if match:
            version = match.group(1)
        else:
            version = None

        return {
            "service": "HTTP",
            "product": "Apache",
            "version": version
        }

    # in the case that the banner is unknown
    return {
        "service": None,
        "product": None,
        "version": None
    }


def vulnerability_scan(target):
        print(f"Scanning target \x1b[35m{target}\x1b[0m for exposed vulnerabilities... ")
        nm = nmap.PortScanner()
        try:
                nm.scan(hosts=target,arguments="-O -sV --script=vuln")
                return nm[target]
        except Exception as e:
                print(f"Error during vulnerability scan: {e}")
                return None


#conducts network scanning and returns information
#regarding found open ports and banners for each ports found respectively
def network_scan(target, start_port, end_port):
        print(f"Starting network scanning services for target: \x1b[35m{target}\x1b[0m ... ")
        start_time = datetime.now()

        open_ports = port_scan(target, start_port, end_port)

        if open_ports:
                print(f"Open ports found: {open_ports}")
        else:
                print("No open ports found on target.")

        banners = banner_scan(target, open_ports)

        for port in sorted(banners):
            banner = banners[port]["banner"]

            banners[port].update(parse_banner(banner))

            if banner:
                print(f"Banner found for \x1b[35m{target}\x1b[0m::\x1b[35m{port}\x1b[0m ")
                print(f"Port: {port}")
                print(f"Banner: {banners[port]['banner']}")
                print(f"Service: {banners[port]['service']}")
                print(f"Product: {banners[port]['product']}")
                print(f"Version: {banners[port]['version']}")
                print("-" * 40)
            else:
                print(f"No banner found for {target}::{port}")



        vuln_info = vulnerability_scan(target)
        if vuln_info:
                if 'hostnames' in vuln_info:
                        print(f"Hostnames: {vuln_info['hostnames']}")
                if 'osmatch' in vuln_info:
                        print(f"Operating System: {vuln_info['osmatch']}")
                if 'vulns' in vuln_info:
                        print(f"Vulnerabilities: {vuln_info['vulns']}")

        else:
                print("No vulnerabilities were able to be detected or is unable to be detected successfully.")

        end_time = datetime.now()
        print(f"Scan completed in: {end_time - start_time}")


if __name__ == "__main__":
        target_ip = input("Enter target IP or Hostname to scan: ")
        start_port = int(input("Specify which port to start scanning from: "))
        end_port = int(input("Specify which port to end scan on: "))

        network_scan(target_ip, start_port, end_port)