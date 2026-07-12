import os
import socket
import re
from os import environ

import requests
import nmap
import nvdlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

NVD_API_KEY = os.getenv("NVD_API_KEY")

logo = r"""

⠄⣾⣿⡇⢸⣿⣿⣿⠄⠈⣿⣿⣿⣿⠈⣿⡇⢹⣿⣿⣿⡇⡇⢸⣿⣿⡇⣿⣿⣿
⢠⣿⣿⡇⢸⣿⣿⣿⡇⠄⢹⣿⣿⣿⡀⣿⣧⢸⣿⣿⣿⠁⡇⢸⣿⣿⠁⣿⣿⣿
⢸⣿⣿⡇⠸⣿⣿⣿⣿⡄⠈⢿⣿⣿⡇⢸⣿⡀⣿⣿⡿⠸⡇⣸⣿⣿⠄⣿⣿⣿
⢸⣿⡿⠷⠄⠿⠿⠿⠟⠓⠰⠘⠿⣿⣿⡈⣿⡇⢹⡟⠰⠦⠁⠈⠉⠋⠄⠻⢿⣿
⢨⡑⠶⡏⠛⠐⠋⠓⠲⠶⣭⣤⣴⣦⣭⣥⣮⣾⣬⣴⡮⠝⠒⠂⠂⠘⠉⠿⠖⣬
⠈⠉⠄⡀⠄⣀⣀⣀⣀⠈⢛⣿⣿⣿⣿⣿⣿⣿⣿⣟⠁⣀⣤⣤⣠⡀⠄⡀⠈⠁
⠄⠠⣾⡀⣾⣿⣧⣼⣿⡿⢠⣿⣿⣿⣿⣿⣿⣿⣿⣧⣼⣿⣧⣼⣿⣿⢀⣿⡇⠄
⡀⠄⠻⣷⡘⢿⣿⣿⡿⢣⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣜⢿⣿⣿⡿⢃⣾⠟⢁⠈
⢃⢻⣶⣬⣿⣶⣬⣥⣶⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣷⣶⣶⣾⣿⣷⣾⣾⢣
                     .--.           
                     |__|           
             .-,.--. .--.           
       __    |  .-. ||  |    __     
    .:--.'.  | |  | ||  | .:--.'.   
   / |   \ | | |  | ||  |/ |   \ |  
   `" __ | | | |  '- |  |`" __ | |  
    .'.''| | | |     |__| .'.''| |  
   / /   | |_| |         / /   | |_ 
   \ \._,\ '/|_|         \ \._,\ '/ 
    `--'  `"              `--'  `"  

"""


def logo_launch():
    print(f"\033[38;5;135m{logo}\033[0m")
    print("\033[38;5;135mAria Scanner \x1b[38;5;214mv1.0.0\x1b[0m \033[38;5;135minitialized.\033[0m\n")


# scans for open ports from desired range, and returns open ports into list to be used and output
def port_scan(target, start_port, end_port):
    print(
        f"Scanning target: \x1b[38;5;214m{target}\x1b[0m for open ports from \x1b[38;5;214m{start_port}\x1b[0m to \x1b[38;5;214m{end_port}\x1b[0m ...")

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
            future = executor.submit(check_port, port)
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

            sock.settimeout(1)
            sock.connect((target, port))

            try:
                response = sock.recv(4096).decode("utf-8", errors="ignore")

                if response.strip():
                    return port, response.strip()

            except socket.timeout:
                pass

            # If no banner try  HTTP request
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: \x1b[38;5;214m{target}\x1b[0m\r\n"
                "Connection: close\r\n\r\n"
            )

            sock.send(request.encode())

            response = sock.recv(4096).decode("utf-8", errors="ignore")

            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    return port, line.replace("Server:", "").strip()

            return port, None

    except Exception:
        return port, None


def banner_scan(target, open_ports):
    print(f"Attempting to grab banners from open ports:\x1b[38;5;214m{open_ports}\x1b[0m")

    banners = {}

    with ThreadPoolExecutor(max_workers=100) as executor:

        futures = []

        for port in open_ports:
            future = executor.submit(grab_banner, target, port)
            futures.append(future)

        for future in as_completed(futures):
            port, banner = future.result()

            banners[port] = {
                "banner": banner,
                "service": None,
                "product": None,
                "version": None,
                "cve": [],
                "risk": None
            }

    return banners


def parse_banner(banner):
    if not banner:
        return {
            "service": None,
            "product": None,
            "version": None
        }

    if "Apache" in banner:
        match = re.search(r"Apache/([\d.]+)", banner)

        return {
            "service": "HTTP",
            "product": "Apache",
            "version": match.group(1) if match else None
        }


    elif "nginx" in banner.lower():
        match = re.search(r"nginx/([\d.]+)", banner, re.IGNORECASE)

        return {
            "service": "HTTP",
            "product": "nginx",
            "version": match.group(1) if match else None
        }


    elif "OpenSSH" in banner:
        match = re.search(r"OpenSSH[_/]([\d.]+)", banner)

        return {
            "service": "SSH",
            "product": "OpenSSH",
            "version": match.group(1) if match else None
        }


    elif "vsFTPd" in banner:
        match = re.search(r"vsFTPd\s([\d.]+)", banner)

        return {
            "service": "FTP",
            "product": "vsFTPd",
            "version": match.group(1) if match else None
        }


    elif "ProFTPD" in banner:
        match = re.search(r"ProFTPD\s([\d.a-zA-Z]+)", banner)

        return {
            "service": "FTP",
            "product": "ProFTPD",
            "version": match.group(1) if match else None
        }


    elif "Microsoft-IIS" in banner:
        match = re.search(r"Microsoft-IIS/([\d.]+)", banner)

        return {
            "service": "HTTP",
            "product": "Microsoft IIS",
            "version": match.group(1) if match else None
        }


    elif "MySQL" in banner:
        match = re.search(r"([\d.]+).*MySQL", banner)

        return {
            "service": "MySQL",
            "product": "MySQL",
            "version": match.group(1) if match else None
        }


    elif "PostgreSQL" in banner:
        match = re.search(r"PostgreSQL\s([\d.]+)", banner)

        return {
            "service": "PostgreSQL",
            "product": "PostgreSQL",
            "version": match.group(1) if match else None
        }


    elif "Samba" in banner:
        match = re.search(r"Samba.*?([\d.]+)", banner)

        return {
            "service": "SMB",
            "product": "Samba",
            "version": match.group(1) if match else None
        }


    elif "Redis" in banner:
        match = re.search(r"Redis.*?v=([\d.]+)", banner)

        return {
            "service": "Redis",
            "product": "Redis",
            "version": match.group(1) if match else None
        }

    elif "telnet" in banner.lower() or "login:" in banner.lower():
        return {
            "service": "Telnet",
            "product": "Telnet",
            "version": None
        }

    return {
        "service": None,
        "product": None,
        "version": None
    }


def cve_lookup(product, version):
    if not product or not version:
        return []

    query = f"{product} {version}"

    try:

        results = nvdlib.searchCVE(
            keywordSearch=query,
            key=NVD_API_KEY,
            limit=5
        )

        cves = []

        for cve in results:

            score = None
            severity = None

            # for CVSS v3.1
            if hasattr(cve, "v31score"):
                score = cve.v31score
                severity = cve.v31severity

            #  CVSS v3.0
            elif hasattr(cve, "v30score"):
                score = cve.v30score
                severity = cve.v30severity

            #  CVSS v2
            elif hasattr(cve, "v2score"):
                score = cve.v2score
                severity = cve.v2severity

            cves.append({

                "id": cve.id,

                "score": score,

                "severity": severity,

                "description":cve.descriptions[0].value

            })

        return cves

    except Exception as e:
        print(e)
        return []


# conducts network scanning and returns information
# regarding found open ports and banners for each ports found respectively
def network_scan(target, start_port, end_port):
    print(f"Starting network scanning services for target: \x1b[38;5;214m{target}\x1b[0m ... ")
    start_time = datetime.now()

    open_ports = port_scan(target, start_port, end_port)

    if open_ports:
        print(f"Open ports found: \x1b[38;5;214m{open_ports}\x1b[0m")
    else:
        print("\x1b[91mNo open ports found on target.\x1b[0m")

    banners = banner_scan(target, open_ports)

    for port in sorted(banners):
        banner = banners[port]["banner"]

        banners[port].update(parse_banner(banner))

        if banner:
            print(f"Banner found for \x1b[38;5;214m{target}\x1b[0m::\x1b[38;5;214m{port}\x1b[0m ")
            print(f"Port: \x1b[38;5;214m{port}\x1b[0m")
            print(f"Banner: \x1b[38;5;214m{banners[port]['banner']}\x1b[0m")
            print(f"Service: \x1b[38;5;214m{banners[port]['service']}\x1b[0m")
            print(f"Product: \x1b[38;5;214m{banners[port]['product']}\x1b[0m")
            print(f"Version: \x1b[38;5;214m{banners[port]['version']}\x1b[0m")
            print("-" * 40)
        else:
            print(f"\x1b[91mNo banner found for\x1b[0m \x1b[38;5;214m{target}\x1b[0m::\x1b[38;5;214m{port}\x1b[0m")

        product = banners[port]["product"]
        version = banners[port]["version"]

        cves = cve_lookup(product, version)

        banners[port]["cve"] = cves

        if cves:
            print("Vulnerabilities Found:")

            for cve in cves:
                print(f"ID: \x1b[38;5;214m{cve['id']}\x1b[0m")
                print(f"Severity: \x1b[91m{cve['severity']}\x1b[0m")
                print(f"CVSS: \x1b[38;5;214m{cve['score']}\x1b[0m")
                print(f"Description: {cve['description']}")
                print("-" * 30)

        else:
            print("\x1b[91mNo vulnerabilities were able to be detected or is unable to be detected successfully.\x1b[0m")

    end_time = datetime.now()
    print(f"Scan completed in: \x1b[38;5;214m{end_time - start_time}\x1b[0m")


if __name__ == "__main__":
    logo_launch()
    target_ip = input("\x1b[38;5;214mEnter target IP or Hostname to scan:\x1b[0m ")
    start_port = int(input("\x1b[38;5;214mSpecify which port to start scanning from:\x1b[0m "))
    end_port = int(input("\x1b[38;5;214mSpecify which port to end scan on:\x1b[0m "))

    network_scan(target_ip, start_port, end_port)