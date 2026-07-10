import socket
import requests
import nmap
from datetime import datetime

# scans for open ports from desired range, and returns open ports into list to be used and output
def port_scan(target, start_port, end_port):
        print(f"Scanning target: {target} for open ports from {start_port} to {end_port} ...")
        open_ports = []
        for port in range(start_port, end_port):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                        open_ports.append(port)
                sock.close()
        return open_ports

# fetches the welcome banner on session connect
def grab_banner(target, port):
        print(f"Attempting to grab banner for {target}::{port}")
        try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((target,port))
                sock.settimeout(2)
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                return banner.strip()
        except:
                return None

#conducts network scanning and returns information
#regarding found open ports and banners for each ports found respectively
def network_scan(target, start_port, end_port):
        print(f"Starting network scanning services for target: {target} ... ")
        start_time = datetime.now()

        open_ports = port_scan(target, start_port, end_port)

        if open_ports:
                print(f"Open ports found: {open_ports}")
        else:
                print("No open ports found on target.")

        for port in open_ports:
                banner = grab_banner(target, port)
                if banner:
                        print(f"Banner was found for {target}::{port} --> {banner}")
                else:
                        print(f"No banner was found for {target}::{port}")


if __name__ == "__main__":
        target_ip = input("Enter target IP or Hostname to scan: ")
        start_port = int(input("Specify which port to start scanning from: "))
        end_port = int(input("Specify which port to end scan on: "))