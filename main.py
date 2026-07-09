import socket
import requests
import nmap
from datetime import datetime

def port_scan(target, start_port, end_port):
        print(f"Scanning target: {target} for open ports from {start_port} to {end_port} ...")
        open_ports = []

def network_scan(target, start_port, end_port):
        print(f"Starting network scanning services for target: {target} ... ")
        start_time = datetime.now()

        open_ports = port_scan(target, start_port, end_port)

        if open_ports:
                print(f"Open ports found: {open_ports}")
        else:
                print("No open ports found on target.")


if __name__ == "__main__":
        target_ip = input("Enter target IP or Hostname to scan: ")
        start_port = int(input("Specify which port to start scanning from: "))
        end_port = int(input("Specify which port to end scan on: "))