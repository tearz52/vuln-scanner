import os
import socket
import re
from os import environ

import requests
import nmap
import nvdlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

NVD_API_KEY = os.environ.get("247706c8-92e5-48c5-900a-57672bf0b82a")

logo = r"""

######******#%%%%%%%%%%%%%%###***####%%%##########****++++****++++++++++*%%%####
******####%%%%%%%%%%%%%%%%%###+===+++========+++++++++++++#%**##################
*****######%%%%%%%%%%%%%##*=++++++++*+++++++==--=++*#####%%%%%%#########**++++++
*********##%%%%%%%%%%###+=+==++====++++==+==++==----####%%%%%*++=====++###*++++*
+++++******###***%%%@#+=====+==-----=====+==-==+==---=++%%#*%@@@@@@@@@#*+++===--
+++++++++++++++++**%#+========----:---==--====-=-=+-==-*@@@@@@@@@@@@@@-.....:.  
+++++++*%@@@@@@@@@@+==========-:--:----==----=--====----+@%**=++###@@@::::--====
+++++++#@@@@@@@@%#*+==-=--=+=---:-:-----==--::----=+==---=#@+*==-++++++++++++=++
++++++++%@%%*+++++=====---+*=--:::::------=--::=-===+=-===+%@+*--==+++++++++++++
+++++===========+++==----=+=-=--::::---------:-:---=++=-=*+#@%++--=++++++++++++=
+++==========+-=++==-----======--:-::=----=-==:-:-=-=++=-+#*@@%+---+++==---==*+=
*+++++====---=-=++==-----==+==----:::-----===--:-:===++===@#%@@*=--+****+==++***
+===++=-----=+=%++=-:-=++=+=---=-----:=---===---::-===++==%*%@%#+-==*****+*****+
----+=------====+==:-=-+===-:---=----:=-=====+---::-===+=+#+#@@#+==-=:..        
...:+=------=======-====+=-:::--=-=---==-=====+=---=====+==+#@@#+-=--.  ...     
...:+=------========-++==-::-----=====-=====--=++---======+##@##+-===:......    
:::-+=------====+====+++=+=====---====-===-=---=+========-=##@##==-==:......    
----=-------==+++===+*+====-------------==*#%%%%#++=-+===--=*@*#+---=::::::.    
----=---------=+====++#@*%@%%*=--:::---=+*=%%%#=%*+======-=**%+++==--:::.::.    
------------===#++===++*--==*+--::::::-----==+=---====-==-+#*%++=-==:::::::.    
---==-------=++#===+=+-:::::::::::..::::::::::::::-======:-#*#+++===.           
*++*+=------+++#=*=+=+-::::....:::..:::..........::=====+==***++===+-------.    
**##***********%*#=++=-:::...:::::..:::::........::=====.-=**++==--=-------.    
*###***********%*%+=+==:::::::::::..::::::......::-=====-==+*+==+--=-======.    
**#*#*******#*=%*%*+*+*=--::::::-=====-::.....::::-+=+==---+*+===---===+===. .. 
*####*******##*%*%*++*+*==---::::::::::.:::::::::-=*+*+-:::-+*==-===---====-----
######******##.....:.....:-=-------::--:::::::---:::...-::....==-===============
#####*##****#:....:..::....::------:::::::::--::::::::..:::...=+==--============
########*###-....:...:....::::---:::::..:::--::::....-:..-:...===-+--===========
##%#*###*=......:...::...:-:::-=--::...:::=+-:-==:...:::..:...:=+-=-------------
****+**=.  ....::..::....::...:::::-:::-=-:::::::::...::......:==--=------------
*****=     ....:...::...:::::..:::::=++=:::::::::::....:.....:++==-:-------:::::
****.        ..::..::::::::::::::::::-=-::::::::::::::::.::-=#+===---:----::::::
***:     .........::::::::::::::::::::-:::::::::::::::::--==+=+===---:----::::::
***:    ..........::::::::::::::::::::-:::::::::::=:-------==+++-----:::-:::::::
***:     ......::::::::::-:---:::::::::::::::---%*---------==+=+=--=--::-:::::::
***:      ..::::::::::::::::::.......::::.::::::-----------==+++==-==-::::::::::
++++.    .....:----------:...........::.........::-----------=+===-==--:::::....
++++:     .....:---==----............:::.........:--------:::-++==-=+--:::::....
++++=.     .....::---===............::::..........-==--:::::::++====+--::::::...
=====-     .....::::--==............::::..........:--:::::...:-=====+--:::::::..
======..   .....:=+++*%:............::-:...........%%*+++=:..:-+====+-=:::::::..
======-....-###%%%%%%%%.............:--:...........*%%%%%%%%%%#==--=+==:::::::::
++=====-+%%%%%#%#***++-.............:=-::..........:===***#%#%#=+-=++=+:-:::::::
++=======%##+-:::::::-:............::=-::...........:::::::::-#+===+*==--:::::::
++++++++===.........::.............::==::............::....::-#+===+*=---:::::::
+++===+++++-........:..............::-=-::...........:.....::-++++=+*=:-::::::::
++=========-.......................:-*+-::.................::=++=-=+==:-::::::::
++==========:.....................:::-=-::.................:--++=+====:-::::::::
+============:....................:::---:::...........:....:-:++=*==+=:-::::::::
+============:....................::----:::................:=:++=+===-:-::::::::
+++===========...................:::----:::............:..::=:+++=+==---::::::::
++=============..................:::::--::::..............::=-+++=+==-=-::::::::

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
    print("\033[38;5;135mAria Scanner v1.0.0 initialized.\033[0m\n")

# scans for open ports from desired range, and returns open ports into list to be used and output
def port_scan(target, start_port, end_port):
    print(f"Scanning target: \x1b[38;5;214m{target}\x1b[0m for open ports from \x1b[38;5;214m{start_port}\x1b[0m to \x1b[38;5;214m{end_port}\x1b[0m ...")

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

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "keywordSearch": query,
        "resultsPerPage": 5
    }

    try:

        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()

        data = response.json()

        cves = []

        for item in data.get("vulnerabilities", []):

            cve = item["cve"]

            metrics = cve.get("metrics", {})

            score = None
            severity = None

            if "cvssMetricV31" in metrics:

                cvss = metrics["cvssMetricV31"][0]

                score = cvss["cvssData"]["baseScore"]
                severity = cvss["cvssData"]["baseSeverity"]

            elif "cvssMetricV30" in metrics:

                cvss = metrics["cvssMetricV30"][0]

                score = cvss["cvssData"]["baseScore"]
                severity = cvss["cvssData"]["baseSeverity"]

            elif "cvssMetricV2" in metrics:

                cvss = metrics["cvssMetricV2"][0]

                score = cvss["cvssData"]["baseScore"]
                severity = cvss["baseSeverity"]

            cves.append({

                "id": cve["id"],

                "score": score,

                "severity": severity,

                "description":
                    cve["descriptions"][0]["value"]

            })

        return cves

    except Exception as e:
        print(e)
        return []


#conducts network scanning and returns information
#regarding found open ports and banners for each ports found respectively
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

        else:
                print("\x1b[91mNo vulnerabilities were able to be detected or is unable to be detected successfully.\x1b[0m")

        end_time = datetime.now()
        print(f"Scan completed in: \x1b[38;5;214m{end_time - start_time}\x1b[0m")


if __name__ == "__main__":
        logo_launch()
        target_ip = input("Enter target IP or Hostname to scan: ")
        start_port = int(input("Specify which port to start scanning from: "))
        end_port = int(input("Specify which port to end scan on: "))

        network_scan(target_ip, start_port, end_port)