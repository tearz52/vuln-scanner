# Aria 
Aria is an open-source vulnerability scanner that can be used to detect and identify exposed ports and find vulnerabilities
from those exposed ports.

## Capabilities:
- Scans target IP from desired range of ports.
- Detects open ports.
- Retrieves banners and identifies versions hosted on identified ports.
- Compares identified versions automatically to NVD NIST CVE database to identify vulnerabilities.

## Before using, make sure you have:
- A NVD NIST API Key in your environment variables
- Installed **nvdlib** on your environment.
- Python 3.10+

## Disclaimer
Aria is developed for educational, research, and authorized security testing purposes only.

Users are responsible for ensuring they have explicit permission before scanning any network, host, or system. Unauthorized scanning or testing of systems you do not own or have permission to assess may violate applicable laws, regulations, or organizational policies.

The author assumes no responsibility or liability for any misuse, damage, or legal consequences resulting from the use of this software. By using this tool, you agree to use it responsibly and ethically.

## Legal Notice
This project was created as part of a cybersecurity learning project. It is intended to demonstrate concepts such as TCP port scanning, multithreaded banner grabbing, service fingerprinting, and CVE lookup using publicly available vulnerability information from the National Vulnerability Database (NVD).

It is not intended to replace professional vulnerability scanners or penetration testing frameworks.

