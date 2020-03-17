# Automated ARP Poison Tool
Performs man in the middle attack to the specified target IP and saves the intercepted network traffic as ".pcap" file then analyzes it to extract visited websites, possible credentials, target information etc.


It does NOT support HTTPS since it is encrypted traffic.


It must run as superuser because it has to change some system configs like IP forwarding.


# Usage
pip3 install -r requirements.txt

sudo python3 main.py

# Test
Tested on macOS Mojave 10.14 and Ubuntu 16.04