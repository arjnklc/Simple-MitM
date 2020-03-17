import dpkt
import httpagentparser
from scapy.all import *
from collections import Counter


class Analyzer:
    def __init__(self):
        self.user_agents = []
        self.websites = set()
        self.creds = dict()

    @staticmethod
    def find_max_occured(lst):
        try:
            most_common, _ = Counter(lst).most_common(1)[0]
            return most_common
        except:
            return None

    def get_target_info(self):
        most_occured = Analyzer.find_max_occured(self.user_agents)
        return httpagentparser.simple_detect(most_occured)

    def get_visited_websites(self):
        return self.websites

    def print_credentials(self):
        for site in self.creds:
            print("Possible credentials for {}".format(site))
            print(self.creds[site] + "\n")

    def print_visited_websites(self):
        print("Visited websites:")
        for site in self.websites:
            if site.startswith("www"):
                print(site)

    def print_target_info(self):
        os, browser = self.get_target_info()
        print("Target OS: {}".format(os))
        print("Target browser: {}".format(browser))

    def get_possible_credentials(self, http_body):
        filter = ["username", "user", "email", "e-mail", "mail", "pass", "password", "passwd"]
        for f in filter:
            if f in http_body:
                return http_body

        return ""

    def parse_http(self, packet):
        try:
            payload = bytes(packet[TCP].payload)
            url_path = payload[payload.index(b"GET ") + 4:payload.index(b" HTTP/1.1")].decode("utf8")
            http_header_raw = payload[:payload.index(b"\r\n\r\n") + 2]
            http_header_parsed = dict(
            re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))

            url = http_header_parsed["Host"] + url_path
            user_agent = http_header_parsed["User-Agent"]
            self.user_agents.append(user_agent)
            os, browser = self.get_target_info()


            if not ".ico" in url and not ".png" in url and not ".gif" in url and not ".js" in url:
                print("Visited url: {}".format(url))
                print("OS: {}, Browser: {}".format(os, browser))
        except:
            pass


    def analyze_packet(self, packet):
        try:
            if packet[TCP].dport == 80:
                self.parse_http(packet)

        except:
            pass


    def parse_pcap_file(self, filename):

        # Open the pcap file read-only binary mode
        f = open(filename, 'rb')
        pcap = dpkt.pcap.Reader(f)

        conn = dict()
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)

            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)

            if tupl in conn:
                conn[tupl] = conn[tupl] + tcp.data
            else:
                conn[tupl] = tcp.data

            try:
                stream = conn[tupl]
                if stream[:4] == 'HTTP':
                    http = dpkt.http.Response(stream)
                else:
                    http = dpkt.http.Request(stream)

                self.user_agents.append(http.headers["user-agent"])
                self.websites.add(http.headers['host'])

                body = http.body.decode("utf-8")
                if body:
                    possible_cred = self.get_possible_credentials(body)
                    if possible_cred:

                        website = http.headers['host']
                        self.creds[website] = possible_cred


                stream = stream[len(http):]
                if len(stream) == 0:
                    del conn[tupl]
                else:
                    conn[tupl] = stream

            except:
                pass

        f.close()


if __name__ == '__main__':

    filename = "capture.pcap"

    analyzer = Analyzer()
    analyzer.parse_pcap_file(filename)
    os, browser = analyzer.get_target_info()

    analyzer.print_visited_websites()
    analyzer.print_credentials()

    print("OS: " + os)
    print("Browser " + browser)