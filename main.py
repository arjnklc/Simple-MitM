from Sniffer import Sniffer
from Analyzer import Analyzer


if __name__== "__main__":

    target_ip = str(input("Enter the target IP >> "))

    filename = "capture_demo.pcap"

    sniffer = Sniffer(target_ip, filename)
    sniffer.sniff_packets(10000)

    analyzer = Analyzer()
    analyzer.parse_pcap_file(filename)

    analyzer.print_visited_websites()
    analyzer.print_credentials()
    analyzer.print_target_info()


