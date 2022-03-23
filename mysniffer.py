from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff
from scapy.utils import *

from threading import Event, Thread
from tempfile import NamedTemporaryFile
from datetime import datetime
from psutil import net_if_addrs, net_io_counters

def get_netcard(self):
    netcard_info = {}
    info = net_if_addrs()
    for k,v in info.items():
        for item in v:
            if item[0] == 2 and item[1] == '127.0.0.1':
                break
            # macOS Catalina
            elif item[0] == -1 or item[0] == 18:
                netcard_info.update({item[1]:k})

    return list(netcard_info.values())



class MySniffer():
    '''
    @params:
    run_state: 
        0 denotes stop;
        1 denotes running
        2 denotes pause
    '''
    def __init__(self):
        self.run_state = 0
        tmp_file = NamedTemporaryFile(suffix=".pcap",
            prefix=datetime.now().strftime('%Y%m%d-%H-%M-%S'), delete=False)
        self.tmp_file = tmp_file.name
        tmp_file.close()

    def process_packet(self, pkt, writer):
        pass


    def capture_packet(self, netcard=None, filters=None):
        w = PcapWriter(self.tmp_file, append=True, sync=True)
        sniff(
            iface=netcard,
            prn=(lambda x: self.process_packet(x, w)),
            filter=filters,
            count=10,
            store=False)

        writer.close()


    def start_capture
        if self.run_state == 1:
            return
        if self.run_state == 

def test():
    s = MySniffer()
    print(s.get_netcard())
test()