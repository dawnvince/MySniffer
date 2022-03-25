from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff
from scapy.utils import *

from threading import Event, Thread
from tempfile import NamedTemporaryFile
from datetime import datetime
from psutil import net_if_addrs, net_io_counters

import os

from enum import Enum

class State(Enum):
    STOP = 1
    RUN = 2
    PAUSE = 3

event = Event()

def get_netcard(self):
    netcard_info = {}
    info = net_if_addrs()
    for k,v in info.items():
        for item in v:
            # ignore loopback
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
        1 denotes stop;
        2 denotes running
        3 denotes pause
    '''
    def __init__(self):
        self.run_state = State.STOP
        self.packet_id = 0
        tmp_file = self.create_tmp_file()
        self.tmp_file = tmp_file.name
        tmp_file.close()


    def create_tmp_file(self):
        return NamedTemporaryFile(suffix=".pcap",
            prefix=datetime.now().strftime('%Y%m%d-%H-%M-%S'), delete=False)


    def save_tmp_file(self):
        pass


    def del_tmp_file(self):
        os.remove(self.tmp_file)


    def read_one_pcap(self, index=1):
        pkts = rdpcap(self.tmp_file, index)
        return pkts[-1]


    def read_all_pcap(self, filename):
        pkts = rdpcap(filename)
        return pkts

    def parse_packet(self, pkt, writer):
        try:
            if pkt.name == "Ethernet" and self.run_state != State.PAUSE:
                if writer:
                    writer.write(pkt)
        except Exception as e:
            print(e)


    def capture_packet(self, netcard=None, filters=None):
        w = PcapWriter(self.tmp_file, append=True, sync=True)
        sniff(
            iface=netcard,
            prn=(lambda x: self.parse_packet(x, w)),
            filter=filters,
            stop_filter=(lambda x: event.is_set()),
            count=10,
            store=False)

        w.close()


    def push_start(self, netcard=None, filters=None):
        if self.run_state == State.RUN:
            return
        elif self.run_state == State.PAUSE:
            self.run_state = State.RUN
            return
        elif self.run_state == State.STOP:
            # 停止转开始，提示保存数据包（同wireshark）
            if self.packet_id != 0:
                # 输出提示框并保存
                del_tmp_file()
                # 重新创建tmp文件
                tmp_file = self.create_tmp_file()
                self.tmp_file = tmp_file.name
                tmp_file.close()
        
        event.clear()
        self.run_state = State.RUN

        thread = Thread(
            target=self.capture_packet,
            daemon=True,
            args=(netcard, filters)
            )
        thread.start()


    def push_pause(self):
        self.run_state = State.PAUSE


    def push_stop(self):
        event.set()
        self.run_state = State.STOP


def test():
    s = MySniffer()
    s.push_start()
    while(1):
        time.sleep(0.1)
        pkt = s.read_one_pcap()
        print(repr(pkt))
test()