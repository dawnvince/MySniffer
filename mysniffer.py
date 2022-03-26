from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import Ether
from scapy.layers.http import *
from scapy.sendrecv import sniff
from scapy.utils import *

from threading import Event, Thread
from tempfile import NamedTemporaryFile
from datetime import datetime
from psutil import net_if_addrs, net_io_counters

import os
import json

from enum import Enum

class State(Enum):
    STOP = 1
    RUN = 2
    PAUSE = 3


# 常用端口
ports = {
    80: "HTTP",
    443: "HTTPS",
    20: "FTP_Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    3306: "MySql"
}

# ICMP类型
icmp_types = {
    0: "Echo Reply",
    3: "Unreachable",
    5: "Redirect",
    8: "Echo request",
    9: "Router advertisement",
    10: "Route solicitation"
}

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
        self.pkt_id = 1
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
        try:
            pkts = rdpcap(self.tmp_file, index)
            return pkts[-1]

        except:
            print("No data could be read!")
            return None

    def read_all_pcap(self, filename):
        try:
            pkts = rdpcap(filename)
            return pkts

        except:
            print("No data could be read!")
            return None


    def parse_layer1(self, pkt, result):
        tmp_result = []
        tmp_result.append("Frame: %d bytes on wire, %d bytes captured"\
                    %(pkt.wirelen, len(pkt)))
        tmp_result.append(["No More Infomation."])
        result.append(tmp_result)

        self.parse_layer2(pkt, result)


    def parse_layer2(self, pkt, result):
        protocol = pkt.name
        tmp_result = []
        if protocol == "NoPayload":
            return

        pkt_cls = pkt.__class__
        # Ethernet
        if protocol == "Ethernet":
            src = pkt[pkt_cls].src
            dst = pkt[pkt_cls].dst
            if dst == "ff:ff:ff:ff:ff:ff":
                dst = "BroadCast (ff:ff:ff:ff:ff:ff)"

            tmp_result.append("Ethernet, Src: %s , Dst: %s" %(src, dst))
            ttmp = []
            ttmp.append("Destination: %s" %(dst))
            ttmp.append("Source: %s" %(src))
            if pkt.payload.name != "NoPayload":
                ttmp.append("Type: %s (%s)" %(pkt.payload.name, \
                            hex(pkt[pkt_cls].type)))

            tmp_result.append(ttmp)
            result.append(tmp_result)

            self.parse_layer_over_2(pkt.payload, result)

    '''
    一开始使用分层结构，写的过程中突然意识到可能会出现 vpn 的情况
    此时数据包分层结构混乱，实际并不是按层解析
    因此将所有的层放在同一个函数中进行解析
    '''
    def parse_layer_over_2(self, pkt, result):
        protocol = pkt.name
        tmp_result = []
        ttmp = []
        cls_ = pkt.__class__
        if protocol == "NoPayload":
            return 

        # ARP
        if protocol == "ARP":
            arp_op = pkt[ARP].op
            op_info = "unknown"
            if arp_op == 1:
                op_info = "request"
            elif arp_op == 2:
                op_info = "reply"

            tmp_result.append("Address Resolution Protocol (%s)" % op_info)
            ttmp.append("Opcode: %s (%d)" %(op_info, pkt[ARP].op))
            ttmp.append("Sender MAC address: %s" %pkt[ARP].hwsrc)
            ttmp.append("Sender IP address: %s" %pkt[ARP].psrc)
            ttmp.append("Target MAC address: %s" %pkt[ARP].hwdst)
            ttmp.append("Target IP address: %s" %pkt[ARP].pdst)

        # IPv4
        elif protocol == "IP":
            ip_src = pkt[cls_].src
            ip_dst = pkt[cls_].dst

            tmp_result.append("Internet Protocol Version 4, Src: %s, Dst: %s" \
                                % (ip_src, ip_dst))
            ttmp.append("Version: %d" % pkt[cls_].version)
            ttmp.append("Header Length: %d bytes (%d)" %
                    (pkt[cls_].ihl << 2, pkt[cls_].ihl))
            ttmp.append("Diiferentiated Services Field: %s" % hex(pkt[cls_].tos))
            ttmp.append("Total Length: %d" % pkt[cls_].len)
            ttmp.append("Identification: %s" % (hex(pkt[cls_].id)))
            ttmp.append("Flags: %d (%s)" % (pkt[cls_].flags,
                                hex(pkt[cls_].flags.value)))
            ttmp.append("Fragment offset: %d" % pkt[cls_].frag)
            ttmp.append("Time to live: %d" % pkt[cls_].ttl)
            ttmp.append("Protocol: %s (%d)" %
                            (pkt.payload.name, pkt[cls_].proto))
            ttmp.append("Header checksum: %s" % hex(pkt[cls_].chksum))
            ttmp.append("Source: %s" % ip_src)
            ttmp.append("Destination: %s" % ip_dst)

        # IPv6
        elif protocol == "IPv6":
            # IPv6可以携带扩展头部，IPv6可能会出现循环解析的情况
            ip_src = pkt[cls_].src
            ip_dst = pkt[cls_].dst
            tmp_result.append("Internet Protocol Version 6, Src: %s, Dst: %s" \
                                % (ip_src, ip_dst))
            ttmp.append("Version: %d" % pkt[cls_].version)
            ttmp.append("Traffice Class: %s" \
                                % hex(pkt[cls_].tc))
            ttmp.append("Flow Label: %s" % hex(pkt[cls_].fl))
            ttmp.append("Payload Length: %d" % pkt[cls_].plen)
            ttmp.append("Next Header: %s (%d)" \
                                % (pkt.payload.name, pkt[cls_].nh))
            ttmp.append("Hop Limit: %d" % pkt[cls_].hlim)
            ttmp.append("Source: %s" % ip_src)
            ttmp.append("Destination: %s" % ip_dst)

        # ICMP
        elif protocol == "ICMP":
            itype = pkt[cls_].type
            if itype in icmp_types:
                info = icmp_types[itype]
            else:
                info = "Other"
            tmp_result.append("Internet Control Message Protocol (%s)" %info)
            ttmp.append("Type: %d" %itype)
            ttmp.append("Code: %d" %pkt[cls_].code)
            ttmp.append("Checksum: %s" % hex(pkt[cls_].chksum))
            ttmp.append("Identifier: %d (%s)" % (pkt[cls_].id,
                            hex(pkt[cls_].id)))
            ttmp.append("Sequence number: %d (%s)" 
                            %(pkt[cls_].seq,hex(pkt[cls_].seq)))
            data =  pkt.payload
            if len(data) > 0:
                ttmp.append("Data (%d bytes): %s" 
                                %(len(data), hex(data)))

        # TCP
        elif protocol == "TCP":
            src_port = pkt[cls_].sport
            dst_port = pkt[cls_].dport
            tmp_result.append("Transmission Control Protocol, \
                    Src Port: %d, Dst Port: %d"% (src_port, dst_port))

            ttmp.append("Source Port: %d" % src_port)
            ttmp.append("Destination Port: %d" % dst_port)
            ttmp.append("Sequence number: %d" % pkt[cls_].seq)
            ttmp.append("Acknowledgment number: %d" % pkt[cls_].ack)
            tcp_head_length = pkt[cls_].dataofs
            ttmp.append("Header Length: %d bytes (%d)" %
                              (tcp_head_length << 2, tcp_head_length))
            ttmp.append("Flags: %s (%d)" \
                            % (hex(pkt[cls_].flags.value),pkt[cls_].flags))
            ttmp.append("Window size value: %d" % pkt[cls_].window)
            ttmp.append("Checksum: %s" % hex(pkt[cls_].chksum))
            ttmp.append("Urgent pointer: %d" % pkt[cls_].urgptr)
            payload_len = len(pkt.payload)
            if payload_len > 0:
                ttmp.append("TCP payload: %d bytes" % payload_len)
            if src_port == 80 or dst_port == 80:
                tmp_result.append(ttmp)
                result.append(tmp_result)
                self.parse_http(pkt, result)
                return
        
        # UDP
        elif protocol == "UDP":
            src_port = pkt[cls_].sport
            dst_port = pkt[cls_].dport
            tmp_result.append("User Datagram Protocol, \
                Src Port: %d, Dst Port: %d"%(src_port, dst_port))
            ttmp.append("Source Port: %d" % src_port)
            ttmp.append("Destination Port: %d" % dst_port)
            ttmp.append("Length: %d" % pkt[cls_].len)
            ttmp.append("Checksum: %s" % hex(pkt[cls_].chksum))
            payload_len = len(pkt.payload)
            if payload_len > 0:
                ttmp.append("UDP payload: %d bytes" % payload_len)
                ttmp.append("Data: %s" % bytes(pkt[cls_].payload).hex())

        else:
            return

        tmp_result.append(ttmp)
        result.append(tmp_result)

        self.parse_layer_over_2(pkt.payload, result)


    def parse_http(self, pkt, result):
        tmp_result = []
        ttmp = []
        if pkt.haslayer(HTTPRequest):
            tmp_result.append("Hyper Text Transfer Protocol (Request)")
            ttmp.append("%s" % str(pkt[HTTPRequest].fields))
        elif pkt.haslayer(HTTPResponse):
            tmp_result.append("Hyper Text Transfer Protocol (Response)")
            ttmp.append("%s" % str(pkt[HTTPResponse].fields))
        else:
            return
        tmp_result.append(ttmp)
        result.append(tmp_result)


    def parse_pkt_detail(self, index):
        # 类似 wireshark 的两层结构，第一层为概述，展开后为详细内容
        # 使用二维数组
        ''' result: [
                [simpfied info, [info1, info2, ...]],
                ...
            ]
        '''
        result = []
        if index < 1 or index > self.pkt_id:
            return

        pkt = self.read_one_pcap(index)
        if pkt:
            self.parse_layer1(pkt, result)

        return result


    def add_pkt_to_qt(self, pkt_id, pkt_time, src, dst, protocol, \
                        pkt_len, pkt_info):
        pass


    def parse_packet(self, pkt, writer):
        try:
            if pkt.name == "Ethernet" and self.run_state == State.RUN:

                pkt_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')

                protocol = pkt.payload.name
                pkt_info = ""
                v6_flag = False

                # 包列表协议解析

                '''
                                     |- - ->TCP- -|->HTTP
                                     |            |
                    |- - ->IPv4/v6- -|- - ->UDP   |->others(see ports)
                    |                |
                Eth-|                |- - ->ICMP
                    |
                    |- - ->ARP

                '''

                # Layer 2
                if protocol == "ARP":
                    src = pkt[Ether].src
                    dst = pkt[Ether].dst
                    pkt_info = pkt[ARP].summary()
                else:
                    if protocol == "IP":
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        pkt_info = pkt[IP].summary()
                    elif protocol == "IPv6":
                        src = pkt[IPv6].src
                        dst = pkt[IPv6].dst
                        pkt_info = pkt[IPv6].summary()
                        v6_flag = True
                    else:
                        return

                    # Layer 3
                    protocol = pkt.payload.payload.name

                    if len(protocol) >= 4 and protocol[0:4] == "ICMP":
                        protocol = "ICMP"
                        pkt_info = pkt[ICMP].summary()
                    elif protocol == "UDP":
                        pkt_info = pkt[UDP].summary()
                    elif protocol == "TCP":
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        pkt_info = pkt[TCP].summary()
                        if sport in ports:
                            protocol = ports[sport]
                        elif dport in ports:
                            protocol = ports[dport]

                        # pkt_name = pkt.payload.payload.payload.name
                        # pkt_cls = pkt.payload.payload.payload.__class__
                        # if pkt_name != "NoPayload":
                        #     protocol = pkt_name
                        #     pkt_info = pkt[pkt_cls].summary()
                        #     print(pkt_info)

                    if v6_flag:
                        protocol = protocol + "v6"

                if writer:
                    writer.write(pkt)

                self.add_pkt_to_qt(self.pkt_id, pkt_time, src, dst, protocol, \
                        len(pkt), pkt_info);

                self.pkt_id += 1

        except Exception as e:
            print(e)


    def capture_packet(self, netcard=None, filters=None):
        try:
            w = PcapWriter(self.tmp_file, append=True, sync=True)
            sniff(
                iface=netcard,
                prn=(lambda x: self.parse_packet(x, w)),
                filter=filters,
                stop_filter=(lambda x: event.is_set()),
                store=False)

            w.close()

        except scapy.error.Scapy_Exception as e:
            print("Please check BPF syntax")


    def push_start(self, netcard=None, filters=None):
        if self.run_state == State.RUN:
            return
        elif self.run_state == State.PAUSE:
            self.run_state = State.RUN
            return
        elif self.run_state == State.STOP:
            # 停止转开始，提示保存数据包（同wireshark）
            if self.pkt_id != 0:
                # 输出提示框并保存
                self.del_tmp_file()
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
    i = 1
    while(1):
        time.sleep(1)
        result = s.parse_pkt_detail(i)
        i += 3
        if result:
            print(result)
test()