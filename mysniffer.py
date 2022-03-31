from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import Ether
from scapy.layers.http import *
from scapy.sendrecv import sniff
from scapy.utils import *

from PyQt5.QtWidgets import QFileDialog, QMessageBox, QTreeWidgetItem
from PyQt5.QtGui import QColor, QBrush
from PyQt5.QtCore import pyqtSignal,QObject
from PyQt5.Qt import Qt

from threading import Event, Thread
from tempfile import NamedTemporaryFile
from datetime import datetime
from psutil import net_if_addrs, net_io_counters

import os
import shutil
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

port_filter = {
    "http" : 80,
    "https":443,
    "ftp"  :21,
    "ssh"  :22,
    "telnet":23,
    "dns"   :53
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

bg_color = {
    "ARP":"#30c9e8",
    "IP":"#f66071",
    "ICMP":"#fbc900",
    "TCP":"#30c9e8",
    "UDP":"#8dc3e0",
    "HTTP":"#0251ff",
    "HTTPS":"#faf5e6",
    "DNS":"#ffccff"
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


class MySniffer(QObject):
    # QT signals
    add_pkt = pyqtSignal(int, str, str, str, str, int, str)
    '''
    @params:
    run_state: 
        1 denotes stop;
        2 denotes running
        3 denotes pause
    '''
    def __init__(self, window=None):
        super().__init__()
        self.window = window
        self.run_state = State.STOP
        self.save_flag = 1
        self.pkt_id = 1
        self.pkt_list = []
        self.trace_flag = False
        self.trace_info = {
            "src":"",
            "dst":"",
            "sport":-1,
            "dport":-1
        }
        
        # bind signals
        self.add_pkt.connect(self.window.add_pkt_to_tree)

        tmp_file = self.create_tmp_file()
        self.tmp_file = tmp_file.name
        tmp_file.close()


    def create_tmp_file(self):
        return NamedTemporaryFile(suffix=".pcap",
            prefix=datetime.now().strftime('%Y%m%d-%H-%M-%S'), delete=False)


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
            print("Wrong File!")
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
                                %(len(data), pkt[cls_].load.hex()))

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
            elif src_port == 443 or dst_port == 443:
                tmp_result.append(ttmp)
                result.append(tmp_result)
                result.append(["Hyper Text Transfer Protocol over SecureSocket Layer",\
                    ["Can't Resolve"]])
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
            for k,v in pkt[HTTPRequest].fields.items():
                ttmp.append("%s : %s" %(str(k), str(v)))

        elif pkt.haslayer(HTTPResponse):
            tmp_result.append("Hyper Text Transfer Protocol (Response)")
            for k,v in pkt[HTTPResponse].fields.items():
                ttmp.append("%s : %s" %(str(k), str(v)))

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

        return result, hexdump(pkt, dump=True)



    def add_pkt_to_qt(self, pkt_id, pkt_time, src, dst, protocol, \
                        pkt_len, pkt_info, sport, dport):

        if self.trace_flag == True:
            if self.trace_info["src"] == src and \
                self.trace_info["dst"] == dst and \
                self.trace_info["sport"] == sport and \
                self.trace_info["dport"] == dport:
                pass
            elif self.trace_info["src"] == dst and \
                self.trace_info["dst"] == src and \
                self.trace_info["sport"] == dport and \
                self.trace_info["dport"] == sport:
                pass
            else:
                return
        # send signals
        self.add_pkt.emit(pkt_id, pkt_time, src, dst, protocol, \
                        pkt_len, pkt_info)


    def parse_packet(self, pkt, writer=None, file_flag=0, prot=""):
        try:
            if pkt.name == "Ethernet" and self.run_state == State.RUN:
                sport = -1
                dport = -1
                if file_flag == 0:
                    pkt_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                else:
                    pkt_time = "Unknown time (Get from file)"

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
                    cls_ = pkt.__class__

                    if len(protocol) >= 4 and protocol[0:4] == "ICMP":
                        protocol = "ICMP"
                        pkt_info = pkt[cls_].summary()
                    elif protocol == "UDP":
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport
                        pkt_info = pkt[UDP].summary()
                    elif protocol == "TCP":
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        pkt_info = pkt[TCP].summary()
                        if sport == 80 or dport == 80:
                            http_payload = pkt.payload.payload.payload
                            if http_payload and len(str(http_payload)) > 4:
                                method = str(http_payload)[2:5]
                                if method == "GET" or method == "POS" or method == "HTT":
                                    protocol = "HTTP"
                        elif sport in ports:
                            protocol = ports[sport]
                        elif dport in ports:
                            protocol = ports[dport]

                        # pkt_name = pkt.payload.payload.payload.name
                        # pkt_cls = pkt.payload.payload.payload.__class__
                        # if pkt_name != "NoPayload":
                        #     protocol = pkt_name
                        #     pkt_info = pkt[pkt_cls].summary()
                        #     print(pkt_info)
                    if prot != "":
                        print("prot is %s" %prot)
                        if prot != protocol.lower():
                            return

                    if v6_flag:
                        protocol = protocol + "v6"


                if writer:
                    writer.write(pkt)

                self.pkt_list.append([self.pkt_id, pkt_time, src, dst, protocol, \
                        len(pkt), pkt_info, sport, dport])
                self.add_pkt_to_qt(self.pkt_id, pkt_time, src, dst, protocol, \
                        len(pkt), pkt_info, sport, dport);

                self.pkt_id += 1

        except Exception as e:
            #print(e)
            raise e


    def read_packet(self, filename, filters=None):
        event.clear()
        self.pkt_id = 1
        self.pkt_list = []
        self.trace_flag = False
        self.run_state = State.RUN
        shutil.copy(filename, self.tmp_file)

        prot = ""
        tmp_filters = None
        if filters:
            tmp_filters = filters.lower()
            if tmp_filters in port_filter:
                prot = tmp_filters
                tmp_filters = "port %d" %port_filter[tmp_filters]


        sniff(
            prn=(lambda x: self.parse_packet(x, None, prot=prot)),
            store=False,
            offline=self.tmp_file,
            filter=tmp_filters
        )


    def capture_packet(self, netcard=None, filters=None):
        prot = ""
        tmp_filters = None
        if filters:
            tmp_filters = filters.lower()
            if tmp_filters in port_filter:
                prot = tmp_filters
                tmp_filters = "port %d" %port_filter[tmp_filters]

        try:
            w = PcapWriter(self.tmp_file, append=True, sync=True)
            sniff(
                iface=netcard,
                prn=(lambda x: self.parse_packet(x, w, prot=prot)),
                filter=tmp_filters,
                stop_filter=(lambda x: event.is_set()),
                store=False)

            w.close()

        except scapy.error.Scapy_Exception as e:
            print("Please check BPF syntax")
            raise e
        except Exception as e:
            raise e


    def push_start(self, netcard=None, filters=None):

        if self.run_state == State.PAUSE:
            self.run_state = State.RUN
            self.save_flag = 0
            return
        elif self.run_state == State.STOP or self.run_state == State.RUN:
            if self.save_flag == 0:
                self.window.save_file()
            self.save_flag = 0
            # 停止转开始，提示保存数据包（同wireshark）
            if self.pkt_id != 1:
                # 输出提示框并保存
                self.del_tmp_file()
                # 重新创建tmp文件
                tmp_file = self.create_tmp_file()
                self.tmp_file = tmp_file.name
                tmp_file.close()
        
        event.clear()
        self.pkt_id = 1
        self.pkt_list = []
        self.trace_flag = False
        self.run_state = State.RUN

        thread = Thread(
            target=self.capture_packet,
            args=(netcard, filters),
            daemon = True
            )
        thread.start()


    def push_pause(self):
        self.run_state = State.PAUSE


    def push_stop(self):
        event.set()
        self.run_state = State.STOP


    #[self.pkt_id, pkt_time, src, dst, protocol, len(pkt), pkt_info, sport, dport]
    #     0           1       2    3       4        5         6        7      8
    # 恢复时间暂停以防包序混乱

    def push_trace(self, pkt_id):
        ori_state = self.run_state
        self.run_state = State.PAUSE
        self.trace_flag = True
        print("Start Tracing")
        print(self.pkt_list[pkt_id-1])
        self.trace_info["src"] = self.pkt_list[pkt_id-1][2]
        self.trace_info["dst"] = self.pkt_list[pkt_id-1][3]
        self.trace_info["sport"] = self.pkt_list[pkt_id-1][7]
        self.trace_info["dport"] = self.pkt_list[pkt_id-1][8]
        print(self.trace_info)
        # 清除列表
        for i in self.pkt_list:
            self.add_pkt_to_qt(i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8])

        self.run_state = ori_state


    def cancel_trace(self):
        ori_state = self.run_state
        self.run_state = State.PAUSE
        self.trace_flag = False
        self.trace_info = {
            "src":"",
            "dst":"",
            "sport":-1,
            "dport":-1
        }

        for i in self.pkt_list:
            self.add_pkt_to_qt(i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8])

        self.run_state = ori_state


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
# test()