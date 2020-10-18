#! /usr/bin/python3

from scapy.all import *

dst_ip = "192.168.20.123"
src_ip = "192.168.20.136"
src_port = RandShort()
dst_port=53
dst_timeout=5

udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
if udp_scan_resp is None: #无响应
    print("port%d statu: open|filtered" %(dst_port))
elif(udp_scan_resp.haslayer(ICMP)):
        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3): #响应ICMP 不可到达(ICMP_PORT_UNREACHABLE)的数据包
            print("port%d statu: closed" %(dst_port))



