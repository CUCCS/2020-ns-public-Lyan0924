#! /usr/bin/python3

from scapy.all import *

src_ip="192.168.20.136"
dst_ip = "192.168.20.123"
src_port = RandShort()
dst_port=22

stealth_scan_resp = sr1(IP(src=src_ip,dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
if stealth_scan_resp is None: #无响应
    print("port%d statu: filtered" %(dst_port))
elif(stealth_scan_resp.haslayer(TCP)):
    if(stealth_scan_resp.getlayer(TCP).flags == 0x12): #响应SYN/ACK数据包
        send_rst = sr(IP(src=src_ip,dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=10)#攻击端返回RST数据包拆除连接
        print("port%d statu: open" %(dst_port))
    elif (stealth_scan_resp.getlayer(TCP).flags == 0x14): #响应RST/ACK数据包 
        print("port%d statu: closed" %(dst_port))
