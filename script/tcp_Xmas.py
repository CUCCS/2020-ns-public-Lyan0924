#! /usr/bin/python3
 
from scapy.all import * 

dst_ip = "192.168.20.123"
src_ip = "192.168.20.136"
src_port = RandShort()
dst_port=22
 
xmas_scan_resp=sr1(IP(src=src_ip,dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="FPU"),timeout=10)
if xmas_scan_resp is None: #目标机无响应
    print("port%d statu: open|filtered" %(dst_port))
elif(xmas_scan_resp.haslayer(TCP)):
    if(xmas_scan_resp.getlayer(TCP).flags == 0x14): #目标机响应RST报文
        print("port%d statu: closed" %(dst_port))
