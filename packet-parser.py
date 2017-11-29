import socket
import struct
import textwrap

def mac_extracter(data):
    raw_dest_mac, raw_src_mac, mac_type = struct.unpack('! 6s 6s H', data[:14])
    mac_type = socket.htons(mac_type)
    return raw_dest_mac, raw_src_mac, mac_type, data[14:]

def actual_mac(raw_generic_mac):
    bundle = map('{:02x}'.format, raw_generic_mac)
    mac_addr = ':'.join(bundle).upper()
    return mac_addr

def eth_protocol_identifier(type):
    proto_data = {8:'IPv4', 56710:'IPv6', 1544:'ARP', 13696:'Reverse ARP', 2184:'Ethernet Flow Control', 18568:'MPLS Multicast', 18312:'MPLS Unicast' }
    return proto_data[type]

def ip_pckt(pckt):
    ver_head_len = pckt[0]
    version = ver_head_len >> 4
    head_len = (ver_head_len & 15) * 4
    ttl, ip_proto, raw_src_ip, raw_dest_ip = struct.unpack('! 8x B B 2x 4s 4s', pckt[:20])
    return version, head_len, ttl. ip_proto, raw_dest_ip, raw_src_ip, data[head_len:]

def actual_ip(generic__raw_ip):
    container = map(str, generic__raw_ip)
    ip = '.'.join(container)
    return ip

def ip_protocol_identifier(type):
    proto_data = {1:'ICMP', 2:'IGMP', 6:'TCP', 17:'UDP', 9:'IGRP', 89:'OSPF', 47:'GRE', 50:'ESP', 51:'AH', 57:'SKIP', 88:'EIGRP', 115:'L2TP'}
    return proto_data[type]

def main():
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = connect.recvfrom(65536)
        raw_dest_mac, raw_src_mac, mac_type, pckt = mac_extracter(raw_data)
        dest_mac = actual_mac(raw_dest_mac)
        src_mac = actual_mac(raw_src_mac)
        protocol = eth_protocol_identifier(mac_type)
        version, header_length, ttl, ip_protocol, raw_dest_ip, raw_src_ip, pkt = ip_pckt(pckt)
        src_ip = actual_ip(raw_src_ip)
        dest_ip = actual_ip(raw_dest_ip)
        ip_proto_name = ip_protocol_identifier(ip_protocol)
        print ('\nDestination MAC:{}\nSource MAC:{}\nProtocol:{}\n'.format(dest_mac, src_mac, protocol))
        print ('\nDestination IP:{}\nSource IP:{}\nIP Protocol:{}\n'.format(dest_ip, src_ip, ip_proto_name))

main()
