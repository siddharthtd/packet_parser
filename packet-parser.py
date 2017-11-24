import socket
import struct
import textwrap
from binascii import a2b_uu
def mac_extracter(data):
    raw_dest_mac, raw_src_mac, mac_type = struct.unpack('! 6s 6s H', data[:14])
    mac_type = socket.htons(mac_type)
    return raw_dest_mac, raw_src_mac, mac_type, data[14:]

def actual_mac(raw_generic_mac):
    bundle = map('{:02x}'.format, (ord(x) for x in raw_generic_mac))
    mac_addr = ':'.join(bundle).upper()
    return mac_addr

def protocol_identifier(type):
    proto_data = {8:'IPv4', 56710:'IPv6', 1544:'ARP', 13696:'Reverse ARP', 2184:'Ethernet Flow Control', 18568:'MPLS Multicast', 18312:'MPLS Unicast' }
    return proto_data[type]

def ip_header_parser(network_pckt):
    version_header_info = network_pckt[0]
    version = ord(version_header_info) >> 4
    header_length = (ord(version_header_info) & 15) * 4
    total_len = struct.unpack('!2s', network_pckt[1:3])
    #frag_val = struct.unpack('!b', network_pckt[6:7])
    #frag_temp = (ord(x) for x in frag_val)
    #frag_flag = frag_temp >> 3
    #frag_offset = (ord(frag_val) & #some_integer) * #some_multiple
    ttl = struct.unpack('!B', network_pckt[8])
    #ip_proto = struct.unpack('!b', network_pckt[9])
    #checksum = struct.unpack('! 2s', network_pckt[10:12])
    #raw_src_ip = struct.unpack('! 4s', network_pckt[13:17])
    #raw_dest_ip = struct.unpack('! 4s', network_pckt[18:20])
    #ttl, ip_proto, raw_src_ip, raw_dest_ip = struct.unpack('! 8x b b 2x 4s 4s', network_pckt[:20])
    #return version, header_length, ttl, ip_proto, raw_dest_ip, raw_src_ip
    print ttl#, total_len, frag_flag, ip_proto, checksum, raw_src_ip, raw_dest_ip

def ip_formatter(raw_generic_ip):
    container = map(str, raw_generic_ip)
    actual_ip = '.'.join(container)
    return actual_ip

def main():
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = connect.recvfrom(65536)
        raw_dest_mac, raw_src_mac, mac_type, pckt = mac_extracter(raw_data)
        dest_mac = actual_mac(raw_dest_mac)
        src_mac = actual_mac(raw_src_mac)
        protocol = protocol_identifier(mac_type)
        #print ('\nDestination MAC:{}\nSource MAC:{}\nProtocol:{}\n'.format(dest_mac, src_mac, protocol))
        #ip_ver, ip_head_len, ttl, ip_proto, raw_dest_ip, raw_src_ip = ip_header_parser(pckt)
        #dest_ip = ip_formatter(raw_dest_ip)
        #src_ip = ip_formatter(raw_src_ip)
        #print ('\nVersion:{}\nHeader Length:{}\nProtocol:{}\nTTL:{}\nDestination IP:{}\nSource IP:{}\n'.format(ip_ver, ip_head_len, ip_proto, ttl, dest_ip, src_ip))
        ip_header_parser(pckt)
main()
