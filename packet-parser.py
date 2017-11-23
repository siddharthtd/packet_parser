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

def ip_parser(pckt):
    version_header_info = pckt[0]
    version = version_header_info >> 4
    header_length = (version_header_info & 15) * 4
    print version, header_length

def main():
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = connect.recvfrom(65536)
        raw_dest_mac, raw_src_mac, mac_type, pckt = mac_extracter(raw_data)
        dest_mac = actual_mac(raw_dest_mac)
        src_mac = actual_mac(raw_src_mac)
        protocol = protocol_identifier(mac_type)
        #print ('\nDestination MAC:{}\nSource MAC:{}\nProtocol:{}\n'.format(dest_mac, src_mac, protocol))
        ip_parser(pckt)

main()
