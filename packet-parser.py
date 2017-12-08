import socket
import struct

#extract mac address in raw format from the packet
def mac_extracter(data):
    raw_dest_mac, raw_src_mac, mac_type = struct.unpack('! 6s 6s H', data[:14])
    mac_type = socket.htons(mac_type)
    return raw_dest_mac, raw_src_mac, mac_type, data[14:]

#format the mac address into human readable format eg. AA:BB:CC:DD:EE
def actual_mac(raw_generic_mac):
    bundle = map('{:02x}'.format, raw_generic_mac)
    mac_addr = ':'.join(bundle).upper()
    return mac_addr

#return the name of the network layer protocol according to it's protocol number from the mac layer (ethernet frane).
def eth_protocol_identifier(type):
    proto_data = {8:'IPv4', 56710:'IPv6', 1544:'ARP', 13696:'Reverse ARP', 2184:'Ethernet Flow Control', 18568:'MPLS Multicast', 18312:'MPLS Unicast' }
    return proto_data[type]

#parsing the IP side of the packet, which is extracted after extracting and dropping the ethernet frame
def ip_pckt(pckt):
    ver_head_len = pckt[0]
    version = ver_head_len >> 4
    head_len = (ver_head_len & 15) * 4
    ttl, ip_proto, raw_src_ip, raw_dest_ip = struct.unpack('! 8x B B 2x 4s 4s', pckt[:20])
    return version, head_len, ttl, ip_proto, raw_dest_ip, raw_src_ip, pckt[head_len:]

#format the ip address into human readable format eg. 192.168.1.1
def actual_ip(generic__raw_ip):
    container = map(str, generic__raw_ip)
    ip = '.'.join(container)
    return ip

#return the name of the transport layer protocol according to it's protocol number from the network layer (IP datagram)
def ip_protocol_identifier(type):
    proto_data = {1:'ICMP', 2:'IGMP', 6:'TCP', 17:'UDP', 9:'IGRP', 89:'OSPF', 47:'GRE', 50:'ESP', 51:'AH', 57:'SKIP', 88:'EIGRP', 115:'L2TP', 128:'SSCOPMCE', 28:'IRTP'}
    return proto_data[type]

#in case the transport layer protocol is ICMP, unpack and extract the ICMP data according to the format.
def icmp_unpack(data):
    type, code, checksum = struct.unpack('! B B H', data[:4])
    return type, code, checksum, data[4:]

#in case the transport layer protocol is TCP, unpack and extract the TCP data according to the TCP frame format.
def tcp_unpack(data):
    (src_port, dest_port, seq_no, acknowledgement, off_reserve_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (off_reserve_flag >> 12) * 4
    urg = (off_reserve_flag & 32) >> 5
    ack = (off_reserve_flag & 16) >> 4
    psh = (off_reserve_flag & 8) >> 3
    rst = (off_reserve_flag & 4) >> 2
    syn = (off_reserve_flag & 2) >> 1
    fin = off_reserve_flag & 1
    return src_port, dest_port, seq_no, acknowledgement, urg, ack, psh, rst, syn, fin, data[offset:]

#in case the transport layer protocol is UDP, unpack and extract the UDP data according to the UDP datagram frame format.
def udp_unpack(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

#main function for control. First displays the ethernet data and then detects the network layer protocol and also the information related to that.
#Then, according to the protocol of the transport layer, the if-else loop directs the control to execute the appropriate function and display the extracted data according to that.
def main():
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = connect.recvfrom(65536)
        raw_dest_mac, raw_src_mac, mac_type, pckt = mac_extracter(raw_data)
        dest_mac = actual_mac(raw_dest_mac)
        src_mac = actual_mac(raw_src_mac)
        protocol = eth_protocol_identifier(mac_type)
        version, header_length, ttl, ip_protocol, raw_dest_ip, raw_src_ip, ip_pkt = ip_pckt(pckt)
        src_ip = actual_ip(raw_src_ip)
        dest_ip = actual_ip(raw_dest_ip)
        ip_proto_name = ip_protocol_identifier(ip_protocol)
        print ('\nDestination MAC:{}\nSource MAC:{}\nProtocol:{}\n'.format(dest_mac, src_mac, protocol))

        if mac_type == 8:
            print('\nIPv4 Packet\n')
            print('\nVersion:{}\nTTl:{}\nSource IP Address:{}\nDestination IP Address:{}\nProtocol Name:{}'.format(version, ttl, src_ip, dest_ip, ip_proto_name))

            if ip_protocol == 1:
                type_icmp, code, checksum, payload_icmp = icmp_unpack(ip_pkt)
                print ('\nICMP Protocol Packet\n')
                print('\nType:{}\nCode:{}\nChecksum:{}\n'.format(type_icmp, code, checksum))
                print (payload_icmp)

            elif ip_protocol == 6:
                src_port, dest_port, seq, ack, flg_urg, flg_ack, flg_psh, flg_rst, flg_syn, flg_fin, payload_tcp = tcp_unpack(ip_pkt)
                print('\nTCP Protocol Packet\n')
                print('\nSource Port:{}\nDestination Port:{}\nSequence No.:{}\nAcknowledgement:{}\n'.format(src_port, dest_port, seq, ack))
                print('\nFlag Information\n')
                print('\nUrgent:[{}]\nAcknowledgement:[{}]\nPush:[{}]\nReset:[{}]\nSyn:[{}]\nFinish:[{}]\n'.format(flg_urg, flg_ack, flg_psh, flg_rst, flg_syn, flg_fin))
                print(payload_tcp)

            elif ip_protocol == 17:
                src_port, dest_port, size, payload_udp = udp_unpack(ip_pkt)
                print('\nUDP Protocol Packet\n')
                print('\nSource Port:{}\nDestination Port:{}\nSize:{}\n'.format(src_port,dest_port, size))
                print(payload_udp)

            else:
                print(ip_pkt)
main()
