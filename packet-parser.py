import socket
import struct
import textwrap


def mac_extracter(data):
    raw_dest_mac, raw_src_mac, mac_type = struct.unpack('! 6s 6s H', data[:14])
    mac_type = socket.htons(mac_type)
    return raw_dest_mac, raw_src_mac, mac_type, #data[14:]


def actual_mac(raw_generic_mac):
    #print raw_generic_mac
    a = str(struct.unpack('!B', raw_generic_mac[0]))
    b = str(struct.unpack('!B', raw_generic_mac[1]))
    c = str(struct.unpack('!B', raw_generic_mac[2]))
    d = str(struct.unpack('!B', raw_generic_mac[3]))
    e = str(struct.unpack('!B', raw_generic_mac[4]))
    f = str(struct.unpack('!B', raw_generic_mac[5]))

def main():
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = connect.recvfrom(65536)
        raw_dest_mac, raw_src_mac, mac_type = mac_extracter(raw_data)
        dest_mac = actual_mac(str(raw_dest_mac))
        src_mac = actual_mac(raw_src_mac)
        #print ('\n{}\n,{}\n,{}\n'.format(dest_mac, src_mac, type))


main()
