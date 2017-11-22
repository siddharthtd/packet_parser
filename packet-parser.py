import socket
import struct
import textwrap


def mac_extracter(data):
    # type: (object) -> object
    raw_dest_mac, raw_src_mac, type = struct.unpack('! 6s 6s H', data[:14])
    type = socket.htons(type)
    return raw_dest_mac, raw_src_mac, type, #data[14:]


def actual_mac(raw_generic_mac):

    a = struct.unpack('!s', len(raw_generic_mac[0:2]))

def main():
    # type: () -> object
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = connect.recvfrom(65536)
        raw_dest_mac, raw_src_mac, type = mac_extracter(raw_data)
        dest_mac = actual_mac(raw_dest_mac)
        src_mac = actual_mac(raw_src_mac)
        print ('\n{}\n,{}\n,{}\n'.format(dest_mac, src_mac, type))


main()
