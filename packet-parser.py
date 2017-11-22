import socket
import struct
import textwrap


def mac_extracter(data):
    # type: (object) -> object
    raw_dest_mac, raw_src_mac, type = struct.unpack('! 6s 6s H', data[:14])
    type = socket.htons(type)
    return raw_dest_mac, raw_src_mac, type, data[14:]


def actual_mac(raw_dest_mac, raw_src_mac):
    temp_dest_mac = map('{:02x}', format, raw_dest_mac)
    dest_mac = ':'.join(temp_dest_mac).upper()
    temp_src_mac = map('{:02x}', format, raw_src_mac)
    src_mac = ':'.join(temp_src_mac).upper()
    dest_mac = ':'.join(temp_dest_mac).upper()
    return dest_mac, src_mac


def main():
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = connect.recvfrom(65535)
        raw_dest_mac, raw_src_mac, type, data = mac_extracter(raw_data)
        dest_mac, src_mac = actual_mac(raw_dest_mac, raw_src_mac)
        print ('\n{}\n,{}\n,{}\n'.format(dest_mac, src_mac, type))


main()
