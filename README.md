The Packet Parser or Packet Sniffer is a tool used for identifying the core networking components inside a data packet.

Simply run the code using a python3 interpreter and the data will be displayed in the terminal window.

Currently, information for ICMP, TCP and UDP protocols in the transport layer can be extracted from the packet.

Alongside, only IPv4 type of packets can be extracted, while IPv6 packets are not yet extractable. It will be implemented in the future.

We have used the socket library for capturing the packet and then struct.unpack is used in abandunce for distributing the data from the packet into different variables for processing.
This data is then displayed using an if-else control loop inside the main program.

In the future, we also plan to convert this code into object-orianted methods and convert each of the functions into classes.

We also plan to parse pcap files (wireshark captures) as opposed to raw packets captured from the network.