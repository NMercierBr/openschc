import socket

# Define the port to listen on
listen_port = 12345

# OpenSCHC setup
import sys
sys.path.insert(1, '../../../openschc/src/')
from gen_parameters import *
import gen_rulemanager as RM
from gen_bitarray import BitBuffer
from compr_core import Decompressor
from compr_parser import Unparser

#from frag_send import FragmentNoAck

rm = RM.RuleManager()
rm.Add(file="ipv6udp.json")
rm.Print()
from scapy.all import raw

# Create an IPv6 UDP socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
    # Bind the socket to all IPv6 addresses on the specified port
    udp_socket.bind(("0.0.0.0", listen_port))  # "::" is the IPv6 equivalent of "0.0.0.0"

    print(f"Listening for UDP packets on port {listen_port}...")
    
    while True:
        # Receive data from the sender
        data, address = udp_socket.recvfrom(1024)  # Buffer size is 1024 bytes
        try:
            print(f"Received: '{data.hex()}' from {address}")
            print(f" ===== : '{data.decode()}'")
        except:
            print(f"Received: '{data.hex()}' from {address}")

        # Processing
        if "127.0.0.1" in address[0]:
            print("- from dev in ipv4 wrapper = schc packet => decompress.")
            
            t_dir = T_DIR_UP # uplink
            packet_bbuf = BitBuffer(data)
            rule = rm.FindRuleFromSCHCpacket(packet_bbuf, device="udp:10.0.0.20:8888")
            print("rule =", rule) # rule found ?
            #print("--- end of rule---")
            if rule != None: 

                decomp = Decompressor()
                unparser = Unparser()
                header_d = decomp.decompress(schc=packet_bbuf, rule=rule, direction=t_dir)
                uri = b"temp"
                header_d[("COAP.URI-PATH", 1)] = [uri, len(uri) * 8]

                pkt_data = bytearray()
                while (packet_bbuf._wpos - packet_bbuf._rpos) >= 8:
                    octet = packet_bbuf.get_bits(nb_bits=8)
                    pkt_data.append(octet)

                #print("The HEADER D:", header_d, pkt_data)
                packet = unparser.unparse(header_d, pkt_data, t_dir, rule, None, True) # last 2 are iface (forward decompressed pkt) and verbose

                # Now we have the uncompressed SCAPY packet

                print("DEcompressed packet:")
                print(raw(packet).hex())
            else:
                print("rule not found.")

