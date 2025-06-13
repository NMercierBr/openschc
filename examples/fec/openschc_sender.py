from scapy.all import *
from scapy.contrib.coap import CoAP

import sys
sys.path.insert(1, '../../../openschc/src/')
from compr_parser import Parser
import gen_rulemanager as RM
from gen_parameters import *
from compr_core import Compressor

import socket
import binascii
import netifaces as ni


if __name__ == "__main__":

    # Form a raw packet to send over IPv4
    payload_data = b'1' * 60  # Example payload
    coap = CoAP(code=1, msg_id=0x0001, tkl=0x01, token=b"\x01")
    packet = (
        IPv6(src="aaaa::1", dst="2001:0:0:1::15") /
                UDP(sport=8888, dport=5683) /
                coap /
                Raw(load=b'\xFF' + payload_data)
    )
    raw_packet = raw(packet)
    
    print("Raw IPv6 Packet =", raw_packet.hex())
    packet.show()

    # Openschc setup
    addr = ni.ifaddresses('lo')[ni.AF_INET][0]['addr']
    PORT = 8888
    deviceID = "udp:"+addr+":"+str(PORT)
    print("device ID is", deviceID)
    # tunnel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # tunnel.bind (("0.0.0.0", PORT)) # same port as in the DeviceID

    # Appy Compression to raw packet (IPv6/UDP)
    rm = RM.RuleManager()
    rm.Add(file="ipv6udp.json")
    rm.Print()    

    t_dir = T_DIR_UP
    parser = Parser()
    parsed_packet, packet_payload, packet_residue = parser.parse(raw_packet, t_dir)
    print ("parsed packet =", parsed_packet)

    rule = rm.FindRuleFromPacket(parsed_packet, t_dir)
    test = rm.FindFragmentationRule(parsed_packet, t_dir)
    print ("rule found =", rule)

    if rule != None:
        compressor = Compressor()
        schc_pkt = compressor.compress(
                rule=rule, 
                parsed_packet=parsed_packet,
                data=packet_payload,
                direction=t_dir,
                verbose=False
        )

        print("SCHC packet in hex:")
        schc_pkt.display()
        # print("SCHC packet in binary")
        # schc_pkt.display(format="bin")
        print(schc_pkt.get_content())

        # IPv4 wrapper packet containing the raw packet -> send to CORE.
        wp = ( 
            IP(src="localhost", dst="localhost") /
            UDP(dport=12345) / 
            Raw(load=schc_pkt.get_content())
        )

        raw_wp = raw(wp)
        print("Raw IPv4 Packet =", raw_wp.hex())
        
        #send(wp)
        # Send the SCHC packet over a real UDP socket to match receiver expectations
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.sendto(schc_pkt.get_content(), ("127.0.0.1", 12345))
            print("Sent SCHC packet via UDP socket")
            print("Le MTU est : ", MTU)
            print("Rule de frag trouvée : ",test)



