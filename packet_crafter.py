from scapy.all import *


class PacketCrafter:
    def __init__(self):
        self.packet = None
        self.packet_list = []

    def craft(self, proto: str = None, destination_addr: str = None, src_port: str = None, flags: str = None, content: str = None):
        if not destination_addr:
            return -1

        network_layer_address_src = []
        network_layer_address_src.extend(destination_addr.split(":"))

        self.packet_add_l1()

        self.packet_add_l3(dst_ip=network_layer_address_src[0])

        if len(network_layer_address_src) > 1:
            self.packet_add_l4(proto=proto, dst_port=network_layer_address_src[1], src_port=src_port, flags=flags if flags else None)

        self.packet_add_load(content)

    def packet_add_l2(self): self.packet = Ether()

    def packet_add_l3(self, dst_ip: str): self.packet /= IP(dst=dst_ip)

    def packet_add_l4(self, proto: str, dst_port: str, src_port: str, flags: str) -> int:
        proto_lowcase = proto.lower()
        if proto_lowcase == 'tcp':
            try:
                self.packet /= TCP(dport=int(dst_port), sport=int(src_port), flags=flags)
                return 0
            except Exception as err:
                print(err)
                print(dst_port)
        elif proto_lowcase == 'udp':
            try:
                self.packet /= UDP(dport=int(dst_port), sport=int(src_port))
                return 0
            except Exception as err:  # todo парсинг портов
                print(err)
                print(dst_port)
        elif proto_lowcase == 'ip':
            return 0
        return 1

    def packet_add_load(self, load):
        self.packet /= Raw(load)
