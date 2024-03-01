from scapy.all import *


class PacketCrafter:
    def __init__(self):
        self.packet = None
        self.packet_list = []

    def craft(self, proto: str = None, source_addr: str = None, destination_addr: str = None, flags: str = None):
        if not destination_addr:
            return -1

        network_layer_address_src = []
        network_layer_address_src.extend(destination_addr.split(":"))

        self.packet_add_l1()

        self.packet_add_l3(dst_ip=network_layer_address_src[0])

        if len(network_layer_address_src) > 1:
            self.packet_add_l4(proto=proto, dst_port=network_layer_address_src[1],
                                src_port="22", flags=flags if flags else '')

    def packet_add_l1(self): self.packet = Ether()

    def packet_add_l3(self, dst_ip: str): self.packet /= IP(dst=dst_ip)

    def packet_add_l4(self, proto: str, dst_port: str, src_port: str, flags, content: str) -> int:
        proto_lowcase = proto.lower()
        if proto_lowcase == 'tcp':
            self.packet /= TCP(dport=int(dst_port), sport=int(src_port),
                            flags="".join(item for item in flags), load=content)
            return 0
        elif proto_lowcase == 'udp':
            self.packet /= UDP(dport=int(dst_port), sport=int(src_port), load=content)
            return 0
        elif proto_lowcase == 'ip':
            return 0
        elif proto_lowcase == 'icmp':
            self.packet /= ICMP(type=flags[0], code=flags[1], load=content)
            return 0
        else:
            return 1


def main() -> None:
    crafter = PacketCrafter()
    crafter.craft(proto='tcp', destination_addr='10.10.10.10:53')
    print(crafter.packet)


if __name__ == "__main__":
    main()
