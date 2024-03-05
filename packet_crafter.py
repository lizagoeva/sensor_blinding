from scapy.all import *


class PacketCrafter:
    def __init__(self):
        self.packet = None
        self.packet_list = []

    def craft(self, proto: str = None, destination_addr: str = None, flags: str = None, content: str = None):
        if not destination_addr:
            return -1

        network_layer_address_src = []
        network_layer_address_src.extend(destination_addr.split(":"))

        # network_layer_address_dst = []
        # network_layer_address_dst.extend(source_addr.split(":"))

        self.packet_add_l1()

        self.packet_add_l3(dst_ip=network_layer_address_src[0])

        if len(network_layer_address_src) > 1:
            self.packet_add_l4(proto=proto, dst_port=network_layer_address_src[1], src_port="22", flags=flags if flags else '')

        self.packet_add_load(content)

    def packet_add_l1(self): self.packet = Ether()

    def packet_add_l3(self, dst_ip: str): self.packet /= IP(dst=dst_ip)

    def packet_add_l4(self, proto: str, dst_port: str, src_port: str, flags: str) -> int:
        proto_lowcase = proto.lower()
        if proto_lowcase == 'tcp':
            try:
                self.packet /= TCP(dport=int(dst_port), sport=int(src_port), flags=flags)
                return 0
            except Exception as err:  # todo парсинг портов
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

    def packet_add_load(self, load: str):
        self.packet /= Raw(load=load)


# test branch
# test
# здесь была лизобчка

# def main() -> None:
#     crafter = PacketCrafter()
#     crafter.craft(proto='tcp', destination_addr='10.10.10.10:53')
#     print(crafter.packet)
#
#
# if __name__ == "__main__":
#     main()
