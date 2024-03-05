import json
import argparse
from scapy.all import *

import packet_crafter
from logger import *
import snort_regex

DIRNAME = os.path.dirname(os.path.realpath(__file__))
LOGFILE = os.path.join(DIRNAME, 'logs', 'run.log')
LOG_LEVEL = "info"
CONFIG_NAME = "sensor_blinding_config.json"
IPV4_REGEX = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"


def parse_config() -> tuple:
    try:
        with open(CONFIG_NAME, 'r') as config_file:
            config_data = json.load(config_file)['data']
            config = config_data['config']
            snort_vars = config_data['snort_vars']
            rules_filename = config_data['rules_filename']
            return config, snort_vars, rules_filename
    except Exception as error:
        return error, None, None


def main():
    configure_logging(LOGFILE, LOG_LEVEL)
    config_data, snort_vars, snort_rules_filename = parse_config()

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--protocol', default='any', dest='protocol', help='Transfer protocol')
    arg_parser.add_argument('--dst-ip', default='any', dest='dst_ip', help='Destination IP-address')
    arg_parser.add_argument('--dst-port', default='any', dest='dst_port', help='Destination port')
    args = arg_parser.parse_args()
    protocol = args.protocol
    dst_ip = args.dst_ip
    dst_port = args.dst_port

    for parsed in snort_regex.snort_rules_parser(snort_rules_filename, protocol, dst_ip, dst_port):
        crafter = packet_crafter.PacketCrafter()
        content = parsed['raw']['content']
        crafter.craft(
            proto=parsed['protocol'],
            destination_addr=':'.join(map(str, (parsed['dst_ip'], parsed['dst_port']))),
            flags=parsed['raw']['flags'],
            src_port=parsed['src_port'],
            content=bytes.fromhex(content.replace('\\x', '')) if content else None
        )
        clog(f"Packet: {crafter.packet}: ", LOG_INFO)
        clog(hexdump(crafter.packet), LOG_INFO)
        sendp(crafter.packet, iface=config_data['use_interface'])


if __name__ == "__main__":
    main()
