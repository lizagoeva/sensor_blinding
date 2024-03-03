import packet_crafter
import json
import re
import socket
import struct
import fcntl
from logger import *

LOGFILE = "./logs/run.log"
LOG_LEVEL = "info"
CONFIG_NAME = "sensor_blinding_config.json"
IPV4_REGEX = "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"


def check_config(config: dict):
    if re.match(config["target_ip"], IPV4_REGEX):
        return -1
    if config["use_interface"] not in socket.if_nameindex()[-1]:
        return -2
    return 0


def parse_config():
    try:
        with open(CONFIG_NAME, 'r') as config_file:
            config = json.load(config_file)['data']['config']
            data = json.load(config_file)['data']['snort_vars']
            return config, data
    except Exception as error:
        return error,


def get_mask_from_bits(bits: int) -> str:
    count = 0
    for i in range(32 - int(bits), 32):
        count |= (1 << i)
    return "%d.%d.%d.%d" % (
        (count & 0xff000000) >> 24, (count & 0xff0000) >> 16,
        (count & 0xff00) >> 8, (count & 0xff)
    )


def get_host_ifaces() -> list:
    logging.info("Network: Getting list of host network interfaces")
    try:
        host_ifaces = [str(pair[-1]) for pair in socket.if_nameindex()]
        clog("Network: List of interfaces formed successfully", LOG_INFO)
        clog("Network: Interfaces: " + " ".join(item for item in host_ifaces), LOG_INFO)
        return host_ifaces
    except Exception as error:
        clog("Network: An error occured while fetching a list of network interfaces", LOG_INFO)
        clog(f"Network: Error: {error}", LOG_INFO)
        return -1


def get_iface_address(ifname: str) -> str:
    clog(f"Getting IPv4 of network interface {ifname}", LOG_INFO)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        res = str(socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', bytes(ifname[:15], 'utf-8'))
        )[20:24]))
        s.close()
        clog(f"Network: IPv4 for {ifname} is {res}", LOG_DEBUG)
        return res
    except Exception as error:
        clog(f"Network: An error occured while getting {ifname} address", LOG_ERROR)
        clog(f"Network: Error: {error}", LOG_ERROR)
        return -1


def get_net_from_ip(cidr: str) -> str:
    netstruct = struct.Struct(">I")
    ip, bit_mask = cidr.split('/')
    ip, = netstruct.unpack(socket.inet_aton(ip))
    mask, = netstruct.unpack(socket.inet_aton(get_mask_from_bits(bit_mask)))
    return socket.inet_ntoa(netstruct.pack(ip & mask)) + f"/{bit_mask}"


def auto_interface():
    try:
        clog("Starting automatic interface picking", LOG_INFO)
        interfaces = get_host_ifaces()
        print(item for item in interfaces)
    except Exception as error:
        return error


def initial_dialog():
    clog("Welcome to Sensor Blinding Attack Script (GAFFK)", LOG_INFO)
    clog("Loading config...", LOG_INFO)
    config, data = parse_config()
    if isinstance(config, Exception):
        clog("An error has occurred while loading config", LOG_ERROR)
        clog(f"Error: {config}", LOG_ERROR)
        return -1
    clog("Config successfully loaded!", LOG_INFO)

    clog("Performing initial config checkup...", LOG_INFO)
    check_result = check_config(config)
    if check_result == -1:
        clog("Target IP not valid / not specified. Please check config file", LOG_ERROR)
        return -1
    if check_result == -2:
        clog("Source interface used for attack is not specified / not valid", LOG_WARN)
        clog("Interface will be chosen automatically", LOG_WARN)
        auto_interface()


def main():
    configure_logging(LOGFILE, LOG_LEVEL)
    if initial_dialog() == -1:
        exit(1)


if __name__ == "__main__":
    main()
