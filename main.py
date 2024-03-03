import packet_crafter
import json
import re
import socket
import logging
from logger import *

LOGFILE_NAME = "output.log"
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


def main():
    configure_logging()
    if initial_dialog() == -1:
        exit(1)


if __name__ == "__main__":
    main()
