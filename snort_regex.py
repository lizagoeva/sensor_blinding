import json
import re
from logger import *

TCP_FLAGS = 'fsrpau21'
VALUABLE_PARAMS = 'content', 'flags'
PARAMETERS_DICT_KEYS = 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'raw'
CONTENT_MODIFIERS = 'depth', 'distance', 'offset'
# alert <protocol> <source_address> <source_port> -> <destination_address> <destination_port> <extra_params>
SNORT_RE = re.compile(
    r'^alert (\w+) (\$\w+|any|[\d.]+) (any|[$\w:\[\],]+) [-<]> (\$\w+|any|[\d.]+) (any|[$\w:\[\],]+) \((.*)\)'
)
PARSED_RULES_NUM = 0
CONFIG_FILENAME = 'sensor_blinding_config.json'
try:
    with open(CONFIG_FILENAME, 'r') as conf_file:
        SNORT_VARIABLES = json.load(conf_file)['data']['snort_vars']
except Exception as err:
    clog('An error has occurred while loading config', LOG_ERROR)
    clog(f'Error message: {err}', LOG_ERROR)
    # todo чи шо делать?


def port_filter_match(port_str: str, port_value: int) -> bool:
    if port_str == 'any':
        return True
    ports_separated = port_str.strip('[]')
    ports_separated = ports_separated.split(',')
    for port in ports_separated:
        if port in SNORT_VARIABLES.keys():
            port = SNORT_VARIABLES[port]
            if isinstance(port, list):
                for item in port:
                    if isinstance(item, int) and item == port_value:
                        return True
            elif isinstance(port, int) and port == port_value:
                return True
        elif isinstance(port, str) and re.match(re.compile(r'\$\w+'), port):
            clog(f'Found unknown snort variable: {port}', LOG_WARN)
            return False
        elif ':' in port:
            if port[-1] == ':':
                port_range = range(int(port[:-1]), 65536)
            else:
                start, end = map(int, port.split(':'))
                port_range = range(start, end + 1)
            if port_value in port_range:
                return True
        elif port.isdigit() and int(port) == port_value:
            return True
        return False


def raw_data_parser(data_string: str) -> dict:
    result_attrs = dict()
    contents_data, content_num = dict(), 0
    tcp_flags = None

    for item in [_.removesuffix(';') for _ in data_string.split('; ')]:
        if ':' in item:
            k, v = [string.strip('"') for string in item.split(':', 1)]
            if k == 'content':
                contents_data[str(content_num)] = v
                content_num += 1
            elif k == 'flags':
                v = v.replace('+', '').replace('*', '')
                if ',' in v:
                    v = v[:v.index(',')]
                tcp_flags = []
                for flag in TCP_FLAGS:
                    tcp_flags.append(1) if flag in v.lower() else tcp_flags.append(0)
                if '!' in v:
                    tcp_flags = [f ^ 1 for f in tcp_flags]
            elif k in CONTENT_MODIFIERS:
                contents_data[k] = v
            elif k in VALUABLE_PARAMS:
                result_attrs[k] = v
        elif item in VALUABLE_PARAMS:
            result_attrs[item] = True

    result_attrs['content'] = handle_content(contents_data) if contents_data else None
    result_attrs['flags'] = tcp_flags

    return result_attrs


def handle_content(content_data: dict) -> str:
    result_content = ''
    current_content_bytes_num = 0
    for key, value in content_data.items():
        if key == 'offset':
            value = int(value)
            result_content = '\\x00' * (value - len(result_content) // 4 + current_content_bytes_num) + result_content
        elif key == 'distance':
            value = int(value)
            insert_index = (len(result_content) // 4 - current_content_bytes_num) * 4
            result_content = result_content[:insert_index] + '\\x00' * value + result_content[insert_index:]
        elif key.isdigit():
            current_content_bytes_num = 0
            content_separated = value.split('|')
            for chunk_num in range(len(content_separated)):
                if chunk_num % 2:
                    for hex_byte in content_separated[chunk_num].split():
                        result_content += ('\\x' + hex_byte.lower())
                        current_content_bytes_num += 1
                else:
                    for symbol in content_separated[chunk_num]:
                        result_content += ('\\x' + '%02x' % ord(symbol))
                        current_content_bytes_num += 1
        elif key == 'depth':
            value = int(value)
            if value < current_content_bytes_num:
                result_content = result_content[:(4 * (current_content_bytes_num - value))]
        else:
            clog(f'Unexpected item in content data: {key} -> {value}', LOG_WARN)

    return result_content


def snort_rules_parser(filename: str) -> dict:
    global PARSED_RULES_NUM

    # todo аргументы из консоли
    protocol = 'tcp'
    ipaddr = '10.10.10.10'
    port = 22

    with open(filename, 'r') as f:
        for rule in f.readlines():
            if not rule.startswith('alert'):
                continue
            parsed_items = re.search(SNORT_RE, rule)
            if not parsed_items:
                clog(f'Rule does not match regex: {rule}', LOG_WARN)
                continue
            parsed_items = list(parsed_items.groups())

            source_check = parsed_items[1] in ('$EXTERNAL_NET', 'any')
            destination_check = parsed_items[3] != '$EXTERNAL_NET' or parsed_items[3] == 'any'
            content_check = 'content:!"' not in parsed_items[-1]
            if not (source_check and destination_check and content_check):
                continue
            # print(parsed_items)

            # filters check
            protocol_check = parsed_items[0] == protocol
            ip_check = parsed_items[3] in ('any', ipaddr)
            if not (protocol_check and ip_check and port_filter_match(parsed_items[4], port)):
                continue
            parsed_items[3], parsed_items[4] = ipaddr, port

            # parsed_items = handle_parameters(list(parsed_items))
            # if not parsed_items:
            #     continue
            parsed_items[-1] = raw_data_parser(parsed_items[-1])

            yield dict(zip(PARAMETERS_DICT_KEYS, parsed_items))
            PARSED_RULES_NUM += 1
    clog(f'{PARSED_RULES_NUM} rules parsed successfully!', LOG_INFO)


# for i in snort_rules_parser('community.rules'):
#     print(i)

# Перспективы развития: отрицательные distance (вместе с модификаторами контента - */+/!)
