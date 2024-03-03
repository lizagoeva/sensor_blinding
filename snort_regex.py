import json
import re
from random import choice, randint

TCP_FLAGS = 'fsrpau21'
VALUABLE_PARAMS = 'content', 'flags'
PARAMETERS_DICT_KEYS = 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'raw'
CONTENT_MODIFIERS = 'depth', 'distance', 'offset'
# alert <protocol> <source_address> <source_port> -> <destination_address> <destination_port> <extra_params>
SNORT_RE = re.compile(
    r'^alert (\w+) (\$\w+|any|[\d.]+) (any|[$\w:\[\],]+) [-<]> (\$\w+|any|[\d.]+) (any|[$\w:\[\],]+) \((.*)\)'
)
SNORT_RULES_FILENAME = 'community.rules'
with open('sensor_blinding_config.json', 'r') as conf_file:
    SNORT_VARIABLES = json.load(conf_file)['data']['snort_vars']


def handle_parameters(parameters: list) -> list:
    for param_num in (1, 2, 3, 4):
        param_separated = parameters[param_num].strip('[]')
        param_separated = param_separated.split(',')
        if len(param_separated) > 1:
            for i in range(len(param_separated)):
                # todo обработать случай когда встречается переменная снорта, но в конфигах её нет
                if param_separated[i] in SNORT_VARIABLES.keys():
                    param_separated[i] = SNORT_VARIABLES[param_separated[i]]
                    if isinstance(param_separated[i], list):
                        param_separated.extend(param_separated[i])
                        del param_separated[i]
        elif str(param_separated[0]) in SNORT_VARIABLES.keys():
            parameters[param_num] = SNORT_VARIABLES[param_separated[0]]
        if isinstance(parameters[param_num], list):
            parameters[param_num] = choice(parameters[param_num])
        elif ':' in parameters[param_num] and param_num in (2, 4):
            if parameters[param_num][-1] == ':':
                start, end = int(parameters[param_num][:-1]), 65535
            else:
                start, end = [int(x) for x in parameters[param_num].split(':')]
            parameters[param_num] = randint(start, end)
        elif parameters[param_num] == 'any' and param_num in (2, 4):
            parameters[param_num] = randint(0, 65535)
    return parameters


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
            print(f'Неожиданный элемент в словаре контента: {key} -> {value}')

    return result_content


def snort_rules_parser() -> dict:
    with open(SNORT_RULES_FILENAME, 'r') as f:
        for rule in f.readlines():
            if not rule.startswith('alert'):
                continue
            parsed_items: re.Match = re.search(SNORT_RE, rule)
            if not parsed_items:
                print(f'совпадений не найдено: {rule}')
                continue
            parsed_items: tuple = parsed_items.groups()

            source_check = parsed_items[1] in ('$EXTERNAL_NET', 'any')
            destination_check = parsed_items[3] != '$EXTERNAL_NET' or parsed_items[3] == 'any'
            content_check = 'content:!"' not in parsed_items[-1]
            if not (source_check and destination_check and content_check):
                continue

            parsed_items: list = handle_parameters(list(parsed_items))
            parsed_items[-1] = raw_data_parser(parsed_items[-1])

            yield dict(zip(PARAMETERS_DICT_KEYS, parsed_items))


for i in snort_rules_parser():
    pass

# todo перспективы развития: отрицательные distance (вместе с модификаторами контента - */+/!)
