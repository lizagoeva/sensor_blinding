import re
from random import randint
from log_conf import parser_logger


def parse_snort_rule(rule):

    # Регулярное выражение для извлечения параметров из строки правила
    pattern = r'^\s*(?:(?!#).*alert\s+(?P<protocol>\S+)\s+(?P<source_address>\S+)\s+(?P<source_port>\S+)\s+->\s+(?P<destination_address>\S+)\s+(?P<destination_port>\S+)\s+\(.*content:"(?P<content>[^"]*)".*;)?'
    match = re.match(pattern, rule)
    if match:
        return match.groupdict()
    else:
        return None

def parse_snort_rules(rules_file, protocol, host, port):
    parsed_rules = []

    # Чтение правил из файла
    with open(rules_file, 'r') as f:
        rules = f.readlines()

    # Парсинг правил
    for rule in rules:
        parsed_rule = parse_snort_rule(rule)
        if parsed_rule:
            
            # Проверка по протоколу и destiination_port
            if (parsed_rule["protocol"] == protocol and
                parsed_rule["destination_address"] == host and
                ("any" in parsed_rule["destination_port"] or
                parsed_rule["destination_port"] == str(port) or
                len(parsed_rule["destination_port"].split(":")) > 1 and 
                parsed_rule["destination_port"].split(":")[1] == str(port))):
                
                # Проверка по source_port
                if "any" in parsed_rule["source_port"]:
                    parsed_rule["source_port"] = str(randint(1234, 65535))

                if type(parsed_rule["source_port"]) is not int:
                    if type(parsed_rule["source_port"].strip('[]').split(',')) is list:
                        parsed_rule["source_port"] = parsed_rule["source_port"].strip('[]').split(",")[0]

                    elif len(parsed_rule["source_port"].split(":")) > 1:
                        parsed_rule["source_port"] = parsed_rule["source_port"].split(":")[1]

                parsed_rules.append(parsed_rule)

    keys = ['rules_file', 'protocol', 'host', 'port', 'rules', 'parsed_rules']
    values = [rules_file, protocol, host, port, len(rules), len(parsed_rules)]
    parser_logger(dict(zip(keys,values)))
    return parsed_rules


# Пример использования
# rules_file = "community.rules"
# protocol = "tcp"
# port = 22
# host = "$EXTERNAL_NET"

# filtered_rules = parse_snort_rules(rules_file, protocol, port, host)
# for rule in filtered_rules:
#     print(rule)
