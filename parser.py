import re


def parse_snort_rule(rule):
    # Регулярное выражение для извлечения параметров из строки правила
    pattern = r'^\s*(?:(?!#).*alert\s+(?P<protocol>\S+)\s+(?P<source_address>\S+)\s+(?P<source_port>\S+)\s+->\s+(?P<destination_address>\S+)\s+(?P<destination_port>\S+)\s+\(.*content:"(?P<content>[^"]*)".*;)?'
    match = re.match(pattern, rule)
    if match:
        return match.groupdict()
    else:
        return None

def parse_snort_rules(rules_file, protocol, port, host):
    parsed_rules = []

    # Чтение правил из файла
    with open(rules_file, 'r') as f:
        rules = f.readlines()

    # Парсинг правил
    for rule in rules:
        parsed_rule = parse_snort_rule(rule)
        if parsed_rule:
            # Проверка соответствия заданным параметрам
            if (parsed_rule["protocol"] == protocol and
                ("any" in parsed_rule["source_port"] or
                (len(parsed_rule["source_port"].split(":")) > 1 and parsed_rule["source_port"].split(":")[1] == str(port))) and
                parsed_rule["destination_address"] == host):
                parsed_rules.append(parsed_rule)

    return parsed_rules

# Пример использования
rules_file = "community.rules"
protocol = "tcp"
port = 2589
host = "$EXTERNAL_NET"

filtered_rules = parse_snort_rules(rules_file, protocol, port, host)
for rule in filtered_rules:
    print(rule)
