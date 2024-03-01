import json
import re
from random import choice

RULE_PARAMS = 'content', 'flags'
# alert <protocol> <source_address> <source_port> -> <destination_address> <destination_port> <extra_params>
SNORT_RE = re.compile(
    r'^alert (\w+) (\$\w+|any|[\d.]+) (any|[$\w:\[\],]+) [-<]> (\$\w+|any|[\d.]+) (any|[$\w:\[\],]+) \((.*)\)'
)
SNORT_RULES_FILENAME = 'community.rules'
with open('sensor_blinding_config.json', 'r') as conf_file:
    SNORT_VARIABLES = json.load(conf_file)['data']['snort_vars']

# todo
#  1) создать файлик с конфигами снорта (json с переменными снорта $HOME_NET, $HTTPS_PORTS и тд),
#  вытягивать из строки правила снорта перемнную, и далее при генерации словаря подставлять туда соответствующее
#  значение из конфига и в словарь их и подставлять
#  2) если content встречается более 1 раза то скипаем его
#  3) если в контенте есть восклицательный знак (перед кавычками после двоеточия!!) то его тоже скипать


def extra_data_parser(data_string: str):
    result_attrs = dict()
    for item in [_.removesuffix(';') for _ in data_string.split('; ')]:
        if ':' in item and item.split(':')[0] in RULE_PARAMS:
            k, v = [string.strip('"') for string in item.split(':')]
            if k in result_attrs:
                if isinstance(result_attrs[k], str):
                    result_attrs[k] = [result_attrs[k], v]
                else:
                    result_attrs[k].append(v)
            else:
                result_attrs[k] = v
            if len(result_attrs[k]) == 3:
                print(f'3: {data_string}')
        elif item in RULE_PARAMS:
            result_attrs[item] = True
    print(result_attrs)
    # content_count, flags_count = msg.count('content'), msg.count('flags')
    # print(f'content: {content_count}')
    # print(f'flags: {flags_count}')


def replace_snort_variables(parameters: list):
    print(f'исходные параметры: {parameters}')
    for param_num in (1, 2, 3, 4):
        param_separated = parameters[param_num].strip('[]')
        param_separated = param_separated.split(',')
        if len(param_separated) > 1:
            for i in range(len(param_separated)):
                if param_separated[i] in SNORT_VARIABLES.keys():
                    param_separated[i] = SNORT_VARIABLES[param_separated[i]]
                    if isinstance(param_separated[i], list):
                        param_separated.extend(param_separated[i])
                        del param_separated[i]
            parameters[param_num] = choice(param_separated)
        elif str(param_separated[0]) in SNORT_VARIABLES.keys():
            parameters[param_num] = SNORT_VARIABLES[param_separated[0]]
    print(f'полученные параметры: {parameters}')
    quit()

    # todo реализовать логику подстановки значений вместо переменных
    #  (для форматов как $HOME_NET, так и [$HTTP_PORTS,3000,5156,7218])
    pass


# todo проверки -> оставляем правило, иначе скипаем
#  (
#  1) исходит из ext net (source = externalnet)
#  or
#  2) source = "any"
#  )
#  and
#  (
#  3) цель - любая из переменных кроме external net
#  or
#  4) цель - "any"
#  )


def snort_rules_parser():
    rules_parsed_full = []
    with open(SNORT_RULES_FILENAME, 'r') as f:
        for rule in f.readlines():
            if not rule.startswith('alert'):
                continue
            parsed_items = re.search(SNORT_RE, rule)
            if not parsed_items:
                print(f'совпадений не найдено: {rule}')
                continue
            parsed_items = parsed_items.groups()
            if (parsed_items[])
            replace_snort_variables(list(parsed_items))

    return rules_parsed_full


# todo передавать флаги посимвольно
#  модификаторы во флагах
#  + - игнорировать
#  * - игнорировать
#  ! - убрать 1 букву перед ! (SA! -> S)
#  , - всё после запятой игнорировать

snort_rules_parser()

# todo total
#  1) подстановка переменных
#  2) парсинг флагов (см выше)
#  3) парсинг контента
