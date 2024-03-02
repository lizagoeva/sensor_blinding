import json
import re
from random import choice, randint

TCP_FLAGS = 'fsrpau21'
VALUABLE_PARAMS = 'content', 'flags'
PARAMETERS_DICT_KEYS = ['protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'raw']
# alert <protocol> <source_address> <source_port> -> <destination_address> <destination_port> <extra_params>
SNORT_RE = re.compile(
    r'^alert (\w+) (\$\w+|any|[\d.]+) (any|[$\w:\[\],]+) [-<]> (\$\w+|any|[\d.]+) (any|[$\w:\[\],]+) \((.*)\)'
)
SNORT_RULES_FILENAME = 'community.rules'
with open('sensor_blinding_config.json', 'r') as conf_file:
    SNORT_VARIABLES = json.load(conf_file)['data']['snort_vars']

'''
with_flags = (
    'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"POLICY-OTHER Sandvine PacketLogic http redirection attempt"; flow:to_client,established; content:"Temporary Redirect"; fast_pattern:only; id:13330; fragbits:!MDR; flags:FA; content:"307"; depth:3; http_stat_code; content:"Temporary Redirect"; nocase; http_stat_msg; metadata:ruleset community, service http; reference:url,citizenlab.ca/2018/03/bad-traffic-sandvines-packetlogic-devices-deploy-government-spyware-turkey-syria; reference:url,github.com/citizenlab/badtraffic; classtype:misc-activity; sid:45983; rev:3;)',
    'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"OS-LINUX Linux Kernel Challenge ACK provocation attempt"; flow:to_server,no_stream; flags:R; detection_filter:track by_src, count 200, seconds 1; metadata:policy max-detect-ips drop, ruleset community; reference:bugtraq,91704; reference:cve,2016-5696; reference:cve,2017-7285; classtype:attempted-admin; sid:40063; rev:5;)',
    'alert tcp $EXTERNAL_NET any <> $HOME_NET 179 (msg:"SERVER-OTHER BGP spoofed connection reset attempt"; flow:established,no_stream; flags:RSF*; detection_filter:track by_dst,count 10,seconds 10; metadata:ruleset community; reference:bugtraq,10183; reference:cve,2004-0230; reference:url,www.uniras.gov.uk/vuls/2004/236929/index.htm; classtype:attempted-dos; sid:2523; rev:15;)',
    'alert tcp $EXTERNAL_NET any -> $HOME_NET 135:139 (msg:"SERVER-OTHER Winnuke attack"; flow:stateless; flags:U+; metadata:ruleset community; reference:bugtraq,2010; reference:cve,1999-0153; classtype:attempted-dos; sid:1257; rev:15;)',
    'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"INDICATOR-SCAN cybercop os probe"; flow:stateless; ack:0; flags:SFP; content:"AAAAAAAAAAAAAAAA"; depth:16; metadata:ruleset community, service http; reference:url,attack.mitre.org/techniques/T1018; reference:url,attack.mitre.org/techniques/T1040; reference:url,attack.mitre.org/techniques/T1046; classtype:attempted-recon; sid:1133; rev:18;)',
    'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"INDICATOR-SCAN synscan portscan"; flow:stateless; flags:SF; id:39426; metadata:ruleset community; reference:url,attack.mitre.org/techniques/T1018; reference:url,attack.mitre.org/techniques/T1040; reference:url,attack.mitre.org/techniques/T1046; classtype:attempted-recon; sid:630; rev:11;)',
    'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"INDICATOR-SCAN cybercop os SFU12 probe"; flow:stateless; ack:0; flags:SFU12; content:"AAAAAAAAAAAAAAAA"; depth:16; metadata:ruleset community; reference:url,attack.mitre.org/techniques/T1018; reference:url,attack.mitre.org/techniques/T1040; reference:url,attack.mitre.org/techniques/T1046; classtype:attempted-recon; sid:627; rev:13;)',
    'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"INDICATOR-SCAN cybercop os PA12 attempt"; flow:stateless; flags:PA12; content:"AAAAAAAAAAAAAAAA"; depth:16; metadata:ruleset community; reference:url,attack.mitre.org/techniques/T1018; reference:url,attack.mitre.org/techniques/T1040; reference:url,attack.mitre.org/techniques/T1046; classtype:attempted-recon; sid:626; rev:13;)',
    'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"INDICATOR-SCAN ipEye SYN scan"; flow:stateless; flags:S; seq:1958810375; metadata:ruleset community; reference:url,attack.mitre.org/techniques/T1018; reference:url,attack.mitre.org/techniques/T1040; reference:url,attack.mitre.org/techniques/T1046; classtype:attempted-recon; sid:622; rev:12;)',
    'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"INDICATOR-SCAN cybercop os probe"; flow:stateless; isdataat:!0; flags:SF12; metadata:ruleset community; reference:url,attack.mitre.org/techniques/T1018; reference:url,attack.mitre.org/techniques/T1040; reference:url,attack.mitre.org/techniques/T1046; classtype:attempted-recon; sid:619; rev:12;)',
    'alert tcp $EXTERNAL_NET 31790 -> $HOME_NET 31789 (msg:"MALWARE-BACKDOOR hack-a-tack attempt"; flow:stateless; flags:A+; content:"A"; depth:1; metadata:ruleset community; classtype:attempted-recon; sid:614; rev:13;)',
    'alert tcp $EXTERNAL_NET 10101 -> $HOME_NET any (msg:"INDICATOR-SCAN myscan"; flow:stateless; ack:0; flags:S; ttl:>220; metadata:ruleset community; reference:url,attack.mitre.org/techniques/T1018; reference:url,attack.mitre.org/techniques/T1040; reference:url,attack.mitre.org/techniques/T1046; classtype:attempted-recon; sid:613; rev:11;)',
    'alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"SERVER-MAIL sniffit overflow"; flow:to_server,established; isdataat:512; flags:A+; content:"from|3A 90 90 90 90 90 90 90 90 90 90 90|"; nocase; metadata:ruleset community, service smtp; reference:bugtraq,1158; reference:cve,2000-0343; classtype:attempted-admin; sid:309; rev:17;)',
    'alert tcp $EXTERNAL_NET 5714 -> any any (msg:"MALWARE-BACKDOOR WinCrash 1.0 Server Active"; flow:stateless; flags:SA,12; content:"|B4 B4|"; metadata:ruleset community; classtype:misc-activity; sid:163; rev:14;)',
    'alert tcp $EXTERNAL_NET 5714 -> any any (msg:"MALWARE-BACKDOOR WinCrash 1.0 Server Active"; flow:stateless; flags:SA!; content:"|B4 B4|"; metadata:ruleset community; classtype:misc-activity; sid:163; rev:14;)',
)
'''

# todo
#  3) если в контенте есть восклицательный знак (перед кавычками после двоеточия!!) то его тоже скипать


def handle_parameters(parameters: list) -> list:
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
    content, tcp_flags = '', None

    for item in [_.removesuffix(';') for _ in data_string.split('; ')]:
        if ':' in item and item.split(':')[0] in VALUABLE_PARAMS:
            k, v = [string.strip('"') for string in item.split(':', 1)]
            if k == 'content':
                content += v
            elif k == 'flags':
                old_value = v
                v = v.replace('+', '').replace('*', '')
                if ',' in v:
                    v = v[:v.index(',')]
                tcp_flags = []
                for flag in TCP_FLAGS:
                    tcp_flags.append(1) if flag in v.lower() else tcp_flags.append(0)
                if '!' in v:
                    tcp_flags = [f ^ 1 for f in tcp_flags]
                new_value = tcp_flags
                print(f'{old_value} -> {new_value}')
            elif k in VALUABLE_PARAMS:
                result_attrs[k] = v
        elif item in VALUABLE_PARAMS:
            result_attrs[item] = True

    result_attrs['content'] = content if content else None
    result_attrs['flags'] = tcp_flags

    return result_attrs


def snort_rules_parser() -> dict:
    with open(SNORT_RULES_FILENAME, 'r') as f:
        for rule in f.readlines():
        # for rule in with_flags:
            if not rule.startswith('alert'):
                continue
            parsed_items: re.Match = re.search(SNORT_RE, rule)
            if not parsed_items:
                print(f'совпадений не найдено: {rule}')
                continue
            parsed_items: tuple = parsed_items.groups()

            source_check = parsed_items[1] in ('$EXTERNAL_NET', 'any')
            destination_check = parsed_items[3] != '$EXTERNAL_NET' or parsed_items[3] == 'any'
            if not (source_check and destination_check):
                continue

            parsed_items: list = handle_parameters(list(parsed_items))
            parsed_items[-1] = raw_data_parser(parsed_items[-1])

            yield dict(zip(PARAMETERS_DICT_KEYS, parsed_items))


for i in snort_rules_parser():
    print(i)
