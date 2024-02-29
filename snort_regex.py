import json
import re

RULE_PARAMS = 'content', 'flags'


def msg_parser(msg: str):
    result_attrs = dict()
    for item in [_.removesuffix(';') for _ in msg.split('; ')]:
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
                print(f'3: {msg}')
        elif item in RULE_PARAMS:
            result_attrs[item] = True
    print(result_attrs)
    # content_count, flags_count = msg.count('content'), msg.count('flags')
    # print(f'content: {content_count}')
    # print(f'flags: {flags_count}')


snort_re = re.compile(r'^alert (\w+) (\$EXTERNAL_NET|\$HOME_NET|any|[\d.]+) (any|\d+|[\d:]+) [-<]> (\$EXTERNAL_NET|\$HOME_NET|any|[\d.]+) (any|\d+|[\d:]+) \((.*)\)')
data = [
    'alert tcp 10.1.1.1 30100:30102 -> 1.1.1.1 any (msg:"MALWARE-BACKDOOR NetSphere access"; flow:established,to_client; content:"NetSphere"; metadata:ruleset community; classtype:trojan-activity; sid:146; rev:13;)',
    'alert tcp any 6969 -> 255.255.255.255 any (msg:"MALWARE-BACKDOOR GateCrasher"; flow:established,to_client; content:"GateCrasher"; depth:11; nocase; content:"Server"; distance:0; nocase; content:"On-Line..."; distance:0; nocase; pcre:"/^GateCrasher\s+v\d+\x2E\d+\x2C\s+Server\s+On-Line\x2E\x2E\x2E/smi"; metadata:policy max-detect-ips drop, ruleset community; reference:url,www.spywareguide.com/product_show.php?id=973; classtype:trojan-activity; sid:147; rev:12;)',
    'alert tcp any any -> any any (msg:"MALWARE-BACKDOOR BackConstruction 2.1 Connection"; flow:established,to_client; content:"c|3A 5C|"; metadata:ruleset community; classtype:misc-activity; sid:152; rev:11;)',
    'alert tcp 127.0.0.1 any -> any 666 (msg:"MALWARE-BACKDOOR BackConstruction 2.1 Client FTP Open Request"; flow:to_server,established; content:"FTPON"; metadata:ruleset community; classtype:misc-activity; sid:157; rev:9;)',
    'alert tcp 1.1.1.1 any <> 23.23.23.23 179 (msg:"SERVER-OTHER BGP spoofed connection reset attempt"; flow:established,no_stream; flags:RSF*; detection_filter:track by_dst,count 10,seconds 10; metadata:ruleset community; reference:bugtraq,10183; reference:cve,2004-0230; reference:url,www.uniras.gov.uk/vuls/2004/236929/index.htm; classtype:attempted-dos; sid:2523; rev:15;)',
    'alert tcp any 5714 -> any any (msg:"MALWARE-BACKDOOR WinCrash 1.0 Server Active"; flow:stateless; flags:SA,12; content:"|B4 B4|"; metadata:ruleset community; classtype:misc-activity; sid:163; rev:14;)',
    'alert tcp any any -> 2.3.4.5 25 (msg:"SERVER-MAIL sniffit overflow"; flow:to_server,established; isdataat:512; flags:A+; content:"from|3A 90 90 90 90 90 90 90 90 90 90 90|"; nocase; metadata:ruleset community, service smtp; reference:bugtraq,1158; reference:cve,2000-0343; classtype:attempted-admin; sid:309; rev:17;)',
]
for i in data:
    res = re.search(snort_re, i)
    if res:
        res = res.groups()
        print(res)
        result = {
            'protocol': res[0],
            'destination_address': res[1],
            'destination_port': res[2],
            'source_port': res[4],
            'params': msg_parser(res[-1]),
        }
    else:
        print(f'нет совпадений - {i}')
    # if res:
    #     print(res.groups())
    #     # msg_parser(res.groups()[-1])
    # else:
    #     print('совпадений не найдено\n')
