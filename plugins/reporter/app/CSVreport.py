
import json



def create_csv(report_id, path):
    with open(path + 'detectionreports/' + report_id + '.json') as f:
            report = json.load(f)
            tests = report['tests']

    output = 'Test ID§Test name§Mitre ID§Category§Command§Description§Status§Detected§Tanium§Cortex§QRadar§Tanium Signals§Cortex BIOCs§QRadar Offenses\n'
    for test in tests:
        output += test['testid'] + '§'
        output += str(test['name']) + '§'
        output += test['attack']['technique_id'] + '§'
        output += test['attack']['tactic'] + '§'
        output += '€'.join(test['command'].splitlines()) + '§'
        output += '€'.join(test['description'].splitlines()) + '§'
        output += test['status'] + '§'
        output += str(test['detected']) + '§'
        output += str(len(test['detection']['tanium_signals']) > 0) + '§'
        output += str(len(test['detection']['cortex_alerts']) > 0) + '§'
        output += str(len(test['detection']['qradar_offenses']) > 0) + '§'
        tan_sig = ''
        for alert in test['detection']['tanium_signals']:
            tan_sig += alert[0][3] + ', '
        tan_sig = tan_sig[:-2]
        output += tan_sig + '§'
        xdr_bioc = ''
        for alert in test['detection']['cortex_alerts']:
            xdr_bioc += alert['name'].encode('utf-8') + ', '
        xdr_bioc = xdr_bioc[:-2]
        output += xdr_bioc + '§'
        qra_off = '' #note implemented
        output += qra_off + '\n'
    
    return output
