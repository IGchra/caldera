from datetime import datetime, timedelta
import time
import json
import socket
import logging
import base64
import csv

# import of own modules
from plugins.reporter.app.tanium import TaniumCon, TaniumResponse, taniumcaldera
from plugins.reporter.app.cortex import CortexCon, CortexResponse, cortexcaldera
from plugins.reporter.app.qradar import QradarCon, QradarResponse, qradarcaldera

##########################################
#### ---------- PARAMETERS ---------- ####
##########################################

path = ''
domain = ''
report = {}
jitter = 0
max_time = 0
status_mapper = {
    0: 'success',
    1: 'fail',
    2: 'timeout'
}

all_mitreIDs = [1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 
1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 
1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 
1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 
1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 
1098, 1099, 1100, 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1115, 1116, 1117, 
1118, 1119, 1120, 1121, 1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129, 1130, 1131, 1132, 1133, 1134, 1135, 1136, 1137, 
1138, 1139, 1140, 1141, 1142, 1143, 1144, 1145, 1146, 1147, 1148, 1149, 1150, 1151, 1152, 1153, 1154, 1155, 1156, 1157, 
1158, 1159, 1160, 1161, 1162, 1163, 1164, 1165, 1166, 1167, 1168, 1169, 1170, 1171, 1172, 1173, 1174, 1175, 1176, 1177, 
1178, 1179, 1180, 1181, 1182, 1183, 1184, 1185, 1186, 1187, 1188, 1189, 1190, 1191, 1192, 1193, 1194, 1195, 1196, 1197, 
1198, 1199, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 1209, 1210, 1211, 1212, 1213, 1214, 1215, 1216, 1217, 
1218, 1219, 1220, 1221, 1222, 1223, 1480, 1482, 1483, 1484, 1485, 1486, 1487, 1488, 1489, 1490, 1491, 1492, 1493, 1494, 
1495, 1496, 1497, 1498, 1499, 1500, 1501, 1502, 1503, 1504, 1505, 1506, 1514, 1518, 1519, 1525, 1526, 1527, 1528, 1529, 
1530, 1531, 1534, 1535, 1536, 1537, 1538, 1539]

def ts_to_datetime(timestamp):
    """ Converts timestamp as string to datetime
    :param alerted: str; timestamp
    :return datetime; timestamp as datetime object
    """
    return datetime(int(timestamp[:4]), int(timestamp[5:7]), int(timestamp[8:10]), int(timestamp[11:13]), int(timestamp[14:16]), int(timestamp[17:19]))


def generate_time_stamp(timestamp):
    time_str = str(timestamp)
    return time_str[:4] + time_str[5:7] + time_str[8:10] + time_str[11:13] + time_str[14:16] + time_str[17:19]


def test_details(step):
    return {
        'testid': step['ability_id'],
        'description': step['description'],
        'name': step['name'],
        'attack': step['attack'],
        'finished': step['run'],
        'status': status_mapper.setdefault(step['status'], 'timeout'),
        'command': base64.b64decode(step['command']).decode('utf8').replace("'", '"')
    }

def initialize_summary():
    overall = {
        'totaltests': 0,
        'successful_detected': 0,
        'unsuccessful_detected': 0,
        'other_detected': 0,
        'successful_undetected': 0,
        'unsuccessful_undetected': 0,
        'other_undetected': 0
    }
    overall_tanium = {
        'successful_detected': 0,
        'unsuccessful_detected': 0,
        'other_detected': 0,
        'successful_undetected': 0,
        'unsuccessful_undetected': 0,
        'other_undetected': 0
    }
    overall_qradar = {
        'successful_detected': 0,
        'unsuccessful_detected': 0,
        'other_detected': 0,
        'successful_undetected': 0,
        'unsuccessful_undetected': 0,
        'other_undetected': 0
    }
    overall_cortex = {
        'successful_detected': 0,
        'unsuccessful_detected': 0,
        'other_detected': 0,
        'successful_undetected': 0,
        'unsuccessful_undetected': 0,
        'other_undetected': 0
    }
    summary = {
        'tests_overall': overall,
        'tests_tanium': overall_tanium,
        'tests_qradar': overall_qradar,
        'tests_cortex': overall_cortex
    }

    return summary

def update_value(detected, status):

    if detected:
        if status == 'success':
            return 'successful_detected'
        elif status == 'fail':
            return 'unsuccessful_detected'
        else:
            return 'other_detected'
    else:
        if status == 'success':
            return 'successful_undetected'
        elif status == 'fail':
            return 'unsuccessful_undetected'
        else:
            return 'other_undetected'


def process_tanium(host, qra, xdr):

    steps = report['steps'][str(host['paw'])]['steps']
    if len(steps) == 0 or steps[0]['run'] == None:
        return ({}, {})

    tests = []
    summary = initialize_summary()

    tancon = TaniumCon()
    if qra:
        qracon = QradarCon()
    if xdr:
        xdrcon = CortexCon()

    """ Dear future editor:
    You might wonder why I solved this here so complicated. The reason is pretty simple:
    It is not possible to filter on date when requesting alerts over the Tanium API.
    If this should change in the future, please feel free to remove this :)
    """

    offset = 0
    computer_name = host['host'] + '.' + domain
    alerts = taniumcaldera(tancon, computer_name=computer_name, offset=offset).alerts
    if len(alerts) > 0:
        alerts.sort(key=lambda i: i[0][0])
        while ts_to_datetime(alerts[-1][0][0]) < ts_to_datetime(steps[0]['run']) + timedelta(seconds=jitter):
            offset += len(alerts)
            alerts = taniumcaldera(tancon, 
                computer_name=computer_name, offset=offset).alerts
            if len(alerts) == 0:
                offset = max(offset - 500, 0)
                alerts = taniumcaldera(tancon, 
                    computer_name=computer_name, offset=offset).alerts
                alerts.sort(key=lambda i: i[0][0])
                break
            else:
                alerts.sort(key=lambda i: i[0][0])

    n_step = 0
    n_alert = 0
    run = True
    tan_detected = []

    while run:
        while n_step < len(steps) and n_alert < len(alerts):
            alerted = ts_to_datetime(alerts[n_alert][0][0])
            if steps[n_step]['run']:
                ts = ts_to_datetime(steps[n_step]['run'])
            else:
                while n_step < len(steps) and not steps[n_step]['run']:
                    n_step += 1
                if n_step >= len(steps):
                    break
                else:
                    ts = ts_to_datetime(steps[n_step]['run'])
            start = ts - timedelta(seconds=max_time)
            if n_step < len(steps) - 1 and steps[n_step + 1]['run']:
                end = ts_to_datetime(
                    steps[n_step + 1]['run']) - timedelta(seconds=max_time)
            else:
                end = ts + timedelta(seconds=(jitter-max_time))

            if alerted >= start:
                if alerted < end:
                    # alert matches step. could have more
                    tan_detected.append(alerts[n_alert])
                    n_alert += 1
                else:
                    # alert does not mach step, but maybe later step
                    # write all information for this step
                    test = test_details(steps[n_step])
                    xdr_detected = []
                    if xdr:
                        xdr_detected = cortexcaldera(
                            xdrcon, start, end, host['host']).incidents
                    qra_detected = []
                    if qra:
                        qra_detected = qradarcaldera(
                            qracon, start, end, host['host']).offenses

                    if len(tan_detected) > 0 or len(xdr_detected) > 0 or len(qra_detected) > 0:
                        test['detected'] = True
                        summary['tests_overall'][update_value(True, test['status'])] += 1
                        summary['tests_tanium'][update_value((len(tan_detected) > 0), test['status'])] += 1
                        summary['tests_qradar'][update_value((len(qra_detected) > 0), test['status'])] += 1
                        summary['tests_cortex'][update_value((len(cor_detected) > 0), test['status'])] += 1
                    else:
                        test['detected'] = False
                        summary['tests_overall'][update_value(False, test['status'])] += 1
                        summary['tests_tanium'][update_value(False, test['status'])] += 1
                        summary['tests_qradar'][update_value(False, test['status'])] += 1
                        summary['tests_cortex'][update_value(False, test['status'])] += 1
                    
                    test['detection'] = {
                        'tanium_signals': tan_detected,
                        'cortex_alerts': xdr_detected,
                        'qradar_offenses': qra_detected
                    }
                    tests.append(test)
                    tan_detected = []
                    n_step += 1
                    summary['tests_overall']['totaltests'] += 1
            else:
                # alert occured before (first) step
                n_alert += 1
        # no more steps
        if n_step  >= len(steps):
            run = False
        else:
            # check for more alerts:
            offset = offset + len(alerts)
            alerts = taniumcaldera(tancon, 
                computer_name=computer_name, offset=offset).alerts
            if len(alerts) > 0:
                alerts.sort(key=lambda i: i[0][0])
            else:
                run = False

    while n_step < len(steps):
        # might not iterated through all steps
        if steps[n_step]['run']:
            ts = ts_to_datetime(steps[n_step]['run'])
        else:
            ts = ts_to_datetime(steps[0]['run'])
        start = ts - timedelta(seconds=max_time)
        if n_step < len(steps) - 1 and steps[n_step + 1]['run']:
            end = ts_to_datetime(
                steps[n_step + 1]['run']) - timedelta(seconds=max_time)
        else:
            end = ts + timedelta(seconds=(jitter-max_time))
        test = test_details(steps[n_step])
        xdr_detected = []
        if xdr:
            xdr_detected = cortexcaldera(xdrcon, start, end, host['host']).incidents
        qra_detected = []
        if qra:
            qra_detected = qradarcaldera(qracon, start, end, host['host']).offenses
        if len(tan_detected) > 0 or len(xdr_detected) > 0 or len(qra_detected) > 0:
            test['detected'] = True
            summary['tests_overall'][update_value(True, test['status'])] += 1
            summary['tests_tanium'][update_value((len(tan_detected) > 0), test['status'])] += 1
            summary['tests_qradar'][update_value((len(qra_detected) > 0), test['status'])] += 1
            summary['tests_cortex'][update_value((len(cor_detected) > 0), test['status'])] += 1
        else:
            test['detected'] = False
            summary['tests_overall'][update_value(False, test['status'])] += 1
            summary['tests_tanium'][update_value(False, test['status'])] += 1
            summary['tests_qradar'][update_value(False, test['status'])] += 1
            summary['tests_cortex'][update_value(False, test['status'])] += 1


        test['detection'] = {
            'tanium_signals': tan_detected,
            'cortex_alerts': xdr_detected,
            'qradar_offenses': qra_detected
        }
        tests.append(test)
        tan_detected = []
        n_step += 1
        summary['tests_overall']['totaltests'] += 1

    return (summary, tests)


def process_no_tanium(host, qra, xdr):

    steps = report['steps'][str(host['paw'])]['steps']
    if len(steps) == 0 or steps[0]['run'] == None:
        return({},{})
    tests = []
    summary = initialize_summary()
    if qra:
        qracon = QradarCon()
    if xdr:
        xdrcon = CortexCon()

    n_step = 0
    while n_step < len(steps):
        
        if steps[n_step]['run']:
            ts = ts_to_datetime(steps[n_step]['run'])
        else:
            while n_step < len(steps) and not steps[n_step]['run']:
                n_step += 1
            if n_step >= len(steps):
                break
            else:
                ts = ts_to_datetime(steps[n_step]['run'])
        start = ts - timedelta(seconds=max_time)
        if n_step < len(steps) - 1 and steps[n_step + 1]['run']:
            end = ts_to_datetime(
                steps[n_step + 1]['run']) - timedelta(seconds=max_time)
        else:
            end = ts + timedelta(seconds=(jitter-max_time))
        

        test = test_details(steps[n_step])

        tan_detected = []
        xdr_detected = []
        if xdr:
            xdr_detected = cortexcaldera(
                xdrcon, start, end, host['host']).incidents
        qra_detected = []
        if qra:
            qra_detected = qradarcaldera(
                qracon, start, end, host['host']).offenses

        if len(tan_detected) > 0 or len(xdr_detected) > 0 or len(qra_detected) > 0:
            test['detected'] = True
            summary['tests_overall'][update_value(True, test['status'])] += 1
            summary['tests_tanium'][update_value((len(tan_detected) > 0), test['status'])] += 1
            summary['tests_qradar'][update_value((len(qra_detected) > 0), test['status'])] += 1
            summary['tests_cortex'][update_value((len(cor_detected) > 0), test['status'])] += 1
        else:
            test['detected'] = False
            summary['tests_overall'][update_value(False, test['status'])] += 1
            summary['tests_tanium'][update_value(False, test['status'])] += 1
            summary['tests_qradar'][update_value(False, test['status'])] += 1
            summary['tests_cortex'][update_value(False, test['status'])] += 1

        test['detection'] = {
                'tanium_signals': tan_detected,
                'cortex_alerts': xdr_detected,
                'qradar_offenses': qra_detected
            }
        tests.append(test)
        n_step += 1
        summary['tests_overall']['totaltests'] += 1

    return (summary, tests)


def process_tets(host, tan, qra, xdr):

    if tan:
        return process_tanium(host, qra, xdr)
    else:
        return process_no_tanium(host, qra, xdr)


def process_techniques(tests, tan, qra, xdr):
    summary = {
        #'Txxxx: '0 = det/succ 
        # 1 = det/(un)succ 
        # 2 = det/unsucc 
        # 3 = (un)det/succ 
        # 4 = (un)det/(un)succ 
        # 5 = (un)det/unsucc 
        # 6 = undet/succ 
        # 7 = undet/(un)secc 
        # 8 = undet/unsucc'
    }

    for test in tests:
        if test['attack']['technique_id'] in summary.keys():
            if test['status'] == 'success':
                if test['detected']:
                    if summary[test['attack']['technique_id']] == 2:
                        summary[test['attack']['technique_id']] = 1
                    elif summary[test['attack']['technique_id']] == 5:
                        summary[test['attack']['technique_id']] = 4
                    elif summary[test['attack']['technique_id']] == 6:
                        summary[test['attack']['technique_id']] = 3
                    elif summary[test['attack']['technique_id']] == 7:
                        summary[test['attack']['technique_id']] = 4
                    elif summary[test['attack']['technique_id']] == 8:
                        summary[test['attack']['technique_id']] = 4
                else:
                    if summary[test['attack']['technique_id']] == 0:
                        summary[test['attack']['technique_id']] = 3
                    elif summary[test['attack']['technique_id']] == 1:
                        summary[test['attack']['technique_id']] = 4
                    elif summary[test['attack']['technique_id']] == 2:
                        summary[test['attack']['technique_id']] = 4
                    elif summary[test['attack']['technique_id']] == 5:
                        summary[test['attack']['technique_id']] = 4
                    elif summary[test['attack']['technique_id']] == 8:
                        summary[test['attack']['technique_id']] = 7
            else:
                if test['detected']:
                    if summary[test['attack']['technique_id']] == 0:
                        summary[test['attack']['technique_id']] = 1
                    elif summary[test['attack']['technique_id']] == 3:
                        summary[test['attack']['technique_id']] = 4
                    elif summary[test['attack']['technique_id']] == 6:
                        summary[test['attack']['technique_id']] = 4
                    elif summary[test['attack']['technique_id']] == 7:
                        summary[test['attack']['technique_id']] = 4
                    elif summary[test['attack']['technique_id']] == 8:
                        summary[test['attack']['technique_id']] = 5    
                else:
                    if summary[test['attack']['technique_id']] == 0:
                        summary[test['attack']['technique_id']] = 4
                    elif summary[test['attack']['technique_id']] == 1:
                        summary[test['attack']['technique_id']] = 4
                    elif summary[test['attack']['technique_id']] == 2:
                        summary[test['attack']['technique_id']] = 5
                    elif summary[test['attack']['technique_id']] == 3:
                        summary[test['attack']['technique_id']] = 4
                    elif summary[test['attack']['technique_id']] == 6:
                        summary[test['attack']['technique_id']] = 7                                      
        else:
            if test['status'] == 'success':
                if test['detected']:
                    summary[test['attack']['technique_id']] = 0
                else:
                    summary[test['attack']['technique_id']] = 6
            elif test['detected']:
                summary[test['attack']['technique_id']] = 2
            else:
                summary[test['attack']['technique_id']] = 8

    for elem in all_mitreIDs:
        if not 'T'+str(elem) in summary.keys():
            summary['T'+str(elem)] = 9    
    overview = {
        'total_techniques': 0,
        'det/succ': 0 ,
        'det/(un)succ': 0, 
        'det/unsucc': 0, 
        '(un)det/succ': 0, 
        '(un)det/(un)succ': 0, 
        '(un)det/unsucc': 0, 
        'undet/succ': 0, 
        'undet/(un)succ': 0, 
        'undet/unsucc': 0
    }
    tanium_overview = {
        'det/succ': 0 ,
        'det/(un)succ': 0, 
        'det/unsucc': 0, 
        '(un)det/succ': 0, 
        '(un)det/(un)succ': 0, 
        '(un)det/unsucc': 0, 
        'undet/succ': 0, 
        'undet/(un)succ': 0, 
        'undet/unsucc': 0
    }
    cortex_overview = {
        'total_techniques': 0,
        'det/succ': 0 ,
        'det/(un)succ': 0, 
        'det/unsucc': 0, 
        '(un)det/succ': 0, 
        '(un)det/(un)succ': 0, 
        '(un)det/unsucc': 0, 
        'undet/succ': 0, 
        'undet/(un)succ': 0, 
        'undet/unsucc': 0
    }
    qradar_overview = {
        'total_techniques': 0,
        'det/succ': 0 ,
        'det/(un)succ': 0, 
        'det/unsucc': 0, 
        '(un)det/succ': 0, 
        '(un)det/(un)succ': 0, 
        '(un)det/unsucc': 0, 
        'undet/succ': 0, 
        'undet/(un)succ': 0, 
        'undet/unsucc': 0
    }
    for key in summary.keys():
        overview['total_techniques'] += 1
        if summary[key] == 0:
            overview['det/succ'] += 1
        elif summary[key] == 1:
            overview['det/(un)succ'] += 1
        elif summary[key] == 2:
            overview['det/unsucc'] += 1
        elif summary[key] == 3:
            overview['(un)det/succ'] += 1
        elif summary[key] == 4:
            overview['(un)det/(un)succ'] += 1
        elif summary[key] == 5:
            overview['(un)det/unsucc'] += 1
        elif summary[key] == 6:
            overview['undet/succ'] += 1
        elif summary[key] == 7:
            overview['undet/(un)succ'] += 1
        elif summary[key] == 8:
            overview['undet/unsucc'] += 1
    techniques ={
        'overall': overview,
        'tanium': tanium_overview,
        'cortex': cortex_overview,
        'qradar': qradar_overview
    }
    return (techniques, summary)

def create_report(host, tan, qra, xdr):
    hostname = host['host']
    os = host['platform']
    run_id = generate_time_stamp(report['start']) + '-' + hostname + '-' + os
    global jitter
    global max_time
    jitter = int(report['jitter'].split('/', 1)[0])
    max_time = int(host['sleep_min'])
    settings = {
        'host': host['host'],
        'platform': host['platform'],
        'privilege': host['privilege'],
        'max_time': max_time,
        'jitter': jitter,
        'tanium': tan,
        'qradar': qra,
        'xdr': xdr,
        'testname': report['name']
    }
    start = str(report['start'])

    techniques = []


    (summary, tests) = process_tets(host, tan, qra, xdr)

    if len(tests) == 0:
        return {}

    tests.sort(key=lambda x: 
            (x['attack']['technique_id'], x['testid']), reverse=False)

    (techniques_summary, techniques) = process_techniques(tests, tan, qra, xdr)
    summary['techniques_overall'] = techniques_summary['overall']
    summary['techniques_tanium'] = techniques_summary['tanium']
    summary['techniques_cortex'] = techniques_summary['cortex']
    summary['techniques_qradar'] = techniques_summary['qradar']

    data = {
        'run_id': run_id,
        'settings': settings,
        'start': start,
        'summary': summary,
        'tests': tests,
        'techniques': techniques
    }
    report_file = path + '/' + run_id + '.json'

    try:
        with open(report_file, "w") as f:
            json.dump(data, f)
    except Exception as err:
        print("During storing of results, an issue occured: %s", str(err))

    return data

def create_detection(report_caldera, dom, path_file, tan, xdr, qra):
    global report
    global domain
    global path
    report = report_caldera
    domain = dom
    path = path_file + 'detectionreports'
    finished_reports = []
    for host in report['host_group']:
        finished_reports.append(create_report(host, tan, qra, xdr))
    finished_reports = [i for i in finished_reports if (i and not i == {})]
    return {'reports':finished_reports}