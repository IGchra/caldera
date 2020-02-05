import logging
import requests
import json
from datetime import datetime, timedelta
import time
import urllib3
import os

from configparser import ConfigParser

#import of own modules
from plugins.reporter.app.connlib import checkanswer, timestamp_to_time

##########################################
#### ---------- PARAMETERS ---------- ####
##########################################
# accounts for time difference between system and tanium server(uses UTC). 0 if machine time is set to UTC
offset = 0

class Signal:

    def __init__(self, data):
        self.ID = data['id']
        self.labels = data['labelIds']
        self.description = data['data']['description']
        self.name = data['data']['name']
        self.mitre = []
        try:
            if 'mitreAttack' in data['data']:
                if 'techniques' in data['data']['mitreAttack']:
                    for technique in data['data']['mitreAttack']['techniques']:
                        self.mitre.append(int(technique['id'][1:]))
        except Exception as err:
            logger.error("Unable to initialize associated techniques for Signal " + self.name)
        #elem in detected: (test.mitreID, test.nr, test.type)
        self.detected = []
        self.n_detected = 0
    
    def __str__(self):
        labels = ""
        IDs = ""
        det = ""
        for label in self.labels:
            labels += str(label) + ", " 
        for ID in self.mitre:
            IDs += str(ID) + ", "
        for detect in self.detected:
            det += str(detect[0]) + ", " + str(detect[1]) +", " + str(detect[2]) + "; "
        return ("ID: " + str(self.ID) + "\nLabels: " + labels + "\nDescription: " + self.description
            + "\nName: " + str(self.name) + "\nMitre: " + IDs + "\nDetected attacks:" 
            + det + "\n# Attacks detected: " + str(self.n_detected))

    def append_detection(self, detected):
        """ appends information about detection, increases detection count
        :param detected: (int, int, str); mitreID of test, number of test, source of test
        :return None
        """
        self.detected.append(detected)
        self.n_detected += 1

class TaniumCon:

    def __init__(self):
        
        config = ConfigParser()
        configpath = os.path.dirname(os.path.abspath(__file__)).split('reporter', 1)[0] + 'reporter/config.ini'
        config.read(configpath)
        
        
        self.username = config.get('tanium', 'username')
        self.password = config.get('tanium', 'password')
        self.server = config.get('tanium', 'server')
        self.verifySSL = config.getboolean('tanium', 'verifySSL')

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        auth = self.authenticate()
        if auth is not '':
            print(auth)

    def __str__(self):
        return ("Username: " + self.username + "\nServer: " + self.server 
                + "\nConnection last validated: " + str(self.session_validated)
                + "\nSession string: " + self.session_key['session'])

    def validate_session(self):
        """ Checks if session_key still valid, otherwise renews it (String expires after 5 minutes)
        return: None
        """
        if (self.session_validated + timedelta(minutes=5)) < datetime.now():
            self.authenticate()


    def authenticate(self):
        """ Logs on Tanium Server
        :format of API call reponse: {u'data': {u'session': u'some_string'}}
        :return None or error message
        """
        json_string = json.dumps({'username': self.username, 'password': self.password})
        try:
            iter = 0
            response = checkanswer(
                requests.request("POST", 'https://tanium.sec-lab.local/api/v2/session/login', data=json_string, verify=self.verifySSL),
                200, True)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.request("POST", 'https://tanium.sec-lab.local/api/v2/session/login', data=json_string, verify=self.verifySSL),
                    200, True) 
                iter += 1
            if response['API_status']:
                self.session_key = {'session': response['response']['data']['session']}
                self.session_validated = datetime.now()
                return ''
            else:
                print("API call to authenticate tanium did not return expected value")
                return 'API_call did not return expected value'
        except Exception as err:
            print("API call to authenticate tanium did result in error: " + str(err))
            return 'API call to authenticate tanium did result in error: ' + str(err)

    def getsignals(self):
        """ Get all signals.
        :return dict; all signals or None if failed
        """
        self.validate_session()
        try:
            iter = 0
            response = checkanswer(
                requests.request("POST", self.server + '/plugin/products/detect3/api/v1/intels/export/signals', headers=self.session_key, data="", verify=self.verifySSL),
                    200, True)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.request("POST", self.server + '/plugin/products/detect3/api/v1/intels/export/signals', headers=self.session_key, data="", verify=self.verifySSL),
                    200, True)
                iter += 1
            if response['API_status']:
                return response['response']
            else:
                print("API call to get signals did not return expected value")
                return None
        except Exception as err:
            print("API call to get signals did result in error: " + str(err))
            return None

    def getalerts(self, computer_name='', offset=0):
        """ Get up to 500 alerts starting from offset for given host
        :param computer_name(optional): str; host which caused alerts. If none given, all are returned
        :param offset(optional): int; offset of alerts
        :return dict; alerts or None if failed
        """
        self.validate_session()
        if offset==0 and computer_name == '':
            querystring = {"limit":"500"}
        else:
            querystring = {"limit":"500", "offset":offset, "computerName":computer_name}
        try:
            iter = 0
            response = checkanswer(
                requests.get(self.server + '/plugin/products/detect3/api/v1/alerts', headers=self.session_key, params=querystring, verify=self.verifySSL),
                200, True)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.get(self.server + '/plugin/products/detect3/api/v1/alerts', headers=self.session_key, params=querystring, verify=self.verifySSL),
                    200, True)
                iter += 1
            if response['API_status']:
                return response['response']
            else:
                logger.error("API call to get alerts did not return expected value")
                return None
        except Exception as err:
            logger.error("API call to get alerts did result in error: " + str(err))
            return None

    def deletealert(self, ID):
        """ Deletes alert by id
        :param ID: int; id of alert to delete
        :return Bool; indicates if operation succeded;
        """
        self.validate_session()
        try:
            iter = 0
            response = checkanswer(
                requests.delete(self.server + '/plugin/products/detect3/api/v1/alerts/' + str(ID), headers=self.session_key, verify=self.verifySSL),
                204, False)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.delete(self.server + '/plugin/products/detect3/api/v1/alerts/' + str(ID), headers=self.session_key, verify=self.verifySSL),
                    204, False)
                iter += 1
            if response['API_status']:
                return True
            else:
                logger.error("API call to delete alert did not return expected value")
                return False
        except Exception as err:
            logger.error("API call to delete alert did result in error: " + str(err))
            return False

    def gettraces(self, starttime, endtime):
        """ Get executed process trees within specified time interval from all machines with parent containing 'python'
        :param starttime: datetime; start of interval of interest (in UTC tanium time)
        :param endtime: datetime; end of interval of interest (in UTC tanium time)
        :return dict; trace information or None if failed
        """
        self.validate_session()
        starter = starttime - timedelta(minutes=1)
        unixstart = time.mktime(starter.timetuple())
        unixend = time.mktime(endtime.timetuple())
        question = {"query_text" : "Get Trace Executed Process Trees[python,0,0,0,As Parent,10000,"+str(unixstart)[:-2] + "000|" + str(unixend)[:-2] + "000] from all machines"}
        try:
            iter = 0
            response = checkanswer(
                requests.post(self.server + '/api/v2/questions', headers=self.session_key, json=question, verify=self.verifySSL),
                200, True)
            while not response['API_status'] and iter < 10:
                checkanswer(
                    requests.post(self.server + '/api/v2/questions', headers=self.session_key, json=question, verify=self.verifySSL),
                    200, True)
                iter += 1
            if not response['API_status']:
                logger.error("API call to ask trace question did not return expected value")
                return None
        except Exception as err:
            logger.error("API call to ask trace question did result in error: " + str(err))
            return None
        question_id = response['response']['data']['id']
        try:
            iter = 0
            response = checkanswer(
                requests.get(self.server + '/api/v2/result_data/question/' + str(question_id), headers=self.session_key, verify=self.verifySSL),
                200, True)
            while (not response['API_status'] or response['response']['data']['result_sets'][0]['estimated_total'] != response['response']['data']['result_sets'][0]['mr_passed']) and iter < 25:
                time.sleep(2)
                self.validate_session()
                response = checkanswer(
                    requests.get(self.server + '/api/v2/result_data/question/' + str(question_id), headers=self.session_key, verify=self.verifySSL),
                    200, True)
                iter += 1
            if response['API_status']:
                return response['response']
            else:
                logger.error("API call to get trace answer did not return expected value")
                return None
        except Exception as err:
            logger.error("API call to get trace answer did result in error: " + str(err))
            return  None

    def snapshot(self, computername="WS-Win10-001.sec-lab.local"):
        """ Makes a snapshot of the specified system
        :param computername: string, name of computer system of interest
        :return string, name of snapshot or error message
        """
        self.validate_session()
        parameter = {
            "remote": True,
            "dst": computername,
            "dstType": "computer_name",
            "connTimeout": 0
        }
        try:
            iter = 0
            response = checkanswer(
                requests.post(self.server + '/plugin/products/trace/conns', headers=self.session_key, json=parameter, verify=self.verifySSL),
                202, False)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.post(self.server + '/plugin/products/trace/conns', headers=self.session_key, json=parameter, verify=self.verifySSL),
                    202, False)
                iter += 1
            if not response['API_status']:
                logger.error("API call to start connection did not return expected value")
                return 'API_call did not return expected value'
        except Exception as err:
            logger.error("API call to start connection did result in error: " + str(err))
            return 'API_call did result in error: ' + str(err)
        try:
            iter = 0
            response = checkanswer(
                requests.post(self.server + '/plugin/products/trace/conns/' + computername + '/snapshots', headers=self.session_key, verify=self.verifySSL),
                202, False)
            while not response['API_status'] and iter < 25:
                time.sleep(2)
                response = checkanswer(
                    requests.post(self.server + '/plugin/products/trace/conns/' + computername + '/snapshots', headers=self.session_key, verify=self.verifySSL),
                    202, False)
                iter += 1
            if not response['API_status']:
                logger.error("API call to take snapshot did not return expected value")
                return 'API_call did not return expected value'
        except Exception as err:
            logger.error("API call to take snapshot did result in error: " + str(err))
            return 'API_call did result in error: ' + str(err)
        try:
            iter = 0
            response = checkanswer(
                requests.get(self.server + '/plugin/products/trace/snapshots', headers=self.session_key, verify=self.verifySSL),
                200, True)
            while not response['API_status'] and iter < 10:
                time.sleep(2)
                response = checkanswer(
                    requests.get(self.server + '/plugin/products/trace/snapshots', headers=self.session_key, verify=self.verifySSL),
                    200, True)
                iter += 1
            if response['API_status']:
                return computername + '-' + response['response'][computername].keys()[0]
            else:
                logger.error("API call to get snapshotname did not return expected value")
                return 'API_call did not return expected value'
        except Exception as err:
            logger.error("API call to get snapshotname did result in error: " + str(err))
            return 'API_call did result in error: ' + str(err)

class TaniumResponse:

    def __init__(self, start, end=datetime.now()):
        self.start = start
        self.end = end
        # trace in traces: str; trace
        self.traces = []
        """ alert in alerts: [[str]]; 
        [
            [alerted at, alert id, signal id, signal name, signal description],
            [signallabelname1, signallabelname2, ...],
            [attack1_id, attack1_name, attack2_id, attack2_name, ...],
            [parentinfo_1, parentinfo_2, ...],
            [parenttrace]
        ]

        """
        self.alerts = []

    def tracecheck(self, con):
        """ Checks for traces within timeframe, writes traces to self.traces
        :param con: TaniumCon; object handling Tanium API calls
        :return None
        """
        response = con.gettraces(self.start, self.end)
        if response:
            try: 
                traces = response['data']['result_sets'][0]['rows']
                for trace in traces:
                    self.traces.append(trace['data'][0][0]['text'] + "\n")
            except Exception as err:
                logger.error("Format of returned trace did no match expected format: " + str(err))

    def alertcheck(self, con, host_ip):
        """ Retrieves up to 500 alerts. Checks if they have been caused by given host and after self.start.
            Enriches information about alerts/signal and writes matching alerts to self.alerts. 
            See above for structure of an alert.
        :param con: TaniumCon; object handling Tanium API calls
        :param host_ip: str; host on which alerts have been triggered
        :return None
        """
        alerts = con.getalerts()
        intel = con.getsignals()
        if alerts and intel:
            try:
                i = 0
                while i < len(alerts):
                    intelid = alerts[i]['intelDocId']
                    alerted = alerts[i]['alertedAt']
                    alerttime = timestamp_to_time(alerted) + timedelta(hours=offset)
                    if (self.start - timedelta(minutes=1) <= alerttime) and alerts[i]['computerIpAddress'] == host_ip:
                        try:    
                            new_alert = []
                            for elem in intel['signals']:
                                if elem['id'] == intelid:
                                    new_alert.append([str(alerttime), str(alerts[i]['id']),
                                        str(elem['id']), str(elem['data']['name']), 
                                        str(elem['data']['description'])])

                                    signal_labels = []
                                    for tag in elem['labelIds']:
                                        for label in intel['labels']:
                                            if label['id'] == tag:
                                                signal_labels.append(str(label['name']))
                                    new_alert.append(signal_labels)
                                    attackids = []
                                    if 'mitreAttack' in elem['data']:
                                        for attackID in elem['data']['mitreAttack']['techniques']:
                                            attackids.append(str(attackID['id']))
                                            attackids.append(str(attackID['name']))
                                    new_alert.append(attackids)

                                    readable_details = json.loads(alerts[i]['details'])
                                    elem = readable_details['match']['properties']
                                    traces = ''
                                    parentinfo = []
                                    while elem['ppid'] and elem['ppid'] != 0 and elem['parent']:
                                        traces = ' -> ' + elem['name'] + traces
                                        detailinfo = "Name: " + elem['name'] + "\nArguments: " + str(elem['args'])
                                        detailinfo += "\nFile: " + elem['file']['fullpath'] + "\nUser: " + elem['user']
                                        detailinfo += "\nPID: " + str(elem['pid']) + "\nPPID: " + str(elem['ppid'])
                                        detailinfo += "\nStart time: " + elem['start_time']
                                        parentinfo.append(detailinfo)
                                        elem = elem['parent']
                                    traces = elem['name'] + traces
                                    detailinfo = "Name: " + elem['name'] + "\nArguments: " + str(elem['args'])
                                    detailinfo += "\nFile: " + elem['file']['fullpath'] + "\nUser: " + elem['user']
                                    detailinfo += "\nPID: " + str(elem['pid']) + "\nPPID: -"
                                    detailinfo += "\nStart time: " + elem['start_time']
                                    parentinfo.append(detailinfo)
                                    new_alert.append(parentinfo)
                                    new_alert.append([traces])
                                    break
                            if not new_alert[0][3] == "#0164-XXXX IG Powershell Compiler Call":
                                self.alerts.append(new_alert)
                        except Exception as err:
                            logger.error("Was not able to parse alert correctly: %s", str(err))
                    i += 1
            except Exception as err:
                logger.error("Format of returned alerts did no match expected format: " + str(err))
    
    def allalerts(self, con, computer_name, offset):
        """ Retrieves up to 500 alerts starting at given offset that were caused by given host. 
            Enriches information about alerts/signal and writes it to self.alerts.
            See above for structure of an alert.
        :param con: TaniumCon; object handling Tanium API calls
        :param computer_name: str; host name for which triggered alerts should be returned
        :param offset: int; offset for tanium alerts 
        :return None
        """
        alerts = con.getalerts(computer_name, offset)
        intel = con.getsignals()
        if alerts and intel:
            try:
                i = 0
                while i < len(alerts):
                    intelid = alerts[i]['intelDocId']
                    alerted = alerts[i]['alertedAt']
                    alerttime = timestamp_to_time(alerted)
                    try:    
                        new_alert = []
                        for elem in intel['signals']:
                            if elem['id'] == intelid:
                                new_alert.append([str(alerttime), str(alerts[i]['id']),
                                    str(elem['id']), str(elem['data']['name']), 
                                    str(elem['data']['description'])])
                                signal_labels = []
                                for tag in elem['labelIds']:
                                    for label in intel['labels']:
                                        if label['id'] == tag:
                                            signal_labels.append(str(label['name']))
                                new_alert.append(signal_labels)
                                attackids = []
                                if 'mitreAttack' in elem['data']:
                                    for attackID in elem['data']['mitreAttack']['techniques']:
                                        attackids.append(str(attackID['id']))
                                        attackids.append(str(attackID['name']))
                                new_alert.append(attackids)
                                readable_details = json.loads(alerts[i]['details'])
                                elem = readable_details['match']['properties']
                                traces = ''
                                parentinfo = []
                                while elem['ppid'] and elem['ppid'] != 0 and elem['parent']:
                                    traces = ' -> ' + elem['name'] + traces
                                    detailinfo = "Name: " + elem['name'] + "\nArguments: " + str(elem['args'])
                                    detailinfo += "\nFile: " + elem['file']['fullpath'] + "\nUser: " + elem['user']
                                    detailinfo += "\nPID: " + str(elem['pid']) + "\nPPID: " + str(elem['ppid'])
                                    detailinfo += "\nStart time: " + elem['start_time']
                                    parentinfo.append(detailinfo)
                                    elem = elem['parent']
                                traces = elem['name'] + traces
                                detailinfo = "Name: " + elem['name'] + "\nArguments: " + str(elem['args'])
                                detailinfo += "\nFile: " + elem['file']['fullpath'] + "\nUser: " + elem['user']
                                detailinfo += "\nPID: " + str(elem['pid']) + "\nPPID: -"
                                detailinfo += "\nStart time: " + elem['start_time']
                                parentinfo.append(detailinfo)
                                new_alert.append(parentinfo)
                                new_alert.append([traces])
                                break

                        self.alerts.append(new_alert)

                    except Exception as err:
                        print("Was not able to parse alert correctly: %s", str(err))

                    i += 1

            except Exception as err:
                print("Format of returned alerts did no match expected format: " + str(err))

def taniumresp(start, con, host_ip):
    """checks for traces and alerts and processes information
    :param start: datetime; start of time interval of interest, e.g. time when test started
    :param con: TaniumCon; object handling Tanium API calls
    :param host_ip: str; IP address of host on which test is run
    :return TaniumResponse; object holding processed information about tanium for this test 
    """
    resp = TaniumResponse(start)
    resp.tracecheck(con)
    resp.alertcheck(con, host_ip)
    return resp

def taniumcaldera(con, computer_name, offset):
    """ loads all alerts for specified host and enriches them with further information about the signal
    :param con: TaniumCon; object handling Tanium API calls
    :param computer_name: str; host name for which triggered alerts should be returned
    :param offset: int; offset for tanium alerts
    :return TaniumResponse: object holding processed information about alerts in self.alerts. 
        All other attributes have dummy values in this case.
    """
    resp = TaniumResponse(datetime.now())
    resp.allalerts(con, computer_name, offset)
    return resp

def taniumsnap():
    """ Creates tanium snapshot of system
    :return str; name of snapshot
    """
    con = TaniumCon()
    return con.snapshot()

def deletetaniumalerts():
    """ Deletes all alerts 
    :return None;
    """
    con = TaniumCon()
    alerts = con.getalerts()
    while alerts is not None and len(alerts) > 0:
        for alert in alerts:
            #Reason for deleting every alert individually: No API-call to delete all exists.
            logger.debug("Deleting alert with id %s", alert['id'])
            con.deletealert(alert['id'])
        alerts = con.getalerts()
    logger.debug("Finished deleting alerts")