import logging
import requests
import json
from datetime import datetime, timedelta
import time
import urllib3
import os

from configparser import ConfigParser

#import of own modules
from plugins.reporter.app.connlib import checkanswer, longunix_to_time

##########################################
#### ---------- PARAMETERS ---------- ####
##########################################
# accounts for time difference (tanium API uses UTC). 0 if machine time is set to UTC
offset = 0

class BIOC:
    
    def __init__(self, data):
        self.ID = data['RULE_ID']
        self.severity = data['RULE_SEVERITY'][8:]
        self.category = data['BIOC_CATEGORY']
        self.name = data['RULE_NAME']
    
        self.detected =[]
        self.n_detected = 0

    def __str__(self):
        return ("ID: " + str(self.ID) + "\nName: " + self.name
            + "\nSeverity: " + str(self.severity) +"\nCategory: " + self.category)

    def append_detection(self, detected):
        """ appends information about detection, increases detection count
        :param detected: (int, int, str); mitreID of test, number of test, source of test
        :return None
        """
        self.detected.append(detected)
        self.n_detected += 1

class Incident:

    def __init__(self, data):
        self.data = data

        #elem in detected: (test.mitreID, test.nr, test.type)
        self.detected = []
        self.n_detected = 0
    
    def __str__(self):
        return 'not implemented'

    def append_detection(self, detected):
        """ appends information about detection, increases detection count
        :param detected: (int, int, str); mitreID of test, number of test, source of test
        :return None
        """
        self.detected.append(detected)
        self.n_detected += 1


class CortexCon:

    def __init__(self):
        
        config = ConfigParser()
        configpath = os.path.dirname(os.path.abspath(__file__)).split('reporter', 1)[0] + 'reporter/config.ini'
        config.read(configpath)

        key_ID = config.get('cortex', 'key_ID')
        api_key = config.get('cortex', 'api_key')

        self.headers = {
            "x-xdr-auth-id": str(key_ID),
            "Authorization": api_key
        }
        
        self.server = config.get('cortex', 'server')
        self.verifySSL = config.get('cortex', 'verifySSL')

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def __str__(self):
        return 'not implemented'

    def getincidents(self, starttime):
        """
        """
        starter = starttime - timedelta(days=1)
        unix_time = time.mktime(starter.timetuple())
        payload = {
            "request_data":{
                "filters": [
                    {
                    "field": "modification_time",
                    "operator": "gte",
                    "value": int(unix_time) * 1000
                    }
                ],
                "search_from": 0,
                "search_to": 100,
                "sort": {
                    "field": "modification_time",
                    "keyword": "desc"
                }
            }
        }
        request = json.dumps(payload)
        try:
            iter = 0
            response = checkanswer(
                requests.request('POST', self.server + '/public_api/v1/incidents/get_incidents/', headers=self.headers, data=request, verify=self.verifySSL),
                200, True)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.request('POST', self.server + '/public_api/v1/incidents/get_incidents/', headers=self.headers, data=request, verify=self.verifySSL),
                    200, True) 
                iter += 1
            if response['API_status']:
                return response['response']
            else:
                print("API call to get incidents did not return expected value")
                return None
        except Exception as err:
            print("API call to get incidents did result in error: " + str(err))
            return None

    def getincidentextra(self, incident_id):
        """
        """
        payload = { 
        	"request_data": {
                "incident_id": str(incident_id)
            }
        }
        request = json.dumps(payload)
        try:
            iter = 0
            response = checkanswer(
                requests.request('POST', self.server + '/public_api/v1/incidents/get_incident_extra_data/', headers=self.headers, data=request, verify=self.verifySSL),
                200, True)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.request('POST', self.server + '/public_api/v1/incidents/get_incident_extra_data/', headers=self.headers, data=request, verify=self.verifySSL),
                    200, True) 
                iter += 1
            if response['API_status']:
                return response['response']
            else:
                print("API call to get incident details did not return expected value")
                return None
        except Exception as err:
            print("API call to get incident details did result in error: " + str(err))
            return None

    def getalerts(self, starttime):
        """
        """
        starter = starttime - timedelta(seconds=20)
        unix_time = time.mktime(starter.timetuple())
        payload = { 
	        "request_data": {
            "filters": [
				{
                "field": "creation_time",
                "operator": "gte",
                "value": int(unix_time) * 1000
                }
                ]
            }
        }
        request = json.dumps(payload)
        try:
            iter = 0
            response = checkanswer(
                requests.request('POST', self.server + '/public_api/v1/alerts/get_alerts/', headers=self.headers, data=request, verify=self.verifySSL),
                200, True)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.request('POST', self.server + '/public_api/v1/alerts/get_alerts/', headers=self.headers, data=request, verify=self.verifySSL),
                    200, True) 
                iter += 1
            if response['API_status']:
                return response['response']
            else:
                print("API call to get alerts did not return expected value")
                return None
        except Exception as err:
            print("API call to get alerts did result in error: " + str(err))
            return None
    
    def getalerts_time(self, starttime, endtime):
        """
        """
        unix_start = time.mktime(starttime.timetuple())
        unix_end = time.mktime(endtime.timetuple())

        payload = {
            "request_data": {
            "filters": [
				{
                "field": "creation_time",
                "operator": "gte",
                "value": int(unix_start) * 1000
                },
                {
                "field": "creation_time",
                "operator": "lte",
                "value": int(unix_end) * 1000
                }
                ]
            }
        }
        request = json.dumps(payload)
        try:
            iter = 0
            response = checkanswer(
                requests.request('POST', self.server + '/public_api/v1/alerts/get_alerts/', headers=self.headers, data=request, verify=self.verifySSL),
                200, True)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.request('POST', self.server + '/public_api/v1/alerts/get_alerts/', headers=self.headers, data=request, verify=self.verifySSL),
                    200, True) 
                iter += 1
            if response['API_status']:
                return response['response']
            else:
                print("API call to get alerts did not return expected value")
                return None
        except Exception as err:
            print("API call to get alerts did result in error: " + str(err))
            return None

class CortexResponse:

    def __init__(self, start):
        self.start = start
        """ alert in incidents: [[str]]; 
        [
            0 = alert id
            1 = detected at
            2 = source
            3 = severity
            4 = name
            5 = category
            6 = action
            7 = description
            8 = process
            9 = command line
        ]
        """
        self.incidents = []

    def incidentcheck(self, con, host_ip):
        response = con.getincidents(self.start)
        if response:
            try:
                incidents = response['reply']['incidents']
                for incident in incidents:
                    data = con.getincidentextra(incident['incident_id'])['reply']
                    if data is None:
                        continue
                    for alert in data['alerts']['data']:
                        alerted = longunix_to_time(alert['detection_timestamp'])
                        if (alerted >= self.start - timedelta(minutes=1)) and (alert['host_ip'] == host_ip):
                            new_alert = []
                            new_alert.append(alert['alert_id'])
                            new_alert.append(str(alerted))
                            new_alert.append(alert['source'])
                            new_alert.append(alert['severity'])
                            new_alert.append(alert['name'])
                            new_alert.append(alert['category'])
                            new_alert.append(alert['action_pretty'])
                            new_alert.append(alert['description'])
                            new_alert.append(alert['actor_process_image_name'])
                            new_alert.append(alert['actor_process_command_line'])
                            self.incidents.append(new_alert)
            except Exception as err:
                print("Format of returned incidents did no match expected format: " + str(err))

        response = con.getalerts(self.start)
        if response:
            try:
                for alert in response['reply']['alerts']:
                    alerted = longunix_to_time(alert['detection_timestamp'])
                    if (alert['host_ip'] == host_ip and not alert['severity'] == "SEV_010_INFO"):
                        new_alert = []
                        new_alert.append(alert['alert_id'])
                        new_alert.append(str(alerted))
                        new_alert.append(alert['source'])
                        new_alert.append(alert['severity'])
                        new_alert.append(alert['name'])
                        new_alert.append(alert['category'])
                        new_alert.append(alert['action_pretty'])
                        new_alert.append(alert['description'])
                        new_alert.append(alert['actor_process_image_name'])
                        new_alert.append(alert['actor_process_command_line'])
                        self.incidents.append(new_alert)
            except Exception as err:
                print("Format of returned incidents did no match expected format: " + str(err))

    def calderacheck(self, con, start, end, host):
        alerts = con.getalerts_time(start, end)
        if alerts:
            try:
                for alert in alerts['reply']['alerts']:
                    if alert['host_name'] == host and not alert['severity'] == "SEV_010_INFO" and not alert['name'] == 'Windows scripting engine runs with system privileges':
                        new_alert = []
                        new_alert.append(alert['alert_id'])
                        new_alert.append(str(longunix_to_time(alert['detection_timestamp'])))
                        new_alert.append(alert['source'])
                        new_alert.append(alert['severity'])
                        new_alert.append(alert['name'])
                        new_alert.append(alert['category'])
                        new_alert.append(alert['action_pretty'])
                        new_alert.append(alert['description'])
                        new_alert.append(alert['actor_process_image_name'])
                        new_alert.append(alert['actor_process_command_line'])
                        self.incidents.append(new_alert)
            except Exception as err:
                print("Format of returned alerts did not match the excpected format: " + str(err))
                


def cortexresp(start, con, host_ip):
    """
    """
    resp = CortexResponse(start)
    resp.incidentcheck(con, host_ip)
    return resp

def cortexcaldera(con, start, end, host):
    """
    """
    resp = CortexResponse(start)
    resp.calderacheck(con, start, end, host)
    return resp
