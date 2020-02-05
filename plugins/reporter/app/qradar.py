import base64
import logging
import requests
import json
from datetime import datetime, timedelta
import time
import requests
import urllib3
import os

from configparser import ConfigParser

#import of own modules
from plugins.reporter.app.connlib import checkanswer, strunix_to_time

##########################################
#### ---------- PARAMETERS ---------- ####
##########################################
# accounts for time difference (qradar in lab set to UTC). 0 if machine time is set to UTC
offset = 0

class Rule:

    def __init__(self, data):
        self.ID = data['id']
        self.identifier = data['identifier']
        self.name = data['name']
        self.type = data['type']
        self.owner = data['owner']
        #elem in detected: (test.mitreID, test.nr, test.type)
        self.detected =[]
        self.n_detected = 0

    def __str__(self):
        return ("ID: " + str(self.ID) + "\nName: " + self.name
            + "\nIdentifier:" + str(self.identifier))

    def append_detection(self, detected):
        """ appends information about detection, increases detection count
        :param detected: (int, int, str); mitreID of test, number of test, source of test
        :return None
        """
        self.detected.append(detected)
        self.n_detected += 1

class Offense:
    
    def __init__(self, data):
        self.ID = data['id']

class QradarCon:

    def __init__(self):
        
        config = ConfigParser()
        configpath = os.path.dirname(os.path.abspath(__file__)).split('reporter', 1)[0] + 'reporter/config.ini'
        config.read(configpath)

        username = config.get('qradar', 'username')
        password = config.get('qradar', 'password')

        userpass = username+":"+password 
        encoded_credentials = b"Basic " + base64.b64encode(userpass.encode('ascii'))
        self.headers = {'Authorization': encoded_credentials}
        self.verifySSL = config.get('qradar', 'verifySSL')
        self.server = config.get('qradar', 'server')

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def getrules(self):
        """ Gets information about all rules
        :return dict; information about all rules or None if failed
        """
        try:
            iter = 0
            response = checkanswer(
                requests.request('GET', self.server+"/api/analytics/rules", headers=self.headers, verify=self.verifySSL),
                200, True)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.request('GET', self.server+"/api/analytics/rules", headers=self.headers, verify=self.verifySSL),
                    200, True) 
                iter += 1
            if response['API_status']:
                return response['response']
            else:
                print("API call to get rules did not return expected value")
                return None
        except Exception as err:
            print("API call to get rules did result in error: " + str(err))
            return None
    
    def getrule(self, rule_id):
        """ Get information about specified rule
        :param rule_id str; ID of the rule requested
        :return dict; information about rule or None if failed
        """
        try:
            iter = 0
            response = checkanswer(
                requests.request('GET', self.server+"/api/analytics/rules/" + str(rule_id), headers=self.headers, verify=self.verifySSL),
                200, True)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.request('GET', self.server+"/api/analytics/rules/" + str(rule_id), headers=self.headers, verify=self.verifySSL),
                    200, True) 
                iter += 1
            if response['API_status']:
                return response['response']
            else:
                print("API call to get rules did not return expected value")
                return None
        except Exception as err:
            print("API call to get rules did result in error: " + str(err))
            return None

    def getoffenses(self):
        """Gets all offenses.
        :return dict; all offenses or None if failed
        """
        try:
            iter = 0
            response = checkanswer(
                requests.request('GET', self.server+"/api/siem/offenses", headers=self.headers, verify=self.verifySSL),
                200, True)
            while not response['API_status'] and iter < 10:
                response = checkanswer(
                    requests.request('GET', self.server+"/api/siem/offenses", headers=self.headers, verify=self.verifySSL),
                    200, True) 
                iter += 1
            if response['API_status']:
                return response['response']
            else:
                print("API call to get rules did not return expected value")
                return None
        except Exception as err:
            print("API call to get rules did result in error: " + str(err))
            return None


class QradarResponse:

    def __init__(self, start):
        self.start = start
        self.response = ""
        """ offense in offenses: [[str]];
        [
            [alerted at, offense id, offense description, offense source]
            [rule1_name, rule1_id, rule2_name, rule2_id,]
            [category_1, category_2, ...]

        ]
        """
        self.offenses = []

    def offensecheck(self, con, host_ip):
        """Checks for offenses, processes information and writes to self.offenses
        :param con: QRadarCon; object handling QRadar API calls
        :return None
        """
        offenses = con.getoffenses()
        if offenses:
            try:
                for offense in offenses:
                    alerted = str(offense['last_updated_time'])
                    alerttime = strunix_to_time(alerted) + timedelta(hours=offset)
                    if(self.start <= alerttime) and offense['offense_source'] == host_ip:
                        new_offense = []
                        new_offense.append([
                            str(alerttime),
                            str(offense['id']),
                            str(offense['description']),
                            str(offense['offense_source'])
                        ])
                        ruleids = []
                        for rule in offense['rules']:
                            ruleinfo = con.getrule(rule['id'])
                            ruleids.append(ruleinfo['name'])
                            ruleids.append(ruleinfo['id'])
                        new_offense.append(ruleids)
                        categories = []
                        for category in offense['categories']:
                            categories.append(str(category))
                        new_offense.append(categories)
                        self.offenses.append(new_offense)
            except Exception as err:
                print("Format of returned alerts did no match expected format: " + str(err))

    def calderacheck(self, con, start, end, host_ip):
        #!not implemented!
        #should return all offenses(alerts) on given host within given timeframe
        # issue: no qradar-call to check when exactly an alert was triggered. only possible to check
        # when offense started and when it was last modified. possible solutions include an API call 
        # with an AQL query, however this was omitted due to low relevance and lack of time.
        self.offenses = []

    

def qradarresp(start, con, host_ip):
    """checks for offenses and processes information
    :param start: datetime; start of time interval of interest, e.g. time when test started
    :param con: QRadarCon; object handling QRadar API calls
    :param host_ip: IP address of host on which program is executed
    :return QradarResponse; object holding processed information about qradar for this test 
    """
    resp = QradarResponse(start)
    resp.offensecheck(con, host_ip)
    return resp

def qradarcaldera(con, start, end, host_ip):
    #!not fully implemented!
    """checks for offenses in given timeframe caused by given host and processes information
    :param con: QRadarCon; object handling QRadar API calls
    :param start: datetime; start of time interval of interest
    :param end: datetime; end of time interval of interest
    :param host_ip: IP address of host which caused offenses
    :return QradarResponse; object holding processed information about qradar for this test 
    """
    resp = QradarResponse(start)
    resp.calderacheck(con, start, end, host_ip)
    return resp