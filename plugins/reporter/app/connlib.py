import logging
import requests
import json
from datetime import datetime, timedelta
import time
import urllib3

##########################################
#### ---------- PARAMETERS ---------- ####
##########################################
# default logger for all files
logger = logging.getLogger(__name__)

def timestamp_to_time(alerted):
    """ Converts timestamp as string to datetime object
    :param alerted: str; timestamp as string
    :return datetime; timestamp as datetime object
    """
    return datetime(int(alerted[:4]), int(alerted[5:7]), int(alerted[8:10]), int(alerted[11:13]), int(alerted[14:16]), int(alerted[17:19]))

def strunix_to_time(timestamp_ms):
    """ Takes a str representing a timestamp in ms and converts it 
    to an element of type datetype
    :params timestamp_ms: str; timestamp in unixtime in ms
    :return datetime; 
    """
    return datetime.fromtimestamp(float(timestamp_ms[:10]))

def longunix_to_time(timestamp_ms):
    """ Takes a long representing a timestamp in ms and converts it 
    to an element of type datetype
    :params timestamp_ms: long; timestamp in unixtime in ms
    :return datetime; 
    """
    return datetime.fromtimestamp(timestamp_ms/1000)

def checkanswer(response, correct_code, json):
    """Takes API response and checks if the response is correct.
    Appends value 'API_status' to answer indicating if response correct or not
    :param response: requests; response returned by API calls
    :param correct_code: int, result code for no errors
    :return dict; coverted json of answer (if correct) and 'API_status'
    """
    if response.status_code != correct_code:
        return {'API_status': False, 'error_code': response.status_code}
    elif json:
        return {'response': response.json(), 'API_status': True}
    else:
        return {'API_status': True}