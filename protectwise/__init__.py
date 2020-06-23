import datetime
import getpass
import json
import os
import time
from configparser import ConfigParser

import requests

try:
    input = raw_input
except:
    pass

homedirectory = os.path.expanduser("~")


def get_times(daydiff):
    # Takes an integer and returns a list of start
    # and end times converted into the proper format
    #//Todo make this more granular to support hours, times, ranges, etc. 
    daystotime = daydiff * 86400
    et = int(datetime.datetime.utcnow().timestamp())
    st = et - daystotime
    endtime = et * 1000
    starttime = st * 1000
    return (str(starttime), str(endtime))


def initialize_token():
    email = input("Email: ")
    password = getpass.getpass("Password: ")
    try:
        response = requests.post(
            url="https://api.protectwise.com/api/v1/token",
            headers={
                "Content-Type": "application/json",
            },
            data=json.dumps({
                "email": email,
                "password": password
            }))
        token = json.loads(response.content)['token']
        config = ConfigParser()
        config.add_section('Token')
        config.set('Token', 'token', token)
        with open(os.path.join(homedirectory, '.config', 'protectwise.ini'),
                  "w") as configfile:
            config.write(configfile)
    except requests.exceptions.RequestException:
        print('HTTP Request failed')


def generate_token():
    # Get Token from protectwise
    # POST https://api.protectwise.com/api/v1/token
    if os.path.isdir(os.path.join(homedirectory, '.config')):
        if os.path.isfile(os.path.join(homedirectory,  '.config', 'protectwise.ini')):
            dothis = input(
                "Protectwise config file already exists, refresh token? [Y/N]: "
            )
            if str(dothis).upper().startswith('Y'):
                initialize_token()
            else:
                print("[*] You selected to not refresh token, aborting")
        else:
            print("[*] creating protectwise configuration file as it does not exist")
            initialize_token()
    else:
        creatdir = input("Directory " + os.path.join(homedirectory, '.config') + " does not exist create"
                                                                                 " it now? [Y/N]:")
        if str(creatdir).upper().startswith("Y"):
            os.mkdir(os.path.join(homedirectory, '.config'))
            print("[+] created directory " + os.path.join(homedirectory, '.config'))
            initialize_token()


def get_token():
    config = ConfigParser()
    config.read(os.path.join(homedirectory, '.config', 'protectwise.ini'))
    token = config.get('Token', 'token')
    return token


def get_domainReputation(domain):
    # Domain Reputation
    # GET https://api.protectwise.com/api/v1/reputations/domains/ucar.edu
    token = get_token()
    try:
        response = requests.get(
            url="https://api.protectwise.com/api/v1/reputations/domains/" +
                domain,
            params={
                "details": "domain,geo",
            },
            headers={
                "X-Access-Token": token,
            }, )
        return response.content

    except requests.exceptions.RequestException:
        print('HTTP Request failed')


def get_ipReputation(ip):
    # IP Reputation
    # GET https://api.protectwise.com/api/v1/reputations/ips/x.x.x.x
    token = get_token()
    try:
        response = requests.get(
            url="https://api.protectwise.com/api/v1/reputations/ips/" + ip,
            params={
                "details": "ip,geo",
            },
            headers={
                "X-Access-Token": token,
            }, )
        return response.content

    except requests.exceptions.RequestException:
        print('HTTP Request failed')


def get_event_info(days):
    # Event Collection
    # GET https://api.protectwise.com/api/v1/events
    # Returns a list of events, the events are dictionarie.
    token = get_token()
    start, end = get_times(days)
    try:
        response = requests.get(
            url="https://api.protectwise.com/api/v1/events",
            params={
                "start": start,
                "end": end,
            },
            headers={
                "X-Access-Token": token,
            }, )
        events = json.loads(response.content)['events']
        for e in events:
            if e['state'] is None:
                yield e

    except requests.exceptions.RequestException:
        print('HTTP Request failed')


def get_pcap(eventid, filename, basedir=os.getcwd()):
    # Event Pcap Download
    # GET https://api.protectwise.com/api/v1/events/eventid
    token = get_token()
    try:
        response = requests.get(
            url="https://api.protectwise.com/api/v1/pcaps/events/" + eventid,
            params={
                "filename": filename,
            },
            headers={
                "X-Access-Token": token,
            }, )
        with open(os.path.join(basedir, filename) + '.pcap', 'wb') as f:
            f.write(response.content)
    except requests.exceptions.RequestException:
        print('HTTP Request failed')
