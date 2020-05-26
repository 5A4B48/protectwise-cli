import datetime, time
from tzlocal import get_localzone
import requests
import json
import getpass
from configparser import ConfigParser
import os

try:
    input = raw_input
except:
    pass

homedirectory = os.path.expanduser("~")


def get_times(daydiff):
    # Takes an integer and returns a list of start
    # and end times converted into the proper format
    local = get_localzone()
    dts = datetime.datetime.now(local)
    endtime = round(time.mktime(dts.timetuple()) * 1e3 + dts.microsecond / 1e3)
    starttime = round(
        (dts - datetime.timedelta(days=daydiff)).timestamp() * 1e3)
    return (starttime, endtime)


def millisecond_to_date(firstseen, lastseen):
    fseen = datetime.datetime(1970, 1, 1) + datetime.timedelta(
        milliseconds=firstseen)
    lseen = datetime.datetime(1970, 1, 1) + datetime.timedelta(
        milliseconds=lastseen)
    return (fseen, lseen)


def generate_token():
    # Get Token from protectwise
    # POST https://api.protectwise.com/api/v1/token
    if os.path.isdir(homedirectory + "/.config"):
        if os.path.isfile(homedirectory + "/.config/protectwise.ini"):
            print(
                "Protectwise config file already exists, if it is stale please delete and re-run init"
            )
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
        with open(homedirectory + "/.config/protectwise.ini",
                  "w") as configfile:
            config.write(configfile)
    except requests.exceptions.RequestException:
        print('HTTP Request failed')


def get_token():
    config = ConfigParser()
    config.read(homedirectory + "/.config/protectwise.ini")
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
        domainInfo = json.loads(
            response.content)['domain']['additionalProperties'][0]['values'][0]
        domainInfo = {k: v for k, v in domainInfo.items() if v is not None}
        domainInfo = {k: v for k, v in domainInfo.items() if len(v) > 0}

        resolveData = json.loads(response.content)['domain']['resolveData'][0]
        resolveData = {k: v for k, v in resolveData.items() if v is not None}
        seenTimes = millisecond_to_date(resolveData['firstSeen'],
                                        resolveData['lastSeen'])
        resolveData['firstSeen'] = str(seenTimes[0])
        resolveData['lastSeen'] = str(seenTimes[1])

        print("Domain Information: \n")
        for key, val in domainInfo.items():
            print(key.upper(), ":", val, "\n")

        print("Resolved Information: \n")
        for key, val in resolveData.items():
            print(key.upper(), ":", val, "\n")

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
        ipInfo = json.loads(response.content)['ip']
        ipInfo = {k: v for k, v in ipInfo.items() if v is not None}
        ipInfo = {k: v for k, v in ipInfo.items() if len(v) > 0}

        geoInfo = json.loads(response.content)['geo']
        geoInfo = {k: v for k, v in geoInfo.items() if v is not None}
        geoInfo = {k: v for k, v in geoInfo.items() if v is not None}
        print("IP Information: \n")
        for key, val in ipInfo.items():
            print(key.upper(), ":", val, "\n")

        print("\nGeograhic Information: \n")
        for key, val in geoInfo.items():
            print(key.upper(), ":", val, "\n")

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


def get_pcap(eventid, filename):
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
        with open(filename + '.pcap', 'wb') as f:
            f.write(response.content)
    except requests.exceptions.RequestException:
        print('HTTP Request failed')

