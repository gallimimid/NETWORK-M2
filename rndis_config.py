import asyncio
import requests
import M2_mass_config
import sys
import json
import time
import logging

# configure logging module
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('rndis_config.log')
sh = logging.StreamHandler(sys.stdout)
# formatter = logging.Formatter('[%(asctime)s] - %(funcName)s - %(message)s',
                               # datefmt='%a, %d %b %Y %H:%M:%S')
# fh.setFormatter(formatter)
# sh.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(sh)

# global card settings
ip_address = '169.254.0.1'
admin_password = 'Password1!'
firmware_version = '1.7.5'

# sensor thresholds
sensor_data = {
    'temperatures':
        [
            {"alarms":{"enabled":True,"hysteresis":1,"thresholds":{"lowCritical":273.15,"lowWarning":283.15,"highWarning":343.15,"highCritical":353.15}}}
        ],
    'humidities':
        [
            {"alarms":{"enabled":True,"hysteresis":1,"thresholds":{"lowCritical":10,"lowWarning":20,"highWarning":80,"highCritical":90}}}
        ],
    'digitalInputs':
        [
            {"alarms":{"enabled":True,"level":6}},
            {"alarms":{"enabled":True,"level":6}}
        ]
    }

# commission M2 card
logging.info('commissioning card')

url = f'https://{ip_address}/rest/mbdetnrs/1.0/card/users/password'
json = {"user":{"username": "admin","current_pwd":"admin","new_pwd": admin_password}}
response = requests.put(url, json=json, verify=False, timeout=10)

if response.status_code == 200:
    logging.info('card successfully commissioned with new password')
else:
    logging.error('failed to commission card')
    M2_mass_config.end_program()

# get authorization token
url = f'https://{ip_address}/rest/mbdetnrs/1.0/oauth2/token'
auth_json = {'username':'admin',
             'password':admin_password,
             'grant_type':'password',
             'scope':'GUIAccess'}
response = requests.post(url, verify=False, json=auth_json, timeout=60)

if response.status_code == 200:
    logging.info('card successfully authenticated')
else:
    logging.error('authentication failure')
    M2_mass_config.end_program()

access_token = response.json()['access_token']
headers = {'Authorization':  'Bearer ' + access_token}

# get identification data
url = f'https://{ip_address}/rest/mbdetnrs/1.0/managers/1/identification/'
response = requests.get(url, headers=headers, verify=False, timeout=60)
identification = response.json()

# apply firmware upgrade if necessary
if identification['firmwareVersion'] != firmware_version:
    asyncio.run(
        M2_mass_config.run(
            network=f'{ip_address}/32',
            password = admin_password,
            upgrade_path = 'Eaton_Network_M2_1.7.5.tar'))
    print('firmware updating...card rebooting...')
    timer = 0
    while timer < 300:
        print(f'{timer}', end="\r")
        time.sleep(1)
else:
    print('firmware up to date')
    
# apply configurations
asyncio.run(
    M2_mass_config.run(network=f'{ip_address}/32',
    password = admin_password,
    import_path = f'{identification["serialNumber"]}_{firmware_version}.xlsx'))

print('card rebooting...please wait')
timer = 0
while timer < 240:
    print(f'{timer}', end="\r")
    timer += 1
    time.sleep(1)

# get authorization token
url = f'https://{ip_address}/rest/mbdetnrs/1.0/oauth2/token'
auth_json = {'username':'admin',
             'password':admin_password,
             'grant_type':'password',
             'scope':'GUIAccess'}
response = requests.post(url, verify=False, json=auth_json, timeout=60)
access_token = response.json()['access_token']
headers = {'Authorization':  'Bearer ' + access_token}

# discover sensors

url = f'https://{ip_address}/rest/mbdetnrs/1.0/sensors/actions/scanDiscover'
response = requests.post(url, headers=headers, verify=False, timeout=60)
if response.status_code == 200:
    print('discovering sensors')
else:
    print('failed to initiate discovery process')

no_sensors = True
discovered_one = False

while no_sensors == True:
    timer = 0
    while timer < 10:
        print(f'{timer}', end="\r")
        timer += 1
        time.sleep(1)

    # get discovered sensors and channels
    url = f'https://{ip_address}/rest/mbdetnrs/1.0/sensors/devices?$expand=2'
    response = requests.get(url, headers=headers, verify=False, timeout=60)
    if response.status_code == 200:
        print('checking discovered sensors')
    else:
        print('failed to check discovered sensors')
    # check if any sensors were discovered
    if response.json():
        if response.json()['members@count'] == 2:
            # populate device/channel data
            devices = response.json()['members']
            no_sensors = False
        elif response.json()['members@count'] == 1 and not discovered_one:
            discovered_one = True
        elif discovered_one:
            print('only discovered one sensor')
            M2_mass_config.end_program()

print('configuring sensor thresholds')

for device in devices:
    for attribute, thresholds in sensor_data.items():
        # set channels data for each device
        endpoints = device['channels'][attribute]['members']
        for endpoint in endpoints:
            url = f'https://{ip_address}{endpoint["@id"]}'
            print(f'setting {attribute} thresholds')
            response = requests.put(url, headers=headers, json=thresholds, verify=False, timeout=60)
            if response.status_code == 200:
                print(f'{attribute} thresholds successfully applied')
            else:
                print(f'failed to apply {attribute} thresholds')


print('completed')