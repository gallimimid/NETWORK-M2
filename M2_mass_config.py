import asyncio
import requests
from update_template import template
import concurrent.futures
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse, sys, os
from io import BytesIO
import pandas as pd
from pandas.io.json import json_normalize
import ipaddress
from datetime import datetime
import socket
import json
import re


# suppress insecure warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# get network ip address
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def GetArgs():
    # command line arguments

    parser = argparse.ArgumentParser(description='Mass configure NETWORK-M2 cards')
    parser.add_argument('-n', '--network', default=get_ip() + '/24', action='store', 
        help='IP network addresses in CIDR notation')
    parser.add_argument('-l', '--ip-file', action='store', 
        help='Spreadsheet of IP network addresses')
    parser.add_argument('-u', '--user', default='admin', action='store', 
        help='User name to use when logging in to network card')
    parser.add_argument('-p', '--password', default='admin', action='store', 
        help='Password to use when logging in to network card')
    parser.add_argument('-P', '--passphrase', default='password', action='store', 
        help='Passphrase used to encode and decode configuration file')
    parser.add_argument('-I', '--import-path', action='store', 
        help='Path to import configuration spreadsheet')
    parser.add_argument('-E', '--export-path', action='store', 
        help='Path to export configuration spreadsheet template')
    parser.add_argument('-C', '--commission', action='store_true', 
        help='Commission sanitized cards')
    parser.add_argument('-S', '--sanitize', action='store_true', 
        help='Sanitize all data on cards')
    parser.add_argument('-U', '--upgrade-path', action='store', 
        help='Path to firmware upgrade file')
    parser.add_argument('-f', '--features', default=['*'], nargs='*', 
        help='Include the following features: ')
    args = parser.parse_args()
    return args


def end_program():
    print('Exiting Program')
    try:
        sys.exit(0)
    except SystemExit:
        os._exit(0)


def get_configs(ip, args):

    try:
        if args.commission:
            url = f'https://{ip}/rest/mbdetnrs/1.0/card/users/password'
            json = {"user":{"username":"admin","current_pwd":"admin","new_pwd":args.password}}
            response = requests.put(url, verify=False, json=json, timeout=10)
        
            if response.status_code != 200:
                return None
                
        # Authenticate
        url = f'https://{ip}/rest/mbdetnrs/1.0/oauth2/token'
        json = {'username':'admin','password':args.password,'grant_type':'password','scope':'GUIAccess'}
        response = requests.post(url, verify=False, json=json, timeout=10)
        if response.status_code != 200:
            return None
        access_token = response.json()['access_token']
        headers = {'Authorization':  'Bearer ' + access_token}
        
        url = f'https://{ip}/rest/mbdetnrs/1.0/managers/1/identification/'
        id_response = requests.get(url, headers=headers, verify=False, timeout=10)

        url = f'https://{ip}/rest/mbdetnrs/1.0/managers/1/actions/saveSettings'
        json = {"exclude": [], "passphrase": args.passphrase}
        config_response = requests.post(url, headers=headers, json=json, verify=False, timeout=10)

        return {'ip': ip, 'id': id_response.text, 'config': config_response.text}
        
    except requests.exceptions.RequestException as e:
        print(e)
        return None
        
        
async def export_configs(args):
    # get all configurations from network cards
    interface = ipaddress.ip_interface(args.network)
    with concurrent.futures.ThreadPoolExecutor(max_workers=250) as executor:
        loop = asyncio.get_running_loop()
        coroutes = [
            loop.run_in_executor(
                executor,
                get_configs,
                ip,
                args
                ) 
            for ip in interface.network
        ]
        configs = await asyncio.gather(*coroutes)
        
    # create unique list of firmware revisions
    firmwares = []
    for config in configs:
        if config:
            json_id = json.loads(config['id'])
            firmware = json_id['firmwareVersion']
            if firmware not in firmwares:
                firmwares.append(firmware)

    # create workbook templates
    workbooks = {}
    for firmware in firmwares:
        tabs = {}
        for feature, data in template[firmware].items():
            columns = [*data['columns'].values()]
            df = pd.DataFrame(columns=columns)
            tabs[feature] = df
        workbooks[firmware] = tabs

    for config in configs:
        if config: # make sure config exists
            # convert json to dict
            json_id = json.loads(config['id'])
            json_config = json.loads(config['config'])
            firmware = json_id['firmwareVersion']
            # iterate over features
            for feature, data in json_config['features'].items():
                ndf = json_normalize(data)
                version = ndf[f'data.version']
                # iterate through each column and its data
                for column, series in ndf.iteritems():
                    setting = series.iloc[0]
                    fc = f'{feature}.{column}'
                    if type(setting) is list: # test if setting is a list
                        fdf = json_normalize(setting)
                        # prepend feature.column to each column
                        fdf = fdf.rename(columns=lambda x: f'features.{fc}.{x}')
                        # add M2 context to each row
                        fdf['IpAddress'] = config['ip']
                        fdf['passphrase'] = json_config.get('passphrase')
                        fdf[f'features.{feature}.data.version'] =version
                        if workbooks.get(firmware) is not None:
                            if workbooks[firmware].get(fc) is not None:
                                workbooks[firmware][fc] = workbooks[firmware][fc].append(fdf, sort=False)
                        ndf = ndf.drop(columns=[column])
                # prepend feature to each column
                ndf = ndf.rename(columns=lambda x: f'features.{feature}.{x}')
                # add M2 context to each row
                ndf['IpAddress'] = config['ip']
                ndf['passphrase'] = json_config.get('passphrase')
                # write setting only if firmware and feature exist
                if workbooks.get(firmware) is not None:
                    if workbooks[firmware].get(feature) is not None:
                        workbooks[firmware][feature] = workbooks[firmware][feature].append(ndf, sort=False)

    # create report
    if workbooks:
        print('Creating configuration spreadsheet')
    for firmware, tabs in workbooks.items():
        with pd.ExcelWriter(f'mass_config_{firmware}.xlsx') as writer:
            for feature, data in tabs.items():
                # translate sheet names
                sheet_name = template[firmware][feature]['name']
                # add white space
                sheet_name = re.sub(r'(\w)([A-Z])', r'\1 \2', sheet_name)
                # Translate column names here
                column_dict = template[firmware][feature]['columns']
                inv_column_dict = {v: k for k, v in column_dict.items()}
                data = data.rename(columns=inv_column_dict)
                data.to_excel(writer,sheet_name=sheet_name,index=False)
    

async def import_configs(args):

    # excluded keys
    ex_keys = ['IpAddress', 'passphrase']

    # extract firmware revision from filename
    result = re.search(r'(\d\.\d\.\d)', args.import_path)
    if result:
        firmware = result.group(0)
    else:
        print('Firmware revision not properly encoded in filename "x.y.z"')
        end_program()
        
    # import excel file
    imported_file = pd.ExcelFile(args.import_path)
    
    # store each excel sheet as dataframe in dict
    fdfs = {}
    for feature_name in imported_file.sheet_names:
        # translate sheet names
        _feature_name = feature_name.replace(' ', '')
        for feature, data in template[firmware].items():
            if _feature_name == data['name']:
                _feature_path = feature
                break
        # filter features by argument
        if _feature_name in args.features or args.features[0] == '*':
            fdf = imported_file.parse(feature_name)
            # Translate column names here
            # fdf = fdf.rename(columns=template[firmware][_feature_name]['columns'])
            fdfs[_feature_path] = fdf
            
        
    # initiate empty configs dict
    configs = {}
    
    # loop through each feature df
    for feature_name, df in fdfs.items():
        df = df.fillna('')
        endpoint = template[firmware][feature_name]['endpoint']
        # determine if foreign key dataframe
        re_root = re.search(r'\.([^.]*)$', feature_name)
        if re_root:
            root = re_root.group(1)
        else:
            root = ''
        # loop through each df row
        for _,row in df.iterrows():
            root_flag = False
            # determine ip
            try:
                ip = row['IpAddress']
                ipaddress.ip_address(ip)
            except:
                continue
            # determine passphrase
            passphrase = row['passphrase']
            if (ip,passphrase) not in configs:
                configs[(ip,passphrase)] = {}
            if endpoint not in configs[(ip,passphrase)]:
                configs[(ip,passphrase)][endpoint] = {}
            # loop through series as index/value pair
            for index, value in row.iteritems():
                if any(ex_key in index for ex_key in ex_keys):
                    continue
                _configs = configs[(ip,passphrase)][endpoint]
                # create key list
                keys = index.split('.')
                i_last = len(keys) - 1
                # loop through keys
                for i, key in enumerate(keys):
                    if type(_configs) is dict:
                        if key not in _configs:
                            if key == root:
                                _configs[key] = []
                            elif i == i_last:
                                if key == 'version':
                                    _configs[key] = str(value)
                                elif key == 'enabled':
                                    _configs[key] = bool(value)
                                elif key == 'plaintext':
                                    if value == "":
                                        _configs[key] = None
                                else:
                                    _configs[key] = value
                            else:
                                _configs[key] = {}
                        # step one level deeper
                        _configs = _configs[key]
                    elif type(_configs) is list:
                        if not root_flag:
                            root_flag = True
                            _configs.append({})
                        # step one level deeper
                        _configs = _configs[-1]
                        if key not in _configs:
                            if i == i_last:
                                _configs[key] = value
                            else:
                                _configs[key] = {}
                        # step one level deeper
                        _configs = _configs[key]

    with concurrent.futures.ThreadPoolExecutor(max_workers=250) as executor:
        loop = asyncio.get_running_loop()
        coroutes = [
            loop.run_in_executor(
                executor,
                push_configs,
                args,
                i_p[0],
                i_p[1],
                endpoint,
                config
                ) # i_p is  tuple containing ip and passphrase
            for i_p, endpoints in configs.items()
                for endpoint, config in endpoints.items()
        ]
        results = await asyncio.gather(*coroutes)
        
    for result in results:
        if result['response'] != 'No response':
            if result['response'].status_code != 200:
                print(result['response'])
        else:
            print(f'No response from {result["ip"]}')


def push_configs(args, ip, passphrase, endpoint, config):

    try:
        if endpoint == '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings':
            print('Wrapping configuration file')
            config['passphrase'] = passphrase
            config['version'] = '1.0'
            config = {'exclude':[], 'passphrase': args.passphrase, 'data': config}
        with open('M2_config.json', 'w') as json_file:  
            json.dump(config, json_file, sort_keys=True, indent=4)
                
        # Authenticate
        print(f'Authenticating with {ip}')
        url = f'https://{ip}/rest/mbdetnrs/1.0/oauth2/token'
        auth_json = {'username':'admin','password':args.password,'grant_type':'password','scope':'GUIAccess'}
        response = requests.post(url, verify=False, json=auth_json, timeout=10)
        if response.status_code != 200:
            print(f'Authentication unsuccessful')
            return None
        else:
            access_token = response.json()['access_token']
            print(f'Authentication successful, token: {access_token}')
        access_token = response.json()['access_token']
        headers = {'Authorization':  'Bearer ' + access_token}
        
        url = f'https://{ip}{endpoint}'
        print(f'Accessing endpoint: {endpoint}')
        config_response = requests.post(url, 
                                        headers=headers, 
                                        json=config, 
                                        verify=False, 
                                        timeout=10)
        
        print(config_response)
        return {'ip': ip, 'response': config_response} # 
    except requests.exceptions.RequestException as e:
        print(e)
        return {'ip': ip, 'response': 'No response'}
        
async def upgrade_card(args):
    interface = ipaddress.ip_interface(args.network)

    with concurrent.futures.ThreadPoolExecutor(max_workers=250) as executor:
        loop = asyncio.get_running_loop()
        coroutes = [
            loop.run_in_executor(
                executor,
                push_upgrades,
                ip,
                args
                ) 
            for ip in interface.network
        ]
        results = await asyncio.gather(*coroutes)
        
    for result in results:
        print(result['response'])
        if result['response'] != 'No response':
            if result['response'].status_code != 200:
                print(result['response'])
        else:
            print(f'No response from {result["ip"]}')

        
def push_upgrades(ip, args):

    try:
        # Authenticate
        print('Authenticating with NMC')
        url = f'https://{ip}/rest/mbdetnrs/1.0/oauth2/token'
        auth_json = {'username':'admin',
                     'password':args.password,
                     'grant_type':'password',
                     'scope':'GUIAccess'}
        response = requests.post(url, verify=False, json=auth_json, timeout=10)
        if response.status_code != 200:
            return None
        else:
            access_token = response.json()['access_token']
            print(f'Authentication successful, token: {access_token}')
        headers = {'Authorization':  'Bearer ' + access_token}
        print('Loading firmware file')
        files = {'upgradeFile': open(args.upgrade_path, 'rb')}
        
        url = f'https://{ip}/rest/mbdetnrs/1.0/managers/1/actions/upgrade'
        upgrade_response = requests.post(url, 
                                        headers=headers, 
                                        files=files, 
                                        verify=False, 
                                        timeout=180)
        

        return {'ip': ip, 'response': upgrade_response} # 
    except requests.exceptions.RequestException as e:
        print(e)
        return {'ip': ip, 'response': 'No response'}

        
async def sanitize_cards(args):
    interface = ipaddress.ip_interface(args.network)

    with concurrent.futures.ThreadPoolExecutor(max_workers=250) as executor:
        loop = asyncio.get_running_loop()
        coroutes = [
            loop.run_in_executor(
                executor,
                push_sanitization,
                ip,
                args
                ) 
            for ip in interface.network
        ]
        results = await asyncio.gather(*coroutes)
        
    for result in results:
        print(result['response'])
        if result['response'] != 'No response':
            if result['response'].status_code != 200:
                print(result['response'])
        else:
            print(f'No response from {result["ip"]}')

        
def push_sanitization(ip, args):

    try:
        # Authenticate
        print('Authenticating with NMC')
        url = f'https://{ip}/rest/mbdetnrs/1.0/oauth2/token'
        auth_json = {'username':'admin',
                     'password':args.password,
                     'grant_type':'password',
                     'scope':'GUIAccess'}
        response = requests.post(url, verify=False, json=auth_json, timeout=10)
        if response.status_code != 200:
            return None
        else:
            access_token = response.json()['access_token']
            print(f'Authentication successful for {ip}, token: {access_token}')
        headers = {'Authorization':  'Bearer ' + access_token}
        print(f'Sanitizing {ip}')
        
        url = f'https://{ip}/rest/mbdetnrs/1.0/managers/1/actions/sanitize'
        upgrade_response = requests.post(url, 
                                        headers=headers, 
                                        verify=False, 
                                        timeout=180)
        

        return {'ip': ip, 'response': upgrade_response} # 
    except requests.exceptions.RequestException as e:
        print(e)
        return {'ip': ip, 'response': 'No response'}

        
async def commission_cards(args):
    interface = ipaddress.ip_interface(args.network)

    with concurrent.futures.ThreadPoolExecutor(max_workers=250) as executor:
        loop = asyncio.get_running_loop()
        coroutes = [
            loop.run_in_executor(
                executor,
                push_commissioning,
                ip,
                args
                ) 
            for ip in interface.network
        ]
        results = await asyncio.gather(*coroutes)
        
    for result in results:
        print(result['response'])
        if result['response'] != 'No response':
            if result['response'].status_code != 200:
                print(result['response'])
        else:
            print(f'No response from {result["ip"]}')

        
def push_commissioning(ip, args):

    try:
        print(f'Commissioning {ip}')
        
        url = f'https://{ip}/rest/mbdetnrs/1.0/card/users/password'
        json = {"user":{"username": args.user,"current_pwd":"admin","new_pwd": args.password}}
        commission_response = requests.put(url, 
                                        json=json,
                                        verify=False, 
                                        timeout=10)
        

        return {'ip': ip, 'response': commission_response}
    except requests.exceptions.RequestException as e:
        print(e)
        return {'ip': ip, 'response': 'No response'}

        
async def main():

    args = GetArgs()
    print(args)
    
    if args.upgrade_path:
        print("Upgrading cards...")
        await upgrade_card(args)

    elif args.export_path is not None:
        print("Exporting configurations.")
        await export_configs(args)
        
    elif args.import_path is not None:
        print("Importing configurations.")
        await import_configs(args)

    elif args.commission:
        print("Commissioning network cards")
        await commission_cards(args)

    elif args.sanitize:
        print("Sanitizing network cards")
        await sanitize_cards(args)

    else:
        print("No arguments specified. Default behavior is to export configurations.")
        await export_configs(args)
        
# Start program
if __name__ == "__main__":
    asyncio.run(main())

