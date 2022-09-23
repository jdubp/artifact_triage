#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
from collections import OrderedDict, defaultdict
from rich.console import Console
from rich.table import Table

# Logging
debug = False
console = Console()

pluginconfig = {'category': [],
                 'mitre': [],
                 'event_ids': ['4625'],
                 'event_fields': ['EventID', 'TimeCreated', 'Provider', 'TargetUserName', 'TargetDomainName', 'TargetLogonId', 'LogonType', 'AuthenticationPackageName', 'WorkstationName', 'IpAddress', 'Status'],
                 'title': 'Failed Logons - Security (4625)',
                 'name': 'plugin_failed_logons',
                 'description': 'parse failed logon events',
                 'analysis': 'Failed logon attempts from public IP addresses indicates that RDP/TermServ is accessible from the Internet'
               }
pluginerrors = {'error': ''}
  

def handler(q):
    events = q
    if not events:
        return False
    
    # Console output
    print()
    console.print(f'[+] {pluginconfig["name"]}: {pluginconfig["description"]}', style='cyan')
      
    # Filter events of interest
    filters = {
        'domain_name': ['NT AUTHORITY', 'NT Service'],
        'user_name': r'.*\$'
    }
    events = [x for x in events if x['EventID'] in pluginconfig['event_ids'] and x['TargetDomainName'] not in filters['domain_name'] and not re.match(filters['user_name'], x['TargetUserName'], re.I)]
    
    # If certain event fields are desired, remove all others
    if pluginconfig['event_fields']:
        events = [{key: value for key, value in dict.items() if key in pluginconfig['event_fields']} for dict in events]    
    
    if events:
        console.print(f' {pluginconfig["title"]}', style='dim cyan')
        ################################
        #
        # Plugin-specific code below
        #
        ################################
        
        # Failed logon status mappings
        status = { 
            '0xc0000064': 'Logon w/ misspelled/bad account',
            '0xc000006a': 'Logon w/ misspelled/bad password',
            '0xc000006d': 'Bad username/authentication info',
            '0xc000006e': 'Logon restrictions apply',
            '0xc000006f': 'Logon outside auth. hours',
            '0xc0000070': 'Logon from unauth workstation',
            '0xc0000071': 'Logon w/ expired password',
            '0xc0000072': 'Logon to disabled account',
            '0xc00000dc': 'SAM server in incorrect state',
            '0xc0000133': 'Clocks out of sync',
            '0xc000015b': 'User not granted requested logon',
            '0xc000018c': 'Trust relationship failed',
            '0xc0000192': 'NetLogon service not started',
            '0xc0000193': 'User logon w/ expired account',
            '0xc0000224': 'User must change password at next logon',
            '0xc0000225': 'Windows bug',
            '0xc0000234': 'Account locked',
            '0xc00002ee': 'An error occurred',
            '0xc0000413': 'Auth firewall in use',
            '0xc000005e': 'No logon servers available'}
            
        # Rebuild a dictionary to get daily failed logon counts
        r = defaultdict(name_subdict)
        for evt in events:
            # Get logon status error description
            if evt['Status'] in status.keys():
                desc = status[evt['Status']]
            else:
                desc = '-'
            logon_error = f'{evt["Status"]} ({desc})'
            # Create new dictionary key for grouping
            system_time_day_string = evt['TimeCreated'].split('T')[0]
            key = system_time_day_string + '|' + evt['TargetUserName'] + '|' + str(evt['LogonType']) + '|' + evt['IpAddress']
            r[key]['TimeCreated'].append(evt['TimeCreated'])
            r[key]['Status'].append(logon_error)
            
        # Output
        table = Table()
        table.add_column('CNT', justify='center', no_wrap=True)
        table.add_column('Date', justify='left', no_wrap=True)
        table.add_column('Username', justify='left', no_wrap=True)
        table.add_column('LogonType', justify='left', no_wrap=True)
        table.add_column('IpAddress', justify='left', no_wrap=True)
        table.add_column('Failure Reason', justify='left', no_wrap=True)
        
        for k, v in sorted(r.items(), key=lambda item: item, reverse=True):
            count = len(v['TimeCreated'])
            date = k.split('|')[0]
            user = k.split('|')[1]
            logon_type = k.split('|')[2]
            ip_address = k.split('|')[3]
            status = '\n'.join(v['Status'])
            
            table.add_row(f'{count}', date, user, logon_type, ip_address, status)
            
        console.print(table) 
    
    else:
        console.print(' No matching events found', style="red")
        
    return   

# Define subdict for cuustom defaultdict in handler function
def name_subdict():
    return {'TimeCreated': [], 'Status': []}
    

if __name__ == "__main__":
    # TESTING
    test_data = {}
    if test_data:
        json_data = json.dumps(test_data)
        print(handler(json_data))