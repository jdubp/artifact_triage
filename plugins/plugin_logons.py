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
                 'event_ids': ['4624'],
                 'event_fields': ['EventID', 'TimeCreated', 'Provider', 'TargetUserName', 'TargetDomainName', 'TargetLogonId', 'LogonType', 'AuthenticationPackageName', 'WorkstationName', 'IpAddress'],
                 'title': 'Logon Events - Security (4624)',
                 'name': 'plugin_logons',
                 'description': 'parse logon events',
                 'analysis': ''
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

        # Logon types
        types = { 
            '2': 'Interactive',
            '3': 'Network',
            '4': 'Batch',
            '5': 'Service',
            '7': 'Unlock',
            '8': 'NetworkCleartext',
            '9': 'NewCredentials',
            '10': 'RemoteInteractive',
            '11': 'CachedInteractive'}  
            
        # Rebuild a dictionary grouped by day and user
        r = defaultdict(name_subdict)
        for evt in events:
            # Get logon type description
            if str(evt['LogonType']) in types.keys():
                desc = types[str(evt['LogonType'])]
            else:
                desc = '-'
            logon_type = f'{evt["LogonType"]} ({desc})'
            # Create new dictionary key for grouping
            system_time_day_string = evt['TimeCreated'].split('T')[0]
            key = system_time_day_string + '|' + evt['TargetUserName']
            r[key]['TimeCreated'].append(evt['TimeCreated'])
            if logon_type not in r[key]['LogonType']:
                r[key]['LogonType'].append(logon_type)
            if evt['WorkstationName'] not in r[key]['Workstation']:
                r[key]['Workstation'].append(evt['WorkstationName'])
            
        # Output
        table = Table()
        table.add_column('CNT', justify='center', no_wrap=True)
        table.add_column('Date', justify='left', no_wrap=True)
        table.add_column('Username', justify='left', no_wrap=True)
        table.add_column('LogonType', justify='left', no_wrap=True)
        table.add_column('Workstation', justify='left', no_wrap=True)
        
        for k, v in sorted(r.items(), key=lambda item: item, reverse=True):
            count = len(v['TimeCreated'])
            date = k.split('|')[0]
            user = k.split('|')[1]
            logon = '\n'.join(v['LogonType'])
            workstation ='\n'.join(v['Workstation'])
            
            table.add_row(f'{count}', date, user, logon, workstation)
            
        console.print(table)  
    else:
        console.print(' No matching events found', style="red")    
        
    return   

# Define subdict for cuustom defaultdict in handler function
def name_subdict():
    return {'TimeCreated': [], 'LogonType': [], 'Workstation': []}   
    

if __name__ == "__main__":
    # TESTING
    test_data = {}
    if test_data:
        json_data = json.dumps(test_data)
        print(handler(json_data))