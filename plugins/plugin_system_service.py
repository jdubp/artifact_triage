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

pluginconfig =  {'category': ['Peristence', 'Privilege Escalation'],
                 'mitre': ['T1543'],
                 'event_ids': ['7045'],
                 'event_fields': [],
                 'title': 'New/Modified Service - System (7045, 7040)',
                 'name': 'plugin_system_service',
                 'description': 'parse service install/modification events',
                 'analysis': 'Installed services may provide indications of malicious persistence'
                }
pluginerrors =  {'error': ''}
  

def handler(q):
    events = q
    if not events:
        return False
    
    # Console output
    print()
    console.print(f'[+] {pluginconfig["name"]}: {pluginconfig["description"]}', style='cyan')

    # Filter events of interest
    filters = {
        'image_path': r'.*(\\ProgramData\\Microsoft\\Windows Defender\\).*',
        'service_name': r'Background Intelligent Transfer Service'
    }
    events = [x for x in events if x['EventID'] in pluginconfig['event_ids']]
    
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
        
        # Event description
        desc = {
                '7040': 'Service Start Type Changed',
                '7045': 'New Service Installed'}
        
        r = defaultdict(name_subdict)
        for evt in events:
            #print(json.dumps(evt, indent=4))
        
            # Filtering
            if evt.get('ImagePath'):
                if re.search(filters['image_path'], evt['ImagePath'], flags=re.I):
                    continue
            if evt.get('param1'):
                if re.match(filters['service_name'], evt['param1'], flags=re.I):
                    continue
                    
            # Map description based on EventID
            evt['Description'] = desc[evt['EventID']]
            
            # Populate keys dependent on specific Event ID captured
            if evt['EventID'] == '7040':
                service_name = evt['param1']
                # Start type changed to
                start = f'{evt["param3"]}'
                info = evt['param4']
                account_name = ''
            else:
                service_name = evt['ServiceName']
                start = evt['StartType']
                info = evt['ImagePath']
                account_name = evt['AccountName']
            
            # Create new dictionary key for grouping
            system_time_day_string = evt['TimeCreated'].split('T')[0]
            key = system_time_day_string + '|' + evt['EventID'] + '|' + evt['Description'] + '|' + service_name + '|' + info + '|' + start
            r[key]['TimeCreated'].append(evt['TimeCreated'])
            if account_name not in r[key]['AccountName']:
                r[key]['AccountName'].append(account_name)

        # Output
        table = Table()
        table.add_column('CNT', justify='center', no_wrap=True)
        table.add_column('Date', justify='left', no_wrap=True)
        table.add_column('EventID', justify='left', no_wrap=True)
        table.add_column('Description', justify='left', no_wrap=True)
        table.add_column('ServiceName', justify='left', no_wrap=True)
        table.add_column('Info', justify='left', no_wrap=True)
        table.add_column('StartType', justify='left', no_wrap=True)
        table.add_column('AccountName', justify='left', no_wrap=True)
        
        for k, v in sorted(r.items(), key=lambda item: item, reverse=True):
            count = len(v['TimeCreated'])
            date = k.split('|')[0]
            event_id = k.split('|')[1]
            description = k.split('|')[2]
            service_name = k.split('|')[3]
            info = k.split('|')[4]
            start_type = k.split('|')[5]
            account_name = '\n'.join(v['AccountName'])
            
            table.add_row(f'{count}', date, event_id, description, service_name, info, start_type, account_name)
            
        console.print(table)              
        
    else:
        console.print(' No matching events found', style='red')      
    
    return   


# Define subdict for cuustom defaultdict in handler function
def name_subdict():
    return {'TimeCreated': [], 'AccountName': []}
        
        

if __name__ == "__main__":
    # TESTING
    test_data = {}
    if test_data:
        json_data = json.dumps(test_data)
        print(handler(json_data))
