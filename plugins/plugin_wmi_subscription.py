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

pluginconfig = {'category': ['Privilege Escalation', 'Peristence'],
                 'mitre': ['T1546'],
                 'event_ids': ['5860', '5861'],
                 'event_fields': [],
                 'title': 'WMI Consumer - WMI-Activity/Operational (5860)',
                 'name': 'plugin_wmi_subscription',
                 'description': 'identify uncommon WMI consumers',
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
        'namespace': r'(root[\\|\/]ccm|securitycenter)|root\\microsoft\\mbam',
        'query': r''
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
                '5860': 'Temporary Consumer',
                '5861': 'Permanent Consumer'}
        
        # Custom result dictionary with multiple key value lists defined in name_subdict function
        r = defaultdict(name_subdict)           
        for evt in events:
            evt['Description'] = desc[evt['EventID']]
            
            # Filtering
            if evt['EventID'] == '5860':
                user_data_key = evt['UserData']['Operation_TemporaryEssStarted']
                namespace = user_data_key['NamespaceName'].lower()
                reason = user_data_key['Query'].lower()
                user = user_data_key['User']
                if re.search(filters['namespace'], namespace, flags=re.I):
                    continue  
            if evt['EventID'] == '5861':
                user_data_key = evt['UserData']['Operation_ESStoConsumerBinding']
                namespace = user_data_key['Namespace'].lower()
                reason = user_data_key['PossibleCause'].lower()
                user = ''
                if re.search(filters['namespace'], namespace, flags=re.I):
                    continue  
                    
            #print(json.dumps(evt, indent=4))

            # Create new dictionary key for grouping
            system_time_day_string = evt['TimeCreated'].split('T')[0]
            key = system_time_day_string + '|' + evt['EventID'] + '|' + namespace + '|' + evt['Description']
            r[key]['TimeCreated'].append(evt['TimeCreated'])
            if user not in r[key]['User']:
                r[key]['User'].append(user)
            if reason not in r[key]['Reason']:
                r[key]['Reason'].append(reason)
        if r:    
            # Output
            table = Table()
            table.add_column('CNT', justify='center', no_wrap=True)
            table.add_column('Date', justify='left', no_wrap=True)
            table.add_column('EventID', justify='left', no_wrap=True)
            table.add_column('Description', justify='left', no_wrap=False)            
            table.add_column('Namespace', justify='left', no_wrap=True)
            table.add_column('User', justify='left', no_wrap=True)
            table.add_column('Reason', justify='left', no_wrap=False)
            
            for k, v in sorted(r.items(), key=lambda item: item, reverse=True):
                count = len(v['TimeCreated'])
                date = k.split('|')[0]
                event_id = k.split('|')[1]
                namespace = k.split('|')[2]
                description = k.split('|')[3]
                reason = '\n'.join(v['Reason'])
                user = '\n'.join(v['User'])
                
                table.add_row(f'{count}', date, event_id, description, namespace, user, reason)
                
            console.print(table)
        else:
            console.print(' No matching events found', style='red') 
  

    else:
        console.print(' No matching events found', style='red')      
    
    return   


# Define subdict for cuustom defaultdict in handler function
def name_subdict():
    return {'TimeCreated': [], 'Reason': [], 'User':[]}
    

if __name__ == "__main__":
    # TESTING
    test_data = {}
    if test_data:
        json_data = json.dumps(test_data)
        print(handler(json_data))
