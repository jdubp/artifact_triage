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

pluginconfig =  {'category': ['Lateral Movement'],
                 'mitre': [],
                 'event_ids': ['1024', '1102'],
                 'event_fields': ['EventID', 'TimeCreated', 'Provider', 'Name', 'Value'],
                 'title': 'Remote Desktop Connections - TerminalServices-RDPClient (1024, 1102)',
                 'name': 'plugin_rdp_conns',
                 'description': 'identify RDP connections',
                 'analysis': ''
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
        'values': []
    }
    events = [x for x in events if x['EventID'] in pluginconfig['event_ids'] and not any(re.match(regex, x['Value']) for regex in filters['values'])]
    
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
        
        # Event descriptions
        desc = { 
            '1024':'RDP Connection Attempt',
            '1102':'RDP Connection Success'}  

        r = defaultdict(name_subdict)            
        for evt in events:
            evt['Description'] = desc[evt['EventID']]
            #print(json.dumps(evt, indent=4))    

            # Create new dictionary key for grouping
            system_time_day_string = evt['TimeCreated'].split('T')[0]
            key = system_time_day_string + '|' + evt['Value']
            r[key]['TimeCreated'].append(evt['TimeCreated'])
            r[key]['EventType'].append(f'{evt["Description"]} ({evt["EventID"]})')
            
        # Output
        table = Table()
        table.add_column('CNT', justify='center', no_wrap=True)
        table.add_column('Date', justify='left', no_wrap=True)
        table.add_column('Workstation', justify='left', no_wrap=True)
        table.add_column('EventType', justify='left', no_wrap=True)
        
        for k, v in sorted(r.items(), key=lambda item: item, reverse=True):
            count = len(v['TimeCreated'])
            date = k.split('|')[0]
            workstation = k.split('|')[1]
            event_type = '\n'.join(list(set(v['EventType'])))
            
            table.add_row(f'{count}', date, workstation, event_type)
            
        console.print(table)  

    else:
        console.print(' No matching events found', style='red')      
    
    return   
    
# Define subdict for cuustom defaultdict in handler function
def name_subdict():
    return {'TimeCreated': [], 'EventType': []}
        

if __name__ == "__main__":
    # TESTING
    test_data = {}
    if test_data:
        json_data = json.dumps(test_data)
        print(handler(json_data))
