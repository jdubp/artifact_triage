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
                 'event_ids': [],
                 'event_fields': [],
                 'title': '{Event Description} - {Event Log Short Name} ({EventIDs})',
                 'name': '{plugin name}',
                 'description': '{short description of plugin purpose}',
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
    # events = {'TimeCreated': '', 'EventID': '', '<event_fields>': ''}
    filters = {}
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
        
        # Custom result dictionary with multiple key value lists defined in name_subdict function
        r = defaultdict(name_subdict)           
        for evt in events:
            print(json.dumps(evt, indent=4))
            '''
            # Create new dictionary key for grouping
            system_time_day_string = evt['TimeCreated'].split('T')[0]
            key = system_time_day_string + '|'
            r[key]['TimeCreated'].append(evt['TimeCreated'])
        if r:    
            # Output
            table = Table()
            table.add_column('CNT', justify='center', no_wrap=True)
            
            for k, v in sorted(r.items(), key=lambda item: item, reverse=True):
                count = len(v['TimeCreated'])
                date = k.split('|')[0]
                
                table.add_row(f'{count}', date)
                
            console.print(table)
        else:
            console.print(' No matching events found', style='red') 
        '''   

    else:
        console.print(' No matching events found', style='red')      
    
    return   


# Define subdict for cuustom defaultdict in handler function
def name_subdict():
    return {'TimeCreated': []}
    

if __name__ == "__main__":
    # TESTING
    test_data = {}
    if test_data:
        json_data = json.dumps(test_data)
        print(handler(json_data))
