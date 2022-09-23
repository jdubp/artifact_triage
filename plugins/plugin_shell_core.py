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
                 'event_ids': ['9707'],
                 'event_fields': ['EventID', 'TimeCreated', 'Provider', 'Command'],
                 'title': 'App Execution - Shell-Core (9707)',
                 'name': 'plugin_shell_core',
                 'description': 'identify apps run via Run/RunOnce keys',
                 'analysis': 'Unusual application executions may be the result of malware'
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
        'command': []
    }
    events = [x for x in events if x['EventID'] in pluginconfig['event_ids'] and not any(re.search(regex, x['Command']) for regex in filters['command'])]
    
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
        
        from collections import Counter
        executions = []
        for evt in events:
            #print(json.dumps(evt, indent=4))
            executions.append(evt['Command'])
        counts = Counter(executions)
        
        # Output
        table = Table()
        table.add_column('CNT', justify='center', no_wrap=True)
        table.add_column('Command', justify='left', no_wrap=True)
        
        # Sort by count of command executions
        for k, v in sorted(counts.items(), key=lambda item: item[1], reverse=True):
            table.add_row(f'{v}', f'{k}')
            
        console.print(table)       

    else:
        console.print(' No matching events found', style='red')      
    
    return   
        

if __name__ == "__main__":
    # TESTING
    test_data = {}
    if test_data:
        json_data = json.dumps(test_data)
        print(handler(json_data))
