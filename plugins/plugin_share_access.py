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

pluginconfig = {'category': ['Lateral Movement'],
                 'mitre': [],
                 'event_ids': ['5140'],
                 'event_fields': ['EventID', 'TimeCreated', 'Provider', 'SubjectUserName', 'SubjectDomainName', 'ObjectType', 'IpAddress', 'ShareName', 'ShareLocalPath'],
                 'title': 'Shares Accessed - Security (5140)',
                 'name': 'plugin_share_access',
                 'description': 'parse network share access events',
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
        
        r = defaultdict(dict)
        for evt in events:
            #print(json.dumps(evt, indent=4))
            key = evt['TimeCreated']
            r[key]['IpAddress'] = evt['IpAddress']
            r[key]['ObjectType'] = evt['ObjectType']
            r[key]['SharePath'] = evt['SharePath']
            r[key]['ShareName'] = evt['ShareName']
            r[key]['Domain'] = evt['Domain']
            r[key]['User'] = evt['User']
            
        if r:
            # Output Table
            table = Table()
            table.add_column('Date', justify='center', no_wrap=True)
            table.add_column('IpAddress', justify='left', no_wrap=True)
            table.add_column('ObjectType', justify='left', no_wrap=True)
            table.add_column('SharePath', justify='left', no_wrap=True)
            table.add_column('ShareName', justify='left', no_wrap=True)
            table.add_column('Domain', justify='left', no_wrap=True)
            table.add_column('User', justify='left', no_wrap=True)
            
            for k, v in sorted(r.items(), key=lambda item: item, reverse=True)
                time_created = key
                table.add_row(time_created, v['IpAddress'], v['ObjectType'], v['SharePath'], v['ShareName'], v['Domain'], v['User']
                
            console.print(table)
        else:
            console.print(' No matching events found', style='red') 
            
    else:
        console.print(' No matching events found', style='red')      
    
    return   
        

if __name__ == "__main__":
    # TESTING
    test_data = {}
    if test_data:
        json_data = json.dumps(test_data)
        print(handler(json_data))
