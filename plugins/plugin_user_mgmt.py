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
                 'event_ids': ['4720, 4722, 4724, 4728, 4732, 4756'],
                 'event_fields': [],
                 'title': 'Account Management Events - Security (47**)',
                 'name': 'plugin_usermgmt',
                 'description': 'parse events related to account management',
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
        
        # Event descriptions
        desc = { 
            '4720': 'User account created',
            '4722': 'User account enabled',
            '4724': 'Attempt to reset account password',
            '4728': 'Member added to security-enabled local group',
            '4732': 'Member added to security-enabled global group',
            '4756': 'Member added to security-enabled universal group'}    
    
    
        for evt in events:
            print(json.dumps(evt, indent=4))
    else:
        console.print(' No matching events found', style='red')      
    
    return   
        

if __name__ == "__main__":
    # TESTING
    test_data = {}
    if test_data:
        json_data = json.dumps(test_data)
        print(handler(json_data))
