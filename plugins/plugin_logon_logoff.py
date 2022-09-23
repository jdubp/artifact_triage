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
                 'event_ids': ['4624', '4634', '4647'],
                 'event_fields': ['EventID', 'TimeCreated', 'Provider', 'TargetUserName', 'TargetDomainName', 'TargetLogonId', 'LogonType', 'AuthenticationPackageName', 'WorkstationName', 'IpAddress'],
                 'title': 'Logon/Logoff Report - Security (4624, 4634, 4647)',
                 'name': 'plugin_logon_logoff',
                 'description': 'parse logon/logoff events by logon id',
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
        report_output_path = os.path.normpath(f'{os.getcwd()}{os.sep}reports{os.sep}')
        output_csv = os.path.normpath(f'{report_output_path}{os.sep}evtx_logon_logoff.csv')
          
        # Rebuild a dictionary grouped by TargetLogonId
        r = defaultdict(dict)
        for evt in events:
            key = evt['TargetLogonId']
            # Get time and event context based on if the event was a logon vs logoff
            if evt['EventID'] != '4624':
                r[key].update({'LogoffTime': evt['TimeCreated']})
                r[key].update({'LogoffEventID': evt['EventID']})
            else:
                r[key].update({'LogonTime': evt['TimeCreated']})
                r[key].update({'LogonEventID': evt['EventID']})
                
            r[key].update(evt)
            # Remove dictionary values that are not needed
            r[key].pop('EventID', None)
            r[key].pop('TimeCreated', None)
            r[key].pop('Provider', None)
            
        if debug:
            print(r)

        # Output CSV
        import csv
        if not os.path.exists(report_output_path):
            os.mkdir(report_output_path)    
          
        columns = ['LogonTime', 'LogonEventID', 'AuthenticationPackageName', 'IpAddress', 'LogonType', 'TargetDomainName', 'TargetLogonId', 'TargetUserName', 'WorkstationName', 'LogoffEventID', 'LogoffTime']
        with open(output_csv, 'w', newline='') as outfile:
            writer = csv.DictWriter(outfile, columns)
            writer.writeheader()
            for k, v in r.items():
                writer.writerow(v)

        console.print(f' {output_csv}', style="dim cyan")  
        
    else:
        console.print(' No matching events found', style="red") 
        
    return   
        

if __name__ == "__main__":
    # TESTING
    test_data = {}
    if test_data:
        json_data = json.dumps(test_data)
        print(handler(json_data))
