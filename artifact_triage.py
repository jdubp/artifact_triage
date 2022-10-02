#!/usr/bin/env python

# ---------------------------------------------------------------------------------
# artifact_triage.py 
#   assists in triaging forensic artifacts (registry, event logs) gathered from a system
# 
# Dependencies: These must be manually updated as desired; locations are defined in config.py
#   python 3.x
#   regripper - https://github.com/keydet89/RegRipper3.0
#   evtx_dump - https://github.com/omerbenamram/evtx
#   chainsaw and rules - https://github.com/WithSecureLabs/chainsaw
#   sigma rules - https://github.com/SigmaHQ/sigma/tree/master/rules
#
# Change history: 
#   20220908 - created
#
# Author:
#
# ToDo:
#   Microsoft-Windows-VHDMP-Operational (12)
#   Microsoft-Windows-TaskScheduler%4Operational.evtx (106)
#   
# ---------------------------------------------------------------------------------

import argparse
import subprocess
import os
import json
import sys
import calendar
import glob
import ntpath
import datetime
import re
import shutil
import platform
from pathlib import Path
from collections import OrderedDict, defaultdict
from rich.console import Console

# Configuration
from config import default_start_date, default_end_date
from config import tmp_path, report_path
from config import sigma_rules_path, chainsaw_rules_path, reg_rip_path, chainsaw_path, bin_path
from config import string_patterns, strings_whitelist, hive_names
from config import evtx_config, rip_config
from plugins import *

# Binary processing dependencies
reg_rip_log = os.path.normpath(f'{report_path}{os.sep}auto_rip-logfile.txt')
reg_rip_timeline = os.path.normpath(f'{report_path}{os.sep}timeline_events.txt')

# Set binaries based on OS
reg_rip_exe = ''
evtx_dump_exe = ''
chainsaw_exe = ''
# (Windows)
if re.match(r'^Windows.*', platform.platform(), re.I):
    reg_rip_exe = f'{reg_rip_path}{os.sep}rip.exe'
    evtx_dump_exe = f'{bin_path}{os.sep}evtx_dump.exe'
    chainsaw_exe = f'{chainsaw_path}{os.sep}chainsaw.exe'
# (MacOS) xattr -d com.apple.quarantine <file>
'''
To use Regripper on MacOS see https://elevated-designes-ai.medium.com/regripper-configuration-on-macos-8a5a8b5f6697
1. perl -MCPAN -e shell
2. install Parse::Win32Registry
3. export PERL5LIB=/Users/<USERID>/perl5/lib/perl5/
4. edit rip.pl lines
    #1 from "#! c:\perl\bin\perl.exe" to "#!/usr/bin/perl -w"
    #71 (uncomment) my $plugindir = $str."plugins/";
'''
if re.match(r'^macOS.*', platform.platform(), re.I):
    reg_rip_exe = f'{reg_rip_path}{os.sep}rip.pl'
    evtx_dump_exe = f'{bin_path}{os.sep}evtx_dump'
    chainsaw_exe = f'{chainsaw_path}{os.sep}chainsaw'

# Logging
debug = False
verbose = None
console = Console()

# Global path for artifacts
artifact_path = None



# Legacy code for using LogParser
#def start_service(service_name):
    # The Windows Event Log Service may stop and cause issues with accessing event logs 
    #service_status = win32serviceutil.QueryServiceStatus(service_name)
    # QueryServiceStatus returns a structure https://docs.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status?redirected=MSDN
    #if service_status[1] != 4:
        #win32serviceutil.StartService(service_name)
        # In case the service does not start immediately
        #time.sleep(3)
        
def get_artifacts(artifact_path):
    # List to hold support artifacts for processing
    hives = []
    event_logs = []

    # Get supported registry hives as defined in the configuration
    for hive in hive_names:
        for name in glob.glob(f'{artifact_path}/**/*{hive}', recursive=True):
            hives.append(name)    
    if debug:
        console.print(f'[purple][*][white] Registry hives: {hives}')
        
    # Get event logs
    event_logs = []
    for name in glob.glob(f'{artifact_path}/**/*.evtx', recursive=True):
        event_logs.append(name)
    if debug:
        console.print(f'[purple][*][white] Event logs: {event_logs}')

    return hives, event_logs


#
# Registry Processing
#   
def parse_registry(hives, timeline):
    # If artifacts have already been processed, skip processing
    if not os.path.isfile(f'{report_path}{os.sep}12_malware_evidence_information.txt'):
        console.print('\n[bold white]Processing registry artifacts:\n' + '-' * 30)

        categories = rip_config['categories']
        for i in categories:
            log_header = '[-] Processing the {} category'.format(i['category'])
            report_header = i['report_header']
            report_file = i['report']
            reg_log_header('\n' + log_header)
            reg_report_header(report_file, report_header)
            print(log_header)
            reg_rip(hives, i['plugins'], report_file, timeline)
    else:
        console.print('\n[yellow][*][white] Registry artifacts have already been processed. Please delete reports in \\reports directory to re-run')
        
    # Run timeline processing if desired
    if timeline:
        # If timeline has already been generated, skip processing
        if not os.path.isfile(reg_rip_timeline):
            # Run timeline plugins against all supported hives
            for hive in hives:
                # rip -r <hive_file> -aT >> <report_path> 2>> <log_path>
                console.print(f'[yellow][+][white] Generating a timeline against {hive}')
                cmd = f'{reg_rip_exe} -r "{hive}" -aT >> "{reg_rip_timeline}" 2>> "{reg_rip_log}"'
                if debug:
                    console.print(f'[purple][*][white] Command: {cmd}')
                subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, start_new_session=True, cwd=reg_rip_path).communicate()
        else:
            console.print('\n[yellow][*][white] Registry timelining already complete. Please delete timeline_events report in \\Documents directory to re-run\n' + '-' * 30)
    

def reg_report_header(report_file, header):
    outputfile = open(f'{report_path}{os.sep}{report_file}', mode='a')
    outputfile.write('=========================================================================================================\n')
    outputfile.write(header + '\n')
    outputfile.write('=========================================================================================================\n')
    outputfile.close()

def reg_log_header(input):
    outputfile = open(reg_rip_log, mode='a')
    outputfile.write(input + '\n')
    outputfile.close()

def reg_rip(hives, plugins, report_file, timeline):   
    # Process categories by hive and plugins specified in configuration 
    for hive, plugin_name in plugins.items():
        for hive_file in hives:
            if (ntpath.basename(hive_file)).lower() == hive.lower():
                for plugin in plugin_name:
                    # rip -r <hive_file> -p <plugin> >> <report_path> 2>> <log_path>
                    cmd = f'{reg_rip_exe} -r "{hive_file}" -p {plugin} >> "{report_path}{os.sep}{report_file}" 2>> "{reg_rip_log}"'
                    if debug:
                        console.print(f'[purple][*][white] Command: {cmd}')
                    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, start_new_session=True, cwd=reg_rip_path).communicate()


  
#
# Event Log Processing
#   
def dump_event_logs(event_logs):
    r = []
    # Iterate through a list of .evtx files identified within the artifacts directory
    for evtx_log in event_logs:
        evtx_log_name = os.path.basename(evtx_log)
        # If the .evtx file is defined within the script configuration, dump it to JSON
        if evtx_log_name in evtx_config['Sources'].keys():
            evtx_log_no_extension = evtx_log_name.split('.')[0]
            evtx_output_json_path = os.path.normpath(f'{tmp_path}{os.sep}{datetime.datetime.now().strftime("%Y%m%d%H%M%S")}_{evtx_log_no_extension}')
            # evtx_dump -f <output_file> -o json <input_file> will dump contents of evtx records as JSON to a given file
            cmd = f'{evtx_dump_exe} -f {evtx_output_json_path} -t 1 -o json "{evtx_log}"'
            if debug:
                console.print(f'[purple][*][white] Command: {cmd}')
            so = os.popen(cmd).read()
            r.append(evtx_output_json_path)
        else:
            if verbose:
                console.print(f'[red][!][white] Unsupported Event Log: {evtx_log_name}')            
        
    return r
        
def parse_event_logs(dumped_event_logs, start_date, end_date): 
    # Datetime filtering variables based on target timerange 
    start_datetime = datetime.datetime.strptime(start_date, '%Y-%m-%d')
    end_datetime = datetime.datetime.strptime(end_date, '%Y-%m-%d')  

    # Iterate through JSON dumps of event log files
    for log in dumped_event_logs:       
        # Read in dumped event log content
        if verbose:
            console.print(f'\n[yellow][*][white] Processing EVTX Log Dump: {log}')
        with open(log, mode='r', errors='replace') as evtx_in:
            content = evtx_in.read()
        
        # Create a list of dict events by splitting the dumped content on delimiter of "Record {#}" and skip the first entry (empty)
        event_list = re.split(r'Record\s[0-9]+', content, maxsplit=0, flags=re.MULTILINE)[1:]
        # Remove empty list entries 
        #event_list = [i for i in json_list if i]

        # Determine which plugins to run based on the EVTX file name
        evtx_plugins = None
        event_log_name = f'{log.split("_")[-1]}.evtx'  
        evtx_plugins = evtx_config['Sources'][event_log_name]['plugins']
        
        # Filter gathered event log events
        filtered_event_list = []
        
        for evt in event_list:
            # Dictionary to hold filtered event record per event
            evt_dict = OrderedDict()
            evt_json = json.loads(evt)
            
            # Common keys that should exist in all EVTX files
            if evt_json['Event'].get('EventData'):
                event_data = evt_json['Event']['EventData']
            else:
                event_data = ''
            # Sometimes events have a "UserData" node
            if evt_json['Event'].get('UserData'):
                user_data = evt_json['Event']['UserData']
            else:
                user_data = ''
            system_data = evt_json['Event']['System']
            provider = system_data['Provider']['#attributes']['Name']
            # Sometimes EventID contains sub-keys
            event_id = system_data['EventID']
            if isinstance(event_id, dict):
                event_id = event_id['#text']
            event_id = str(event_id)
            # Time filtering is based on day; adjust the TimeCreated string " %Y-%m-%dT%H:%M:%S.%fZ" to match
            system_time_string = system_data['TimeCreated']['#attributes']['SystemTime']
            system_time_day_string = system_time_string.split('T')[0]
            system_time_datetime = datetime.datetime.strptime(system_time_day_string, '%Y-%m-%d')

            # Time filtering
            if not (system_time_datetime >= start_datetime and system_time_datetime <= end_datetime):
                continue

            evt_dict['TimeCreated'] = system_time_string
            evt_dict['EventID'] = event_id
            evt_dict['Provider'] = provider
            # Get event fields; some logs may have null event data
            if isinstance(event_data, dict):
                for k, v in event_data.items():
                    evt_dict[k] = v
            if user_data:
                evt_dict['UserData'] = user_data
                   
            filtered_event_list.append(evt_dict)
                            
       
        # Run plugins
        if evtx_plugins:
            for plugin in evtx_plugins:
                # Run each plugin defined in __init__.py by accessing the global handler
                globals()[plugin].handler(filtered_event_list)


def hunt_event_logs(artifact_path):
    console.print('\n[cyan][+][white] Hunting event logs with Chainsaw')
    # -q flag suppresses output
    cmd = f'{chainsaw_exe} hunt "{artifact_path}" -s {sigma_rules_path} --mapping {chainsaw_path}{os.sep}mappings{os.sep}sigma-event-logs-all.yml -r {chainsaw_rules_path} --skip-errors --csv --full --metadata --output {report_path}'
    if debug:
        console.print(f'[purple][*][white] Command: {cmd}')
    so = os.popen(cmd).read()

    

# 
# String Searching 
#  
def search_event_logs(artifact_path, search):
    console.print('\n[cyan][+][white] Searching event logs with Chainsaw')
    cmd = f'{chainsaw_exe} search -e "{search}" "{artifact_path}" --skip-errors --extension "evtx" -o {report_path}{os.sep}evtx_chainsaw_search.txt'
    if debug:
        console.print(f'[purple][*][white] Command: {cmd}')
    so = os.popen(cmd).read()
    
def search_registry_strings(start_date, end_date, search):
    # Perform stock string searches
    for i in string_patterns:
        for k, v in i.items():
            console.print('\n[cyan][+][white] Searching for {}'.format(k))
            parse_registry_reports(v, strings_whitelist, 'cyan')

    # Build date query for string searching registry artifacts
    date_query = build_regex_date_query(start_date, end_date)
    console.print('\n[cyan][+][white] Searching registry artifacts for target date range')
    parse_registry_reports(date_query, strings_whitelist, 'green')

    # Determine if custom searching was requested
    if search:
        console.print('\n[cyan][+][white] Searching registry artifacts for custom strings')
        parse_registry_reports(search, strings_whitelist, 'blue')

def parse_registry_reports(regex_query, whitelist, source_color):
    # Gather registry report files for parsing
    registry_reports = []
    # Recursive mode for glob.glob to account for multiple user profile report parsing
    # for name in glob.glob(report_path+'\\**\\*.txt', recursive=True):
    for name in glob.glob(f'{report_path}{os.sep}*_information.txt'):
        registry_reports.append(name)
        
    results_found = False
    
    # Regex patterns for line matching
    more_context_needed = r'^([a-zA-Z]{3}\s[a-zA-Z]{3}\s{1,2}\d{1,2}\s\d{2}\:\d{2}\:\d{2}\s\d{4}(Z|\sZ|\s\(UTC\))?$)|(LastWrite.*)'

    # Build a list of lines found within the registry reports
    for report in registry_reports:
        if 'logfile' not in report:
            with open(report, 'r', errors='replace') as r:
                content = r.readlines()

            # Current report being parsed
            source = ntpath.basename(report)
            matches = []

            for index, item in enumerate(content[:-1]):
                # Get next item in case it is needed for more detail on a match
                next_item = content[index + 1]

                # Determine if query string is contained within line item
                if re.search(regex_query, item, re.I):
                    if not any(re.findall(regex, item, re.I) for regex in whitelist):
                        # Cleanup shellbag output
                        item = re.sub(r'\|\s+', '', item)

                        # If detection contained no useful data (date only, "LastWrite", etc.), look at the surrounding items which usually contain related detail
                        if re.match(more_context_needed, item.strip(), re.I) and not next_item.strip() == '':
                            # Append current item to match list if next item is not whitelisted
                            if not any(re.findall(regex, next_item, re.I) for regex in whitelist):
                                matches.append(item.strip())
                                # If next item contains known keywords, get the previous item for further related detail, otherwise use the next item
                                if any(re.findall(regex, next_item, re.I) for regex in [r'(MRUListEx|AutoConfigProxy|Version|CacheLimit|AllowWindowReuse|ConfiguredScopes|Signature|value not found)']):
                                    prev_item = content[index - 1]
                                    matches.append('  > ' + prev_item.strip())
                                else:
                                    matches.append('  > ' + next_item.strip())
                                    
                        # Amcache logs require the prior, prior line item
                        elif re.match('^Last Mod Time2.*', item.strip(), re.I):
                            prev_prev_item = content[index - 2]
                            if not any(re.findall(regex, prev_prev_item, re.I) for regex in whitelist):
                                matches.append(item.strip())
                                matches.append('  > ' + prev_prev_item.strip())
                        # Append match if no other criteria was met
                        else:
                            matches.append(item.strip())

            # Print matches and source if any found
            if matches:
                results_found = True
                console.print(f'[{source_color}]{source}')
                for match in matches:
                    print(match)
    
    if not results_found:
        console.print(' No matching events found', style="red")   

def build_regex_date_query(start_date, end_date):
    # Create start date and end date objects for calculating diff
    start_date_object = datetime.datetime.strptime(start_date, '%Y-%m-%d')
    end_date_object = datetime.datetime.strptime(end_date, '%Y-%m-%d')

    # Calculate time range (number of days between start and end date)
    diff = end_date_object - start_date_object
    # print('Difference in days: '+str(diff.days))

    # Create list of numerical date strings for searching shellbags  YYYY-MM-DD (Ex: 2018-07-05)
    target_date_list = []
    for day in range(diff.days + 1):
        target_date = (start_date_object + datetime.timedelta(day)).strftime('%Y-%m-%d').split('.')[0]
        target_date_list.append(target_date)

    # Create list of alphabetic date strings for searching other logs  MMM DD  (Ex: Jul 05)
    target_cal_list = []
    for d in target_date_list:
        month_no = d.split('-')[1]
        month_abbr = calendar.month_abbr[int(month_no)]
        day_no = d.split('-')[2]
        # Logs use a space for days that start with zero -- 05 become " 5"
        if day_no.startswith('0'):
            day_no = day_no.replace('0', ' ')
        # Must add space to day -- "Jun 20" is not the same as "Jun 2017"
        target_cal_list.append(month_abbr + ' ' + day_no + ' ')

    search_list = target_date_list + target_cal_list
    # Build regex search
    regex_query = '(' + '|'.join(search_list) + ')'

    return regex_query


# ---------------------------------------------------------------------------------
# Main Program
#    
def main():
    # Command line parsing
    # TODO: arg for dumping to CSV, arg for searching EVTX fields using regex
    parser = argparse.ArgumentParser(description='Artifact Triage', epilog='Example: ')
    parser.add_argument('-d', '--directory', required=True, help='The path to a directory containing artifacts to parse')
    parser.add_argument('-s', '--start', default=default_start_date, help='Start date YYYY-MM-DD, default is 7 days ago')
    parser.add_argument('-e', '--end', default=default_end_date, help='End date YYYY-MM-DD format only, default is current date')
    parser.add_argument('-f', '--find', help='artifact searching, for multiple strings use a pipe-seperated regular expression ex:mimikatz|powershell')
    parser.add_argument('-t', '--timeline', action='store_true', help='run RegRipper hive-specfic TLN plugins (will increase processing time), default is FALSE, specify argument to change to TRUE')
    parser.add_argument('-v', '--verbose', action='store_true', help='display printout of commands used in script, default is FALSE, specify argument to change to TRUE')   
    parser.add_argument('--debug', action='store_true', help='printout additional information for troubleshooting, default is FALSE, specify argument to change to TRUE')        
    args = parser.parse_args()

    # Set global variables for additional printout
    global verbose
    global debug
    verbose = args.verbose
    debug = args.debug

    # Set variable for RegRipper timeline processing
    timeline = args.timeline
        
    # Ensure executables exist
    executables = [reg_rip_exe, evtx_dump_exe, chainsaw_exe]
    for dependency in executables:
        if not os.path.isfile(dependency):
            console.print(f'[!] ERROR: {dependency} not found', style='bold red')
            sys.exit()
            
    # Define processing paths
    artifact_path = os.path.normpath(Path(args.directory).resolve()) 
    if debug:
        console.print(f'[purple][*][white] Artifact path: {artifact_path}')
    if not os.path.exists(args.directory):
        parser.error('[!] ERROR: The provided path %s does not exist! Please ensure the full path is being provided!' % args.directory)
        sys.exit()

    # Ensure the report directory exists
    if not os.path.exists(report_path):
        os.mkdir(report_path)            
            
    # Validate date format (if provided)
    if not re.match('\d{4}\-\d{2}\-\d{2}', args.start):
        parser.error('[!] ERROR: Please provide the start date in the format YYYY-MM-DD')
        sys.exit()
    if not re.match('\d{4}\-\d{2}\-\d{2}', args.end):
        parser.error('[!] ERROR: Please provide the end date in the format YYYY-MM-DD')
        sys.exit()      
    start_date_string = args.start
    end_date_string = args.end
    
    # Set custom search pattern (if provided)
    if args.find:
        search = args.find
    else:
        search = ''
    
    # Get supported artifacts for triage
    registry_hives, event_logs = get_artifacts(artifact_path)
    console.print('=' * 57, style='black on white')
    console.print(f'{parser.prog} Target Dates: {start_date_string} to {end_date_string}', style='black on white')
    console.print('=' * 57, style='black on white')
    # Registry Processing
    console.print('\nREGISTRY PARSING', style='bold yellow')
    if registry_hives:
        parse_registry(registry_hives, timeline)
        console.print('\nREGISTRY REPORT STRING SEARCHING', style='bold yellow')
        search_registry_strings(start_date_string, end_date_string, search)
    else:
        console.print('[red][!][white] No registry artifacts found')
    # Event log Processing
    console.print('\nEVENT LOG PARSING', style='bold yellow')
    if event_logs:
        event_log_dumps = dump_event_logs(event_logs)
        parse_event_logs(event_log_dumps, start_date_string, end_date_string)
        console.print('\nEVENT LOG HUNTING', style='bold yellow')
        hunt_event_logs(artifact_path)
        if search:
            console.print('\nEVENT LOG SEARCHING', style='bold yellow')
            search_event_logs(artifact_path, search)
    else:
        console.print('[red][!][white] No event log artifacts found') 
        
    # Cleanup
    if os.path.exists(tmp_path):
        shutil.rmtree(tmp_path)

    
          
if __name__ == "__main__":
    main()