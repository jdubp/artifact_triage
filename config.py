#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import datetime

#[Date Variables]
default_start_date = str(datetime.date.today() + datetime.timedelta(-7))  # 7 days ago
default_end_date = str(datetime.date.today())

#[File Paths]
tmp_path = os.path.normpath(f'{os.getcwd()}/tmp/')
report_path = os.path.normpath(f'{os.getcwd()}/reports/')
sigma_rules_path = os.path.normpath(f'{os.getcwd()}/bin/sigma/')
chainsaw_rules_path = os.path.normpath(f'{os.getcwd()}/bin/chainsaw/rules/')
chainsaw_path = os.path.normpath(f'{os.getcwd()}/bin/chainsaw/')
bin_path = os.path.normpath(f'{os.getcwd()}/bin/')
reg_rip_path = os.path.normpath(f'{os.getcwd()}/bin/RegRipper3.0-master/')

#[String Patterns]
string_patterns = [
                    {'executables in %users%': r'.*\\users\\.*\.exe'}
                  ]

#[String Whitelist]
strings_whitelist = [r'\\\\(Intel|Cisco|WebEx|GoToMeeting|CCM|Software Distribution|Microsoft Policy Platform|OneDrive|Macromedia)\\',
                     r'StartMenu_Balloon_Time',
                     r'LastCrawl|UpgradeTime',
                     r'\\program files( \(x86\))?\\(common files\\)?(citrix|adobe|microsoft)'
                     ]

#[Artifacts]
hive_names = ['SOFTWARE', 'SYSTEM', 'SAM', 'SECURITY', 'NTUSER.dat', 'UsrClass.dat', 'Amcache.hve']

#[Windows Event Log Configuration]
evtx_config = { 'Sources': {
                    'Security.evtx' : {
                        'plugins': ['plugin_logons', 'plugin_logon_logoff', 'plugin_failed_logons', 'plugin_user_mgmt', 'plugin_share_access']
                    },
                    'System.evtx' : {
                        'plugins': ['plugin_system_service']
                    },
                    'Microsoft-Windows-Shell-Core%4Operational.evtx' : {
                        'plugins': ['plugin_shell_core']
                    },    
                    'Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx' : {
                        'plugins': ['plugin_rdp_conns']
                    },  
                    'Microsoft-Windows-WMI-Activity%4Operational.evtx' : {
                        'plugins': ['plugin_wmi_subscription']
                    },                     
}}  

#[RegRipper Configuration]
rip_config = {'categories': [
                {'category': 'os',
                 'report': '01_operating_system_information.txt',
                 'report_header': 'General Information about the Operating System and its Configuration',
                 'plugins': {
                     'NTUSER.dat': ['compdesc', 'nation', 'osversion'],
                     'SOFTWARE': ['allowedenum', 'dcom', 'disablesr', 'execpolicy', 'gpohist', 'remoteaccess', 'secctr',
                                  'spp_clients', 'uac', 'watp', 'winver', 'wsh_settings'],
                     'SYSTEM': ['backuprestore', 'compname', 'codepage', 'disablelastaccess', 'disableremotescm', 'pagefile',
                                'processor_architecture', 'shutdown', 'source_os', 'thispcpolicy', 'timezone']
                 }
                 },
                {'category': 'users',
                 'report': '02_user_account_information.txt',
                 'report_header': 'User Account Information',
                 'plugins': {
                     'SAM': ['samparse'],
                     'SOFTWARE': ['profilelist']
                 }
                 },
                {'category': 'software',
                 'report': '03_installed_software_information.txt',
                 'report_header': 'Installed Software Information',
                 'plugins': {
                     'NTUSER.dat': ['appassoc', 'apppaths', 'appcompatflags', 'arpcache', 'clsid', 'listsoft', 'pslogging'],
                     'SOFTWARE': ['apppaths', 'appcompatflags', 'clsid', 'defender', 'installer', 'licenses', 'msis',
                                  'powershellcore', 'pslogging', 'uninstall']
                 }
                 },
                {'category': 'network',
                 'report': '04_network_configuration_information.txt',
                 'report_header': 'Network Configuration Information',
                 'plugins': {
                     'SOFTWARE': ['macaddr', 'networkcards', 'networklist', 'ssid', 'termserv'],
                     'SYSTEM': ['ips', 'macaddr', 'networksetup2', 'nic2', 'rdpport', 'routes', 'shares', 'termcert', 'termserv', 'portproxy']
                 }
                 },
                {'category': 'storage',
                 'report': '05_storage_information.txt',
                 'report_header': 'Storage Information',
                 'plugins': {
                     'NTUSER.dat': ['mndmru'],
                     'SOFTWARE': ['btconfig', 'emdmgmt'],
                     'SYSTEM': ['bthport', 'devclass', 'imagedev', 'mountdev', 'mountdev2', 'usbdevices', 'usbstor', 'wpdbusenum']
                 }
                 },
                {'category': 'execution',
                 'report': '06_program_execution_information.txt',
                 'report_header': 'Program Execution Information',
                 'plugins': {
                     'Amcache.hve': ['amcache'],
                     'NTUSER.dat': ['cached', 'featureusage', 'jumplistdata', 'muicache', 'recentapps', 'userassist', 'winscp'],
                     'SOFTWARE': ['at', 'direct', 'heap', 'srum', 'tasks', 'taskcache', 'tracing', 'exefile'],
                     'SYSTEM': ['appcompatcache', 'bam', 'prefetch', 'shimcache'],
                     'UsrClass.dat': ['muicache', 'exefile']
                 }
                 },
                {'category': 'autoruns',
                 'report': '07_autoruns_information.txt',
                 'report_header': 'Autostart Locations Information',
                 'plugins': {
                     'NTUSER.dat': ['appkeys', 'appx', 'cmdproc', 'environment', 'load', 'pendinggpos', 'profiler', 'run',
                                    'runvirtual'],
                     'SOFTWARE': ['appinitdlls', 'appkeys', 'calibrator', 'cmd_shell', 'drivers32', 'imagefile', 'killsuit',
                                  'netsh', 'printdemon', 'run', 'runonceex', 'runvirtual', 'schedagent', 'silentprocessexit', 'wab',
                                  'winlogon_tln', 'wow64', 'wrdata'],
                     'SYSTEM': ['appcertdlls', 'environment', 'lsa', 'printmon', 'profiler', 'securityproviders', 'services', 'svc',
                                'svcdll'],
                     'UsrClass.dat': ['appx']
                 }
                 },
                {'category': 'log',
                 'report': '08_log_information.txt',
                 'report_header': 'Logging Information',
                 'plugins': {
                     'SECURITY': ['auditpol'],
                     'SYSTEM': ['crashcontrol', 'netlogon']
                 }
                 },
                {'category': 'web',
                 'report': '09_web-browsing_information.txt',
                 'report_header': 'Web Browsing Information',
                 'plugins': {
                     'NTUSER.dat': ['oisc', 'typedurls', 'typedurlstime']
                 }
                 },
                {'category': 'user_config',
                 'report': '10_user-configuration_information.txt',
                 'report_header': 'User Account Configuration Information',
                 'plugins': {
                     'NTUSER.dat': ['allowedenum', 'attachmgr', 'appspecific', 'comdlg32', 'gpohist', 'logonstats', 'lxss',
                                    'shellfolders', 'sysinternals', 'tsclient']
                 }
                 },
                {'category': 'user_activity',
                 'report': '11_user-account_activity_information.txt',
                 'report_header': 'User Account Activity',
                 'plugins': {
                     'NTUSER.dat': ['adoberdr', 'applets', 'lastloggedon', 'link_click', 'mmc', 'mndmru', 'mpmru', 'msoffice',
                                    'onedrive', 'putty', 'typedpaths', 'recentdocs', 'runmru', 'sevenzip', 'winrar', 'winzip',
                                    'wordwheelquery'],
                     'UsrClass.dat': ['photos', 'shellbags']
                 }
                 },
                {'category': 'malware',
                 'report': '12_malware_evidence_information.txt',
                 'report_header': 'Possible Malware Evidence',
                 'plugins': {
                     'Amcache.hve': ['fileless', 'null', 'findexes'],
                     'NTUSER.dat': ['fileless', 'injectdll64', 'inprocserver', 'mixer', 'mmo', 'null', 'rlo', 'findexes'],
                     'SAM': ['fileless', 'null', 'rlo', 'findexes'],
                     'SECURITY': ['fileless', 'null', 'rlo', 'findexes'],
                     'SOFTWARE': ['fileless', 'injectdll64', 'inprocserver', 'shelloverlay', 'null', 'rlo', 'wbem', 'findexes'],
                     'SYSTEM': ['cred', 'fileless', 'null', 'rlo', 'findexes'],
                     'UsrClass.dat': ['fileless', 'inprocserver', 'null', 'rlo', 'findexes']
                 }
                 },
]}