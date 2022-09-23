# Artifact Triage
Assists in triaging forensic artifacts (registry, event logs) gathered from a system.

## Description
This project processes various forensic artifacts collected from a target system including Windows Event Logs and Registry Hives using a combination of native Python and some popular forensic toolsets (included in the /bin folder). Time filtering capability is included to target specific dates for artifact processing. Various reports are output to the /reports directory and summary output is produced via CLI.

For Windows Event Log processing:
* Supported EVTX files (as defined in config.py) are dumped to JSON using Rust-based evtx_dump and processed with various Python plugins
* Chainsaw is used to perform hunting (based on included SIGMA and Chainsaw rulesets) 
* Chainsaw is used to search all EVTX logs against a regular expression pattern (if provided)

For Registry Hive processing:
* RegRipper is utilized to run various pre-defined plugins (config.py) against collected hives and group results into various category reports (os, users, software, malware, etc.)
* Optionally, RegRipper is used to produce a timeline output for supported hives and plugins
* Registry reports are searched against the target date range as well as by custom regular expression (if provided).

## Getting Started
### Dependencies
* Windows, MacOS
* rich (Python)

### Installing
* Ensure the binary dependencies are available in the /bin directory (unzip bin.zip from this repo)
```
pip install -r requirements.txt
```

### Executing program
```
python artifact_triage.py -d <artifact_directory>
```

## Help
```
python artifact_triage.py -h
```

### Building Windows Event Log Plugins
To add new plugins for processing Windows Event Logs, do the following:
* Create a new plugin using the _template.py file within the /plugins directory
* Ensure the targeted Event Log exists within the evtx_config['Sources'] key defined in config.py and the plugin name is added to the list of plugins
```
evtx_config = { 'Sources': {
                    'Security.evtx' : {
                        'plugins': ['plugin_logons', 'plugin_logon_logoff', 'plugin_failed_logons', 'plugin_user_mgmt', 'plugin_share_access']
                    },
```

### Adding additional Registry processing plugins
All Registry plugins are defined within the config.py file in the rip_config dictionary and grouped by category. These plugins are pulled from the RegRipper3.0 repository and exist with the appropriate sub-folder in /bin. To add additional plugins per registry processing category, simply add the plugin name to the appropriate list.
```
rip_config = {'categories': [
                {'category': 'os',
                 'report': '01_operating_system_information.txt',
                 'report_header': 'General Information about the Operating System and its Configuration',
                 'plugins': {
                     'NTUSER.dat': ['compdesc', 'nation', 'osversion'],
```

## Authors
[jdubp](https://twitter.com/j_dubp)

## Version History
* 0.1
    * Initial Release

## License

## Acknowledgments
* [RegRipper3](https://github.com/keydet89/RegRipper3.0)
* [Evtx](https://github.com/omerbenamram/evtx)
* [Chainsaw](https://github.com/WithSecureLabs/chainsaw)
* [SIGMA Rules](https://github.com/SigmaHQ/sigma/tree/master/rules)