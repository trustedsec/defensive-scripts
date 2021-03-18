# HAFNIUM

The following scripts and queries are for aiding in the triaging of logs looking for possible HAFNIUM attacks againgst 
Exchange servers where CVE-2021-26855, CVE-2021-26857, CVE-2021-26858 and CVE-2021-27065 are being exploited by several
groups.

# LogParser

The following queries are for use with Microsoft LogParser 2.2. A UI like LogParser Studio or Log Parser Lizard is recomended. 

| File          | Description  |     
| :-------------: |------------|
| hafniun_exploit_attempt.sql | Query for W3SVC1 log files for exploitation attemps where a .js file is created as part of the exploit.|
| hafniun_malicious_action_example.sql | Example query for W3SVC1 log that checks for exploit attempt, known bad IPs and common WebShells.|
| known_webshell_success.sql | Query for W3SVC1 log files for WebShells seen used and scanned for as part of the mass exploitation of the vulnerability|
| ordered_by_requests.sql | Query for W3SVC1 log files to get a list of URIs and the numbers of requests for each, aids in looking for not frequently used URI that may help in finding webshells.|
| search_by_ip.sql | Query for W3SVC1 log files for known bad IP Addresses.|
| suspicious_useragents.sql |Query for W3SVC1 log files to find common user-agents used by automated scripts|
| unique_useragents.sql | Query for W3SVC1 log files to get a list of user-agents and the number of times used.|

# PowerShell Scripts

The following PowerhShell 7 scripts leverage Get-WinEvent with the EventData filtering capability.

| File            | Description |
| :-------------: |-------------|
| Get-EventW3WPChild.ps1 | Script takes advantage of the Get-WinEvent cmdlet capability in PS Core to filter for event fields to look for child processes of w3wp.exe. |
 