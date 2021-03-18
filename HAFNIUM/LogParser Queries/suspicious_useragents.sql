/*
Author carlos.perez<at>trustedsec.com

Description: LogParser 2.2 query to look URIs accessed by scripted methods.

Version: 1.0
*/

SELECT date,time,cs-uri-stem,cs-uri-query,c-ip,cs-method,sc-status,cs(user-agent),Logfilename 
FROM '<path to logs>\W3SVC1\*.log' 
WHERE (cs(user-agent) LIKE '%python%' OR 
	cs(user-agent) LIKE '%Go%' OR
	cs(user-agent) LIKE '%perl%' OR 
	cs(user-agent) LIKE '%curl%' OR 
	cs(user-agent) LIKE '%java%' OR 
	cs(user-agent) ='')