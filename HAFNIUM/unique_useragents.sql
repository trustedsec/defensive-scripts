/*
Author carlos.perez<at>trustedsec.com

Description: LogParser 2.2 query to get a count of used User Agents.

Version: 1.0
*/

SELECT cs(user-agent) AS UserAgent, COUNT(*) AS Requests 
FROM '<Path to Logs>\W3SVC1\*.log'
WHERE sc-status = 200
GROUP BY cs(user-agent) ORDER BY Requests
