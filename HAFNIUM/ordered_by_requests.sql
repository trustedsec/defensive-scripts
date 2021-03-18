/*
Author carlos.perez<at>trustedsec.com

Description: LogParser 2.2 query to group URIs by hitcount, good for looking for low numbered URIs that might be webshells.
 
Version: 1.0
*/

SELECT cs-uri-stem AS URI, COUNT(*) AS Requests 
FROM '<path to logs>\W3SVC1\*.log'
WHERE sc-status = 200
GROUP BY cs-uri-stem ORDER BY Requests