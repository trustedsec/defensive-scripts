/*
Author carlos.perez<at>trustedsec.com

Description: LogParser 2.2 query to look for IPs that where initially trying to exploit the HAFNIUM vulnerabilities.
             We recomment to replace the list and some host may have changed.

Version: 1.0
*/

SELECT date,time,cs-uri-stem,cs-uri-query,c-ip,cs-method,sc-status,cs(user-agent),Logfilename 
FROM '<path to logs>\W3SVC1\*.log'
WHERE 
-- Checking IPs seen scanning for Webshells and Exploiting hosts
(c-ip IN ('86.105.18.116';
	'89.34.111.11';'182.18.152.105';'103.77.192.219';
	'104.140.114.110';'104.248.49.97';'104.250.191.110';
	'108.61.246.56';'149.28.14.163'; '157.230.221.198';
	'161.35.1.207';'161.35.1.225';'165.232.154.116';
	'167.99.168.251';'167.99.239.29';'185.250.151.72';
	'192.81.208.169';'203.160.69.66';'211.56.98.146';
	'5.2.69.14';'5.254.43.18';'80.92.205.81';
	'91.192.103.43';'13.231.174.2';'161.35.45.41';
	'194.87.69.35';'45.76.110.29'; '45.77.252.175';
	'165.227.196.109';'142.93.182.54';'167.179.82.76';
	'172.104.251.234';'185.65.134.170';'20.73.224.195';
	'31.7.61.190';'45.32.251.60';
	'82.221.139.240';'86.105.18.116';'46.101.232.43')) OR