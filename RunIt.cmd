@echo off

java -jar MyDnsTool.jar

del /Q /F /S ..\unbound\unbound_ad_servers
del /Q /F /S ..\unbound\unbound_blocked_servers
del /Q /F /S ..\unbound\unbound_localforwards

copy AdServers_Processed ..\unbound\unbound_ad_servers
copy MalwareDomains_Processed ..\unbound\unbound_blocked_servers
copy LocalForwards_Processed ..\unbound\unbound_localforwards

..\unbound\unbound-checkconf.exe ..\unbound\service.conf

pause