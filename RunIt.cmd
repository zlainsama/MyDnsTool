@echo off

java -jar MyDnsTool.jar

del /Q /F /S ..\unbound\unbound_ad_servers
del /Q /F /S ..\unbound\unbound_blocked_servers
del /Q /F /S ..\unbound\unbound_localforwards

cp AdServers_Processed ..\unbound\unbound_ad_servers
cp MalwareDomains_Processed ..\unbound\unbound_blocked_servers
cp LocalForwards_Processed ..\unbound\unbound_localforwards

..\unbound\unbound-checkconf.exe ..\unbound\service.conf

pause