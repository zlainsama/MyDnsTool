@echo off

java -jar MyDnsTool.jar

if %ERRORLEVEL%==0 (
  del /Q /F /S ..\unbound\unbound_ad_servers
  del /Q /F /S ..\unbound\unbound_localforwards

  copy AdServers_Processed ..\unbound\unbound_ad_servers
  copy LocalForwards_Processed ..\unbound\unbound_localforwards

  ..\unbound\unbound-checkconf.exe ..\unbound\service.conf
)

pause