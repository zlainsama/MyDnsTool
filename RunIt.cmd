@echo off

java -jar MyDnsTool.jar

if %ERRORLEVEL%==0 (
  del /Q /F /S ..\unbound\unbound_blackhole
  del /Q /F /S ..\unbound\unbound_localforwards

  copy StevenBlack_Processed ..\unbound\unbound_blackhole
  copy LocalForwards_Processed ..\unbound\unbound_localforwards

  ..\unbound\unbound-checkconf.exe ..\unbound\service.conf
)

pause