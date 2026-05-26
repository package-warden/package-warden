@echo off
setlocal

:: ---------------------------------------------------------------------------
:: Package Warden -- run script
::
:: Usage:
::   package-warden.bat
::
:: Environment variables (all optional):
::   PW_PORT        Listening port       (default: 5050)
::   PW_DATA_DIR    Root data directory  (default: %APPDATA%\PackageWarden)
::   PW_LOG_LEVEL   ASP.NET log level    (default: Information)
::
:: Examples:
::   set PW_PORT=8080 && package-warden.bat
::   set PW_DATA_DIR=C:\data\package-warden && package-warden.bat
:: ---------------------------------------------------------------------------

if not defined PW_PORT     set "PW_PORT=5050"
if not defined PW_LOG_LEVEL set "PW_LOG_LEVEL=Information"

:: Export PW_DATA_DIR so the app can read it; default is applied by the app itself.
:: Uncomment and edit the line below to override the default (%APPDATA%\PackageWarden):
:: set "PW_DATA_DIR=C:\data\package-warden"

set "SCRIPT_DIR=%~dp0"

echo Package Warden -- http://localhost:%PW_PORT%/ui

set "ASPNETCORE_URLS=http://+:%PW_PORT%"
set "Logging__LogLevel__Default=%PW_LOG_LEVEL%"
set "PackageWarden__BaseUrl=http://localhost:%PW_PORT%"

"%SCRIPT_DIR%package-warden.exe"
