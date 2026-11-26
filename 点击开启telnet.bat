@echo off
setlocal EnableExtensions
chcp 65001 >nul

set "BASE=%~dp0"
set "INFILE=%BASE%config.bin"
set "OUTFILE=%BASE%config-telnet-enable.bin"
set "SCRIPT=%BASE%telnet_enable.js"
set "NODEBIN=%BASE%node.exe"
set "NODESHIM=%BASE%node\node.exe"

if not exist "%INFILE%" goto NOINPUT
if not exist "%SCRIPT%" goto UNSUPPORTED

if exist "%NODEBIN%" goto RUNTASK
if exist "%NODESHIM%" (
    set "NODEBIN=%NODESHIM%"
    goto RUNTASK
)

where node.exe >nul 2>nul
if errorlevel 1 goto NONODE
set "NODEBIN=node.exe"

:RUNTASK
if exist "%OUTFILE%" del /q "%OUTFILE%" >nul 2>nul
"%NODEBIN%" "%SCRIPT%" "%INFILE%" "%OUTFILE%"
if errorlevel 1 goto UNSUPPORTED
if not exist "%OUTFILE%" goto UNSUPPORTED
echo.
pause >nul
exit /b 0

:NOINPUT
if exist "%NODEBIN%" "%NODEBIN%" -e "process.stdout.write('\u672a\u68c0\u6d4b\u5230 config.bin \u6587\u4ef6\u3002\n')"
if not exist "%NODEBIN%" echo config.bin not found.
echo.
pause >nul
exit /b 1

:NONODE
echo Node.js runtime not found.
echo.
pause >nul
exit /b 1

:UNSUPPORTED
if exist "%OUTFILE%" del /q "%OUTFILE%" >nul 2>nul
if exist "%NODEBIN%" "%NODEBIN%" -e "process.stdout.write('config \u6587\u4ef6\u6682\u4e0d\u9002\u914d\u3002\n')"
if not exist "%NODEBIN%" echo Unsupported config file.
echo.
pause >nul
exit /b 1
