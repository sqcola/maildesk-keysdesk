@echo off
setlocal
title KeyDesk

rem Keep this file pure ASCII. cmd.exe reads .bat in the OEM code page (936/GBK
rem on zh-CN Windows), so UTF-8 Chinese would be decoded as garbage and every
rem garbled word would be run as a command.

chcp 65001 >nul
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 goto NONODE

node server.js
goto END

:NONODE
echo.
echo   [ERROR] Node.js not found.
echo.
echo   Please install Node.js 18 or newer:  https://nodejs.org/
echo   After installing, run this file again.
echo.

:END
pause
endlocal
