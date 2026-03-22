@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File ".\EnigmaDrive.ps1" -Gui
endlocal
