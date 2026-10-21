@echo off
cd /d "%~dp0"
wsl.exe -d Ubuntu-24.04 -u phplab --cd /mnt/c/Users/user/Downloads/php --exec /bin/bash linux/build.sh %*
