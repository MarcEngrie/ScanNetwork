@echo off
cls
ipconfig /flushdns
python %~dpn0.py %1 %2 %3 %4 %5 %6 %7 %8 %9
pause