@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cd /d "%~dp0"
cl /nologo /EHsc /Od /W4 main.cpp /Fe:password_demo.exe /link user32.lib /SUBSYSTEM:CONSOLE
exit /b %errorlevel%
