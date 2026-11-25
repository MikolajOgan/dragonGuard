@echo off
rem Builds DragonGuard (bin\UsbGuard.exe) with the C# compiler that ships with Windows (.NET Framework 4.x)
rem Icon/logo come from assets\ (regenerate from logo.jpg with: powershell -ExecutionPolicy Bypass -File tools\make-assets.ps1)
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist bin mkdir bin
"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ /out:bin\UsbGuard.exe /win32manifest:src\app.manifest ^
  /win32icon:assets\DragonGuard.ico /resource:assets\DragonGuard.ico,DragonGuard.ico /resource:assets\logo.png,DragonGuard.logo.png ^
  /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.ServiceProcess.dll ^
  src\*.cs
if errorlevel 1 (echo BUILD FAILED & exit /b 1)
echo Built bin\UsbGuard.exe
