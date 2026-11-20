@echo off
setlocal
set "base=%~dp0"
set "keepassExe=%ProgramFiles(x86)%\KeePass Password Safe 2\KeePass.exe"

where nuget >nul 2>nul
if errorlevel 1 (
  echo NuGet CLI is required and must be on PATH.
  exit /b 1
)
where msbuild >nul 2>nul
if errorlevel 1 (
  echo MSBuild is required and must be on PATH.
  exit /b 1
)
if not exist "%keepassExe%" (
  echo Install the official KeePass application at "%keepassExe%".
  exit /b 1
)

nuget restore "%base%HaveIBeenPwned.sln"
if errorlevel 1 exit /b 1
msbuild "%base%HaveIBeenPwned.sln" /target:Clean /m
if errorlevel 1 exit /b 1
msbuild "%base%HaveIBeenPwned.sln" /p:Configuration=Release /m
if errorlevel 1 exit /b 1

if not exist "%base%mono" mkdir "%base%mono"
copy /y "%base%HaveIBeenPwned\bin\Release\HaveIBeenPwned.dll" "%base%mono\" >nul
if errorlevel 1 exit /b 1
copy /y "%base%HaveIBeenPwned\bin\Release\Newtonsoft.Json.dll" "%base%mono\" >nul
if errorlevel 1 exit /b 1

msbuild "%base%HaveIBeenPwned.sln" /target:Clean /m
if errorlevel 1 exit /b 1

if exist "%base%HaveIBeenPwned.plgx" del /q "%base%HaveIBeenPwned.plgx"
"%keepassExe%" --plgx-create "%base%HaveIBeenPwned" --plgx-prereq-kp:2.34 --plgx-prereq-net:4.5.2
if errorlevel 1 exit /b 1
if not exist "%base%HaveIBeenPwned.plgx" (
  echo KeePass did not create HaveIBeenPwned.plgx.
  exit /b 1
)

echo Build complete. PLGX: HaveIBeenPwned.plgx; DLLs: mono\
endlocal