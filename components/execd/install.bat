REM Copyright 2026 Alibaba Group Holding Ltd.
REM
REM Licensed under the Apache License, Version 2.0 (the "License");
REM you may not use this file except in compliance with the License.
REM You may obtain a copy of the License at
REM
REM     http://www.apache.org/licenses/LICENSE-2.0
REM
REM Unless required by applicable law or agreed to in writing, software
REM distributed under the License is distributed on an "AS IS" BASIS,
REM WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
REM See the License for the specific language governing permissions and
REM limitations under the License.

@echo off
setlocal enableextensions

REM install.bat for dockur/windows OEM hook.
REM It downloads execd.exe into a Windows host and starts it.

set "EXECD_INSTALL_DIR=%EXECD_INSTALL_DIR%"
if "%EXECD_INSTALL_DIR%"=="" set "EXECD_INSTALL_DIR=C:\OpenSandbox"

set "EXECD_BIN=%EXECD_BIN%"
if "%EXECD_BIN%"=="" set "EXECD_BIN=%EXECD_INSTALL_DIR%\execd.exe"

set "EXECD_DOWNLOAD_URL=%EXECD_DOWNLOAD_URL%"
if "%EXECD_DOWNLOAD_URL%"=="" if not "%~1"=="" set "EXECD_DOWNLOAD_URL=%~1"
if "%EXECD_DOWNLOAD_URL%"=="" set "EXECD_DOWNLOAD_URL=https://github.com/alibaba/OpenSandbox/releases/download/docker%%2Fexecd%%2Fv1.0.11/execd_v1.0.11_windows_amd64.exe"

if not exist "%EXECD_INSTALL_DIR%" mkdir "%EXECD_INSTALL_DIR%"
if errorlevel 1 (
    echo [install.bat] ERROR: failed to create install dir: %EXECD_INSTALL_DIR%
    exit /b 1
)

echo [install.bat] Downloading execd from:
echo [install.bat] %EXECD_DOWNLOAD_URL%
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'Stop'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%EXECD_DOWNLOAD_URL%' -OutFile '%EXECD_BIN%';"
if errorlevel 1 (
    echo [install.bat] ERROR: failed to download execd.exe
    exit /b 1
)

echo [install.bat] Starting: %EXECD_BIN%
start "opensandbox-execd" /B "%EXECD_BIN%"
if errorlevel 1 (
    echo [install.bat] ERROR: failed to start execd.exe
    exit /b 1
)

echo [install.bat] execd started in background.
exit /b 0
