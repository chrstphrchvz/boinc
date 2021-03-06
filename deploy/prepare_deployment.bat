rem @echo off
set bintray_deploy=False
for /f "tokens=2-4 delims=/ "  %%a in ("%date%") do (set MM=%%a& set DD=%%b& set YYYY=%%c)
set build_date=%YYYY%-%MM%-%DD%
set git_rev=%APPVEYOR_REPO_COMMIT:~0,8%

rem Default values because %bintray_deploy% is currently unused
set pkg_name=master
set git_rev=%APPVEYOR_REPO_COMMIT:~0,8%
set pkg_version=master_%build_date%_%git_rev%

if defined APPVEYOR_PULL_REQUEST_NUMBER (
    set pkg_name=pull-requests
    set git_rev=%APPVEYOR_PULL_REQUEST_HEAD_COMMIT:~0,8%
    set pkg_version=PR%APPVEYOR_PULL_REQUEST_NUMBER%_%build_date%_%git_rev%
    set bintray_deploy=True
)
if defined APPVEYOR_SCHEDULED_BUILD (
    if "%APPVEYOR_SCHEDULED_BUILD%" == "True" (
        set pkg_name=weekly
        set pkg_version=weekly_%build_date%_%git_rev%
        set bintray_deploy=True
    )
)

if not exist "deploy\win-apps" mkdir deploy\win-apps
copy "win_build\Build\x64\Debug\htmlgfx*.exe" "deploy\win-apps\"
copy "win_build\Build\x64\Debug\wrapper*.exe" "deploy\win-apps\"
copy "win_build\Build\x64\Debug\vboxwrapper*.exe" "deploy\win-apps\"
copy "win_build\Build\x64\Debug\boincsim.exe" "deploy\win-apps\"
copy "win_build\Build\x64\Debug\slide_show.exe" "deploy\win-apps\"
copy "win_build\Build\x64\Debug\example_app_multi_thread.exe" "deploy\win-apps\"
copy "win_build\Build\x64\Debug\example_app_graphics.exe" "deploy\win-apps\"
copy "win_build\Build\x64\Debug\example_app.exe" "deploy\win-apps\"
copy "win_build\Build\x64\Debug\worker.exe" "deploy\win-apps\"
copy "win_build\Build\x64\Debug\sleeper.exe" "deploy\win-apps\"
cd deploy\win-apps
7z a win-apps_%pkg_version%.7z *.exe
cd ..\..

if not exist "deploy\win-client" mkdir deploy\win-client
copy "win_build\Build\x64\Debug\boinc.exe" "deploy\win-client\"
copy "win_build\Build\x64\Debug\boincsvcctrl.exe" "deploy\win-client\"
copy "win_build\Build\x64\Debug\boinccmd.exe" "deploy\win-client\"
copy "win_build\Build\x64\Debug\boincscr.exe" "deploy\win-client\"
copy "win_build\Build\x64\Debug\boinc.scr" "deploy\win-client\"
cd deploy\win-client
7z a win-client_%pkg_version%.7z *.exe *.scr
cd ..\..

if not exist "deploy\win-manager" mkdir deploy\win-manager
copy "win_build\Build\x64\Debug\boinctray.exe" "deploy\win-manager\"
copy "win_build\Build\x64\Debug\boincmgr.exe" "deploy\win-manager\"
cd deploy\win-manager
7z a win-manager_%pkg_version%.7z *.exe
cd ..\..
