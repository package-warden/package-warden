@echo off
setlocal EnableDelayedExpansion

:: ---------------------------------------------------------------------------
:: Package Warden -- Package Manager Setup
::
:: Configures your package managers to route through Package Warden proxy.
:: Run this script after starting Package Warden.
::
:: Usage:
::   setup-package-managers.bat          -- configure all available
::   setup-package-managers.bat --undo   -- restore original settings
::
:: Environment variables:
::   PW_PORT   Port Package Warden is listening on (default: 5050)
::
:: Package managers configured:
::   npm, pip, dotnet/NuGet, cargo, go modules, bundler
:: ---------------------------------------------------------------------------

if not defined PW_PORT set "PW_PORT=5050"
set "BASE=http://localhost:%PW_PORT%"
set "UNDO=false"
set "COUNT_OK=0"
set "COUNT_SKIP=0"

if /i "%~1"=="--undo" set "UNDO=true"
if /i "%~1"=="/undo"  set "UNDO=true"

if "!UNDO!"=="true" (
    echo Removing Package Warden proxy settings from package managers...
) else (
    echo Configuring package managers to use Package Warden at %BASE% ...
)
echo.


:: ===========================================================================
:: npm
:: ===========================================================================

where npm >nul 2>&1
if %errorlevel% equ 0 (
    if "!UNDO!"=="true" (
        npm config delete registry >nul 2>&1
        echo   [+] npm -- registry restored to default
        set /a COUNT_OK+=1
    ) else (
        npm config set registry %BASE%/v1/proxy/npm
        echo   [+] npm -- registry ^> %BASE%/v1/proxy/npm
        set /a COUNT_OK+=1
    )
) else (
    echo   [-] npm -- not installed
    set /a COUNT_SKIP+=1
)


:: ===========================================================================
:: pip
:: ===========================================================================

set "PIP_FOUND=false"
where pip  >nul 2>&1 && set "PIP_FOUND=true"
where pip3 >nul 2>&1 && set "PIP_FOUND=true"

if "!PIP_FOUND!"=="true" (
    set "PIP_CONF=%APPDATA%\pip\pip.ini"
    set "PIP_URL=%BASE%/v1/proxy/pypi/simple/"

    if "!UNDO!"=="true" (
        if exist "!PIP_CONF!" (
            set "TEMP_PS1=%TEMP%\pw-pip-%RANDOM%.ps1"
            (
                echo $conf = '!PIP_CONF!'
                echo $url  = '!PIP_URL!'
                echo if ^(Test-Path $conf^) {
                echo     $c = Get-Content $conf -Raw
                echo     if ^($c -match [regex]::Escape^($url^)^) {
                echo         $c = $c -replace "(?m)^index-url.*\r?\n", ""
                echo         Set-Content $conf $c
                echo         Write-Host "  [+] pip -- index-url removed"
                echo     } else {
                echo         Write-Host "  [-] pip -- not configured (nothing to undo)"
                echo     }
                echo } else {
                echo     Write-Host "  [-] pip -- not configured (nothing to undo)"
                echo }
            ) > "!TEMP_PS1!"
            powershell -NoProfile -ExecutionPolicy Bypass -File "!TEMP_PS1!"
            del "!TEMP_PS1!" >nul 2>&1
        ) else (
            echo   [-] pip -- not configured (nothing to undo^)
            set /a COUNT_SKIP+=1
        )
    ) else (
        if not exist "%APPDATA%\pip" mkdir "%APPDATA%\pip"
        set "TEMP_PS1=%TEMP%\pw-pip-%RANDOM%.ps1"
        (
            echo $conf = '!PIP_CONF!'
            echo $url  = '!PIP_URL!'
            echo $line = "index-url = $url"
            echo if ^(Test-Path $conf^) {
            echo     $c = Get-Content $conf -Raw
            echo     if ^($c -match "(?m)^index-url"^) {
            echo         $c = $c -replace "(?m)^index-url.*$", $line
            echo         Set-Content $conf $c
            echo     } else {
            echo         if ^($c -notmatch "(?m)^\[global\]"^) { Add-Content $conf "`n[global]" }
            echo         Add-Content $conf $line
            echo     }
            echo } else {
            echo     Set-Content $conf "[global]`n$line"
            echo }
        ) > "!TEMP_PS1!"
        powershell -NoProfile -ExecutionPolicy Bypass -File "!TEMP_PS1!"
        del "!TEMP_PS1!" >nul 2>&1
        echo   [+] pip -- index-url ^> !PIP_URL!
        echo       config: !PIP_CONF!
        set /a COUNT_OK+=1
    )
) else (
    echo   [-] pip -- not installed
    set /a COUNT_SKIP+=1
)


:: ===========================================================================
:: dotnet / NuGet
:: ===========================================================================

where dotnet >nul 2>&1
if %errorlevel% equ 0 (
    set "NUGET_URL=%BASE%/v1/proxy/nuget/v3/index.json"
    if "!UNDO!"=="true" (
        dotnet nuget remove source package-warden >nul 2>&1
        dotnet nuget enable source nuget.org      >nul 2>&1
        echo   [+] dotnet/NuGet -- package-warden source removed, nuget.org re-enabled
        set /a COUNT_OK+=1
    ) else (
        dotnet nuget remove source package-warden >nul 2>&1
        dotnet nuget add source "!NUGET_URL!" --name package-warden >nul 2>&1
        dotnet nuget disable source nuget.org >nul 2>&1
        echo   [+] dotnet/NuGet -- source ^> !NUGET_URL!
        echo       (nuget.org disabled^)
        set /a COUNT_OK+=1
    )
) else (
    echo   [-] dotnet/NuGet -- not installed
    set /a COUNT_SKIP+=1
)


:: ===========================================================================
:: Cargo
:: ===========================================================================

where cargo >nul 2>&1
if %errorlevel% equ 0 (
    set "CARGO_CONF=%USERPROFILE%\.cargo\config.toml"
    set "CARGO_URL=sparse+%BASE%/v1/proxy/cargo/"

    if "!UNDO!"=="true" (
        set "TEMP_PS1=%TEMP%\pw-cargo-%RANDOM%.ps1"
        (
            echo $f = '!CARGO_CONF!'
            echo if ^(Test-Path $f^) {
            echo     $c = Get-Content $f -Raw
            echo     $c = $c -replace '(?s)# --- package-warden:cargo start ---.*?# --- package-warden:cargo end ---\r?\n?', ''
            echo     Set-Content $f $c
            echo     Write-Host "  [+] cargo -- config.toml restored"
            echo } else {
            echo     Write-Host "  [-] cargo -- not configured (nothing to undo)"
            echo }
        ) > "!TEMP_PS1!"
        powershell -NoProfile -ExecutionPolicy Bypass -File "!TEMP_PS1!"
        del "!TEMP_PS1!" >nul 2>&1
    ) else (
        if not exist "%USERPROFILE%\.cargo" mkdir "%USERPROFILE%\.cargo"
        set "TEMP_PS1=%TEMP%\pw-cargo-%RANDOM%.ps1"
        (
            echo $f   = '!CARGO_CONF!'
            echo $url = '!CARGO_URL!'
            echo $block = "`n# --- package-warden:cargo start ---`n[source.crates-io]`nreplace-with = `"package-warden`"`n`n[source.package-warden]`nregistry = `"$url`"`n# --- package-warden:cargo end ---`n"
            echo if ^(Test-Path $f^) {
            echo     $c = Get-Content $f -Raw
            echo     $c = $c -replace '(?s)# --- package-warden:cargo start ---.*?# --- package-warden:cargo end ---\r?\n?', ''
            echo     Set-Content $f ($c + $block)
            echo } else {
            echo     Set-Content $f $block
            echo }
        ) > "!TEMP_PS1!"
        powershell -NoProfile -ExecutionPolicy Bypass -File "!TEMP_PS1!"
        del "!TEMP_PS1!" >nul 2>&1
        echo   [+] cargo -- registry ^> !CARGO_URL!
        echo       config: !CARGO_CONF!
        set /a COUNT_OK+=1
    )
) else (
    echo   [-] cargo -- not installed
    set /a COUNT_SKIP+=1
)


:: ===========================================================================
:: Go modules
:: ===========================================================================

where go >nul 2>&1
if %errorlevel% equ 0 (
    set "GOPROXY_VAL=%BASE%/v1/proxy/golang,direct"
    if "!UNDO!"=="true" (
        setx GOPROXY "" >nul 2>&1
        set "GOPROXY="
        echo   [+] go -- GOPROXY cleared (open a new terminal for this to take effect^)
        set /a COUNT_OK+=1
    ) else (
        setx GOPROXY "!GOPROXY_VAL!" >nul 2>&1
        set "GOPROXY=!GOPROXY_VAL!"
        echo   [+] go -- GOPROXY ^> !GOPROXY_VAL!
        echo       (open a new terminal for this to take effect^)
        set /a COUNT_OK+=1
    )
) else (
    echo   [-] go -- not installed
    set /a COUNT_SKIP+=1
)


:: ===========================================================================
:: Bundler / RubyGems
:: ===========================================================================

where bundle >nul 2>&1
if %errorlevel% equ 0 (
    if "!UNDO!"=="true" (
        bundle config --delete "mirror.https://rubygems.org" >nul 2>&1
        echo   [+] bundler -- mirror removed
        set /a COUNT_OK+=1
    ) else (
        bundle config set "mirror.https://rubygems.org" "%BASE%/v1/proxy/gem"
        echo   [+] bundler -- mirror ^> %BASE%/v1/proxy/gem
        set /a COUNT_OK+=1
    )
) else (
    echo   [-] bundler -- not installed
    set /a COUNT_SKIP+=1
)


:: ===========================================================================
:: Maven (instructions only)
:: ===========================================================================

where mvn >nul 2>&1
if %errorlevel% equ 0 (
    echo.
    if "!UNDO!"=="true" (
        echo   Maven: remove the following mirror from %%USERPROFILE%%\.m2\settings.xml:
    ) else (
        echo   Maven: add the following mirror to %%USERPROFILE%%\.m2\settings.xml:
    )
    echo     ^<mirrors^>
    echo       ^<mirror^>
    echo         ^<id^>package-warden^</id^>
    echo         ^<mirrorOf^>central^</mirrorOf^>
    echo         ^<url^>%BASE%/v1/proxy/maven^</url^>
    echo       ^</mirror^>
    echo     ^</mirrors^>
)


:: ===========================================================================
:: Summary
:: ===========================================================================

echo.
echo Done -- configured: !COUNT_OK!, skipped (not installed): !COUNT_SKIP!

if not "!UNDO!"=="true" (
    echo.
    echo Start Package Warden: package-warden.bat
    echo Dashboard:            %BASE%/ui
)

endlocal
