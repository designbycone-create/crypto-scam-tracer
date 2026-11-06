# ScamHunter Desk - one-line Windows installer (free for victims).
#   irm https://raw.githubusercontent.com/designbycone-create/crypto-scam-tracer/stable/install.ps1 | iex
# Installs to %USERPROFILE%\ScamHunter, adds Start Menu / Desktop / startup shortcuts,
# then opens the setup page in your browser. No admin rights needed.
$ErrorActionPreference = 'Stop'
$Dir  = Join-Path $env:USERPROFILE 'ScamHunter'
$Zip  = Join-Path $env:TEMP 'scamhunter.zip'
$Repo = 'https://github.com/designbycone-create/crypto-scam-tracer/archive/refs/heads/stable.zip'   # signed releases only
Write-Host "`nScamHunter Desk installer" -ForegroundColor Cyan
Write-Host "Free for victims. It will never ask for money or a seed phrase.`n"

# 1. Python 3.9+
function Find-Python {
  foreach ($c in @('py -3', 'python')) {
    try { $v = & ([scriptblock]::Create("$c -c `"import sys;print(sys.version_info[:2]>=(3,9))`"")) 2>$null
          if ($v -match 'True') { return $c } } catch {}
  }
  return $null
}
$py = Find-Python
if (-not $py) {
  Write-Host "Python not found - installing Python 3.12 (one time)..." -ForegroundColor Yellow
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements | Out-Null
    $env:Path = [Environment]::GetEnvironmentVariable('Path','User') + ';' + [Environment]::GetEnvironmentVariable('Path','Machine')
    $py = Find-Python
  }
  if (-not $py) { Write-Host "Please install Python from https://www.python.org/downloads/ (tick 'Add to PATH'), then run this again." -ForegroundColor Red; return }
}
Write-Host "Python OK ($py)"

# 2. Download / update (keeps your case files). Pin the exact version so the Desk's Updates page knows what's installed.
$sha = $null
try { $sha = (Invoke-RestMethod 'https://api.github.com/repos/designbycone-create/crypto-scam-tracer/commits/stable' -TimeoutSec 20).sha } catch {}
if ($sha) { $Repo = "https://github.com/designbycone-create/crypto-scam-tracer/archive/$sha.zip" }
Invoke-WebRequest $Repo -OutFile $Zip -UseBasicParsing
$tmp = Join-Path $env:TEMP 'scamhunter_x'; Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive $Zip $tmp -Force
New-Item -ItemType Directory $Dir -Force | Out-Null
Copy-Item (Join-Path (Get-ChildItem $tmp)[0].FullName '*') $Dir -Recurse -Force
if ($sha) { Set-Content -Path (Join-Path $Dir 'VERSION') -Value $sha -NoNewline }
Write-Host "Installed to $Dir"

# 3. Dependencies
& ([scriptblock]::Create("$py -m pip install --user -q -r `"$Dir\requirements.txt`""))
Write-Host "Dependencies OK"

# 4. Shortcuts: Start Menu + Desktop open the Desk; Startup runs it quietly at sign-in
$ws = New-Object -ComObject WScript.Shell
$cmd = Join-Path $Dir 'run_desk.cmd'
$startup = Join-Path ([Environment]::GetFolderPath('Startup')) 'ScamHunter Desk.lnk'
$vbs = Join-Path $Dir 'run_desk_hidden.vbs'
$l = $ws.CreateShortcut($startup); $l.TargetPath = "$env:WINDIR\System32\wscript.exe"; $l.Arguments = "`"$vbs`""; $l.WorkingDirectory = $Dir; $l.Save()
$open = Join-Path $Dir 'open_desk.vbs'      # starts the Desk if it's down, then opens the dashboard
foreach ($p in @([Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('Desktop'))) {
  Remove-Item (Join-Path $p 'ScamHunter Desk.url') -ErrorAction SilentlyContinue   # older installs: link that only opened the page
  $s = $ws.CreateShortcut((Join-Path $p 'ScamHunter Desk.lnk'))
  $s.TargetPath = "$env:WINDIR\System32\wscript.exe"; $s.Arguments = "`"$open`""; $s.WorkingDirectory = $Dir
  $s.IconLocation = "$env:WINDIR\System32\shell32.dll,47"; $s.Description = 'Open ScamHunter Desk (starts it if needed)'
  $s.Save()
}
Write-Host "Shortcuts created (Desktop + Start Menu; starts automatically when you sign in)"

# 5. Launch -> browser opens the setup page
Start-Process "$env:WINDIR\System32\wscript.exe" -ArgumentList "`"$vbs`"" -WorkingDirectory $Dir
Start-Sleep 4
Start-Process 'http://127.0.0.1:8787/'
Write-Host "`nDone. Your browser is opening the setup page." -ForegroundColor Green
