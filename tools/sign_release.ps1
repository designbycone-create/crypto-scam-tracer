# Sign one exact ScamHunter version with the maintainer key on THIS computer.
#   powershell -ExecutionPolicy Bypass -File tools\sign_release.ps1 -Sha <commit>
# Downloads that commit from GitHub, signs the extracted files with the private key in
# %USERPROFILE%\.scamhunter_signing (never uploaded), verifies the result, and leaves
# RELEASE.json + RELEASE.sig in .\signed\<sha>\ to be committed.
param([Parameter(Mandatory=$true)][string]$Sha, [string]$Note = "")
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Repo = 'designbycone-create/crypto-scam-tracer'
$key = Join-Path $env:USERPROFILE '.scamhunter_signing\ed25519_private.key'
if (-not (Test-Path $key)) { throw "No signing key at $key. Only the maintainer's computer can sign." }
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = 'py' }
$work = Join-Path $env:TEMP "sh_sign_$Sha"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $work | Out-Null
Invoke-WebRequest "https://github.com/$Repo/archive/$Sha.zip" -OutFile "$work\src.zip" -UseBasicParsing
Expand-Archive "$work\src.zip" "$work\x"
$src = (Get-ChildItem "$work\x")[0].FullName
if (-not $src.EndsWith($Sha)) { throw "Download didn't match commit $Sha" }
Remove-Item "$src\RELEASE.json", "$src\RELEASE.sig" -ErrorAction SilentlyContinue
& $py "$src\release_sig.py" sign $src $Note
& $py "$src\release_sig.py" verify $src
$out = Join-Path (Get-Location) "signed\$Sha"
New-Item -ItemType Directory $out -Force | Out-Null
Copy-Item "$src\RELEASE.json", "$src\RELEASE.sig" $out -Force
Write-Host "Signed release files are in $out" -ForegroundColor Green
