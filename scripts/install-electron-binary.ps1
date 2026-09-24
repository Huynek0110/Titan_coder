$ErrorActionPreference = 'Stop'
$version = (& node -p "require('./node_modules/electron/package.json').version").Trim()
$cacheDir = Join-Path $env:TEMP 'codepilot-electron-download'
$zipPath = Join-Path $cacheDir "electron-v$version-win32-x64.zip"
$dist = Join-Path (Get-Location) 'node_modules\electron\dist'
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
if (!(Test-Path -LiteralPath $zipPath)) {
  $url = "https://github.com/electron/electron/releases/download/v$version/electron-v$version-win32-x64.zip"
  & curl.exe --fail --location --retry 2 --connect-timeout 20 --max-time 600 --output $zipPath $url
  if ($LASTEXITCODE -ne 0) { throw "Electron download failed with exit code $LASTEXITCODE" }
}
if (Test-Path -LiteralPath $dist) { Remove-Item -LiteralPath $dist -Recurse -Force }
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Expand-Archive -LiteralPath $zipPath -DestinationPath $dist -Force
Set-Content -LiteralPath (Join-Path (Get-Location) 'node_modules\electron\path.txt') -Value 'electron.exe' -NoNewline
Set-Content -LiteralPath (Join-Path (Get-Location) 'node_modules\electron\dist\version') -Value $version -NoNewline
$exe = Join-Path $dist 'electron.exe'
if (!(Test-Path -LiteralPath $exe)) { throw 'Electron executable is missing after extraction.' }
Write-Output "Electron binary installed: $exe"
