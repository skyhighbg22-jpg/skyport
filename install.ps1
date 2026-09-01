$ErrorActionPreference = "Stop"
$Repo = "skyhighbg22-jpg/skyport"
$Version = if ($env:VERSION) { $env:VERSION } else { "latest" }
if ($Version -eq "latest") {
  $BaseUrl = "https://github.com/$Repo/releases/latest/download"
} else {
  $BaseUrl = "https://github.com/$Repo/releases/download/v$Version"
}
$Asset = "skyport-x86_64-pc-windows-msvc.exe"
$Url = "$BaseUrl/$Asset"
$InstallDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { "$env:USERPROFILE\.local\bin" }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Dest = Join-Path $InstallDir "skyport.exe"
$Temp = Join-Path $InstallDir ".skyport-$([Guid]::NewGuid().ToString('N')).tmp"
$Checksums = "$Temp.SHA256SUMS"
try {
  Write-Host "Downloading $Url ..."
  Invoke-WebRequest -Uri $Url -OutFile $Temp -UseBasicParsing
  Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS" -OutFile $Checksums -UseBasicParsing
  $Pattern = "\s\*?$([Regex]::Escape($Asset))$"
  $ChecksumLine = Get-Content -LiteralPath $Checksums | Where-Object { $_ -match $Pattern } | Select-Object -First 1
  if (-not $ChecksumLine) { throw "No SHA-256 checksum published for $Asset" }
  $Expected = ($ChecksumLine.Trim() -split "\s+")[0].ToLowerInvariant()
  $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Temp).Hash.ToLowerInvariant()
  if ($Actual -ne $Expected) { throw "SHA-256 verification failed for $Asset" }
  Write-Host "Verified SHA-256 checksum"
  Move-Item -LiteralPath $Temp -Destination $Dest -Force
} finally {
  Remove-Item -LiteralPath $Temp -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $Checksums -Force -ErrorAction SilentlyContinue
}
Write-Host "Installed to $Dest"
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
  Write-Host "Added $InstallDir to user PATH (restart terminal)"
}
& $Dest --version
