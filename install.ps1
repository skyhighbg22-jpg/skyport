$ErrorActionPreference = "Stop"
$Repo = "skyhighbg22-jpg/skyport"
$Version = if ($env:VERSION) { $env:VERSION } else { "latest" }
if ($Version -eq "latest") {
  $Url = "https://github.com/$Repo/releases/latest/download/skyport-x86_64-pc-windows-msvc.exe"
} else {
  $Url = "https://github.com/$Repo/releases/download/v$Version/skyport-x86_64-pc-windows-msvc.exe"
}
$InstallDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { "$env:USERPROFILE\.local\bin" }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Dest = Join-Path $InstallDir "skyport.exe"
Write-Host "Downloading $Url ..."
Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
Write-Host "Installed to $Dest"
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
  Write-Host "Added $InstallDir to user PATH (restart terminal)"
}
& $Dest --version
