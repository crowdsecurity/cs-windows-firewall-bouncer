$ErrorActionPreference = 'Stop';
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$fileLocation = Join-Path $toolsDir 'cs_windows_firewall_bouncer_setup.msi'

$packageArgs = @{
  packageName   = $env:ChocolateyPackageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  file64         = $fileLocation
  softwareName  = 'Crowdsec Windows Firewall Bouncer*'
  checksum64    = ''
  checksumType64= 'sha256'
  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyInstallPackage @packageArgs

if (-not(Test-Path -Path "C:\Program Files\CrowdSec\cscli.exe" -PathType Leaf)) {
  Write-Host "cscli.exe was not found, please manually register the bouncer with your CrowdSec installation, update C:\Program Files\CrowdSec\bouncers\cs-windows-firewall-bouncer\cs-windows-firewall-bouncer.yaml and configure the service to start on boot."
}
