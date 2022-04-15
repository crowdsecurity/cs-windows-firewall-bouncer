
Set-Location .\Chocolatey\crowdsec-windows-firewall-bouncer
Copy-Item ..\..\cs-windows-firewall-bouncer-setup\bin\x64\Release\cs_windows_firewall_bouncer_setup.msi tools\cs_windows_firewall_bouncer_setup.msi

choco pack