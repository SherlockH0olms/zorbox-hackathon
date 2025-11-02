# PowerShell (Run as Administrator)

# 1. UAC söndür
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0

# 2. Windows Defender söndür
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force

# 3. Windows Update söndür
Stop-Service -Name wuauserv -Force
Set-Service -Name wuauserv -StartupType Disabled

# 4. Firewall söndür
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# 5. Automatic login (ixtiyari)
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $RegPath -Name "AutoAdminLogon" -Value "1"
Set-ItemProperty -Path $RegPath -Name "DefaultUserName" -Value "Sandbox User"
Set-ItemProperty -Path $RegPath -Name "DefaultPassword" -Value "YourPassword"

# 6. Power settings
powercfg -change -monitor-timeout-ac 0
powercfg -change -disk-timeout-ac 0
powercfg -change -standby-timeout-ac 0

# Reboot
Restart-Computer
