# Enable System Audit Policy
auditpol /set /category:"System" /success:enable /failure:enable
 
# Enable Logon/Logoff Audit Policy
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
 
# Enable Object Access Audit Policy
auditpol /set /category:"Object Access" /success:enable /failure:enable
 
# Enable Privilege Use Audit Policy
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
 
# Enable Detailed Tracking Audit Policy
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
 
# Enable Policy Change Audit Policy
auditpol /set /category:"Policy Change" /success:enable /failure:enable
 
# Enable Account Management Audit Policy
auditpol /set /category:"Account Management" /success:enable /failure:enable
 
# Enable DS Access Audit Policy
auditpol /set /category:"DS Access" /success:enable /failure:enable
 
# Enable Account logon Audit Policy
auditpol /set /category:"Account logon" /success:enable /failure:enable
 
# Enable PowerShell Module Logging
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /t REG_DWORD /d 0x1 /f
 
# Configure PowerShell Module Logging
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames /v * /t REG_SZ /d * /f
 
# Enable PowerShell Script Block Logging
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 0x1 /f
 
# Enable Process Command-line details in Event ID 4688
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0x1 /f
 
# Force Group Policy Update
gpupdate /force
