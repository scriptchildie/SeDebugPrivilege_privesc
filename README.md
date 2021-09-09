# SeDebugPrivilege_privesc
Privilege escalation by abusing the SeDebugPrivilege


The code is split into two functions.

1. Set_Privilege enables or disables any available privilege to the user.

Usage:
Set_Privilege SeTimeZonePrivilege disable
Set_Privilege SeTimeZonePrivilege enable

2. debug_priv_esc function (taken from: https://github.com/decoder-it/psgetsystem  / https://decoder.cloud/2018/02/02/getting-system/)

Usage: 
Change the IP & Port address in the $ReverseShellScriptBlock. 
Modify the $PID_Debug to a PID of a process that runs as NT Auth. (Following command will give you a list in powershell.)
Get-Process -IncludeUserName
Lastly, debug_priv_esc should do the trick






