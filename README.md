# Get-RemoteAdminPermittedOUs
This script analyzes group policy objects to detect and list all OUs in an AD Domain which permit remote access to local administrator accounts.

Having an understanding of which OUs are allowing remote access to local administrators helps identify gaps in organizational security policy. It can also be useful for penetration testing or attack simulation work, where local administrator or LAPS credentials have been compromised.
Note that this script requires [Microsoft RSAT](https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools) modules if GPOReport and OU list files are not provided.

Under construction! Targeting end of September delivery, if not earlier.