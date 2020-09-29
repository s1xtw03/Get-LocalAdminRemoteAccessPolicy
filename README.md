# Get-LocalAdminRemoteAccessPolicy
This script analyzes group policy objects to detect and list OUs in an AD Domain which permit remote access to local administrator accounts.

Having an understanding of which OUs are allowing remote access to local administrators helps identify gaps in organizational security policy. It can also be useful for penetration testing or attack simulation work, where local administrator credentials have been compromised.

## The Policies
Default domain policy allows the RID-500 local administrator account to obtain a privileged, remote, non-interactive session with a username & password combination or by passing the hash. Other local administrators cannot obtain a privileged, remote, non-interactive session; they are limited to non-administrative rights. In this context, "non-interactive" refers to basically any remote access that is not RDP. 

There are three directives in Group Policy which affect remote privileges for local administrators:

* **FilterAdministratorToken**: If FilterAdministratorToken is enabled, even the RID-500 administrator is restricted from obtaining a privileged, remote, non-interactive session. It is disabled by default. 
* **EnableLUA**: If EnableLUA is enabled, UAC is enforced for administrative actions. If it is disabled, this effectively allows any local administrator to obtain a privileged, remote, non-interactive session. It is enabled by default. 
* **LocalAccountTokenFilterPolicy**: If LocalAccountTokenFilterPolicy is enabled, it effectively allows any local administrator to obtain a privileged, remote, non-interactive session. It is disabled by default.

## Example
This repository includes a sample GPO report for testing, which is intended to demonstrate the use of all three settings as well as traditional inheritance. 

The GPO is demonstrated graphically below:
<img src="https://raw.githubusercontent.com/s1xtw03/Get-LocalAdminRemoteAccessPolicy/master/windomain_GPOgraphic.png"/>

Running `Get-LocalAdminRemoteAccessPolicy.ps1` against this GPO returns the following output:

~~~
PS > Get-LocalAdminRemoteAccessPolicy.ps1 -GPOReportFile "s1xtw03/Get-LocalAdminRemoteAccessPolicy/Get-GPOReport_windomain.xml" 
FilterAdministrationToken is enabled for the following OUs and inherited by their children:
windomain.local/Admin

FilterAdministrationToken is explicitly disabled for the following OUs, which likely bypasses any inherited restrictions:
windomain.local/Admin/Tier 2/T2-Servers

FilterAdministrationToken is implicitly disabled for the following OUs. OUs which are likely restricted by inheritance have been removed.
windomain.local/Domain Controllers
windomain.local/Servers
windomain.local/Stage
windomain.local/Workstations

EnableLUA is explicitly disabled for the following OU:
windomain.local/Stage

LocalAccountTokenFilterPolicy is enabled for the following OUs:
windomain.local/Stage
~~~

## Other Notes
This script requires [Microsoft RSAT](https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools) modules if GPOReport and OU list files are not provided.

One shortcoming of this script is that it assumes default inheritance. In most configurations, child OUs can override the policy of a parent OU if they specify a different policy value. However, it is possible for a parent OU to enforce their configuration regardless of the child's policy directives. If this is the case, it would result in false positives returned by the script. 

## Thanks

* John Redford for holding my hand through the XPath queries & Dalton Wright for being part of the script's genesis
* [SomaFM](https://somafm.com/) for getting me through the last 15% with Groove Salad and Thistle Radio
* [harmj0y](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/), [William Knowles and Jon Cave](https://labs.f-secure.com/blog/enumerating-remote-access-policies-through-gpo/) for their blogs on the policy implications
* [DetectionLab](https://github.com/clong/DetectionLab) for an effortless test environment