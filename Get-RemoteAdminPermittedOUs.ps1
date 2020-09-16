<#
.SYNOPSIS
    This script analyzes group policy objects to detect and list all OUs in an AD Domain which permit remote access to local administrator accounts.

.DESCRIPTION
    Having an understanding of which OUs are allowing remote access to local administrators helps identify gaps in organizational security policy. It can also be useful for penetration testing or attack simulation work, where local administrator or LAPS credentials have been compromised.
    Note that this script requires Microsoft RSAT modules if GPOReport and OU list files are not provided.
    For information on RSAT, see https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools

.EXAMPLE
    ./Get-RemoteAdminPermittedPermittedOUs.ps1
    If you're on a domain joined machine and authenticated with a domain account, no arguments are needed. 

.EXAMPLE
    ./Get-RemoteAdminPermittedPermittedOUs.ps1 -Domain "thedomain.com"
    Depending on the domain configuration, one may wish to specify a domain to analyze. 

.EXAMPLE
    ./Get-RemoteAdminPermittedPermittedOUs.ps1 -GPOReportFile "C:\Path\To\GPOReport.xml" -OUListFile "C:\Path\To\OUList.txt"
    If you have manually obtained the GPO Report and OU List, provide the file paths in this way. 

.PARAMETER Domain
    The name of the domain you wish to analyze.

.PARAMETER GPOReportFile
    The path to a file containing all GPOs for the domain you wish to analyze. 
    Should be generated via: Get-GPOReport -All -Domain "thedomain.com" -ReportType xml

.PARAMETER OUListFile
    The path to a file containing all GPOs for the domain you wish to analyze. 
    Should be generated via: Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Select -ExpandProperty DistinguishedName

.LINK 
    https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/

.LINK
    https://labs.f-secure.com/blog/enumerating-remote-access-policies-through-gpo/
#>
[CmdletBinding()]
param(
    [string] $Domain,
    [string] $GPOReportFile,
    [string] $OUListFile
)

#Retrieve the GPO Report, by file path or dynamically via RSAT
[xml]$GPOXML = ""
if($GPOReportFile)
{
  try {
    [xml]$GPOXML = Get-Content -Path $GPOReportFile
  }
  catch [System.Exception]
  {
    throw "Could not read GPOReportFile at path $GPOReportFile"
  }
}
else {
  if($Domain){
    try {
      [xml]$GPOXML = Get-GPOReport -All -Domain $Domain -ReportType xml
    }
    catch [System.Exception]
    {
      throw "Could not obtain GPO Report for $Domain. Perhaps RSAT is not installed, or you cannot connect to the domain controller."
    }
  }
  else {
    try {
      [xml]$GPOXML = Get-GPOReport -All -ReportType xml
    }
    catch [System.Exception]
    {
      throw "Could not obtain GPO Report. Perhaps RSAT is not installed, or you cannot connect to the domain controller."
    }
  }
}

#Retrieve complete list of OUs in domain, by file path or dynamically via RSAT
$OUList = ""
if($OUListFile)
{
  try {
    $OUList = Get-Content -Path $OUListFile
  }
  catch [System.Exception]
  {
    throw "Could not read OUListFile at path $OUListFile"
  }
}
else {
  try {
    $OUList = Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Select -ExpandProperty DistinguishedName
  }
  catch [System.Exception]
  {
    throw "Could not obtain list of OUs from domain. Perhaps RSAT is not installed, or you cannot connect to the domain controller."
  }
}


$XMLNameSpaces = @{gpns="http://www.microsoft.com/GroupPolicy/Settings"; 
                     q1="http://www.microsoft.com/GroupPolicy/Settings/Security";
                     q2="http://www.microsoft.com/GroupPolicy/Settings/Windows/Registry"}

#Get the XML nodes associated with GPOs that have remote access policy directives
$FATKey = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken"
$FATXPath = "/report/gpns:GPO[gpns:Computer/gpns:ExtensionData/gpns:Extension/q1:SecurityOptions/q1:KeyName[text()='$FATKey']]"
$FilterAdministratorTokenNodes = Select-Xml -Xml $GPOXML -XPath $FATXPath -Namespace $XMLNameSpaces

$EnableLUAKey = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA"
$EnableLUAXPath = "/report/gpns:GPO[gpns:Computer/gpns:ExtensionData/gpns:Extension/q1:SecurityOptions/q1:KeyName[text()='$EnableLUAKey']]"
$EnableLUANodes = Select-Xml -Xml $GPOXML -XPath $EnableLUAXPath -Namespace $XMLNameSpaces

$LATPXPath = "/report/gpns:GPO[gpns:Computer/gpns:ExtensionData/gpns:Extension/q2:RegistrySettings/q2:Registry/q2:Properties[@name='LocalAccountTokenFilterPolicy']]"
$LocalAccountTokenFilterPolicyNodes = Select-Xml -Xml $GPOXML -XPath $LATPXPath -Namespace $XMLNameSpaces

#Get the XML nodes associated with OU names
$AllOUs = Select-Xml -Xml $GPOXML -XPath "/report/gpns:GPO/gpns:LinksTo/gpns:SOMPath" -Namespace $XMLNameSpaces

$SecuredOUs = @()
$UHOHOUs = @()

Write-Output "--Checking FilterAdministrationToken--"
ForEach($GPONode in $FilterAdministratorTokenNodes)
{
  "Explicit FilterAdministratorToken directive found in GPO named '" + $GPONode.Node.Name + "' with GUID " + $GPONode.Node.Identifier.Identifier.'#text' | Write-Output

  $SecurityOption = $GPONode.Node.Computer.ExtensionData.Extension.SecurityOptions | Where-Object {$_.KeyName -eq "$FATKey"}
  $FATSetting = $SecurityOption.SettingNumber

  $OUNodes = $GPONode.Node.LinksTo

  if($FATSetting -eq 0)
  {
      Write-Output "FilterAdministrationToken is not restricting remote login, though, cause it's disabled by the policy. (This is also the default setting)"

  }
  if($FATSetting -eq 1)
  {
      Write-Output "FilterAdministrationToken is enabled, which restricts RID-500 Administrator from performing privileged remote authentication (things run as medium-integrity)."
  }
}
Write-Output ""

Write-Output "--Checking EnableLUA--"
ForEach($GPONode in $EnableLUANodes)
{
  "Explicit EnableLUA directive found in GPO named '" + $GPONode.Node.Name + "' with GUID " + $GPONode.Node.Identifier.Identifier.'#text' | Write-Output

  $SecurityOption = $GPONode.Node.Computer.ExtensionData.Extension.SecurityOptions | Where-Object {$_.KeyName -eq "$EnableLUAKey"}
  $EnableLUASetting = $SecurityOption.SettingNumber

  $OUNodes = $GPONode.Node.LinksTo

  if($EnableLUASetting -eq 0)
  {
      Write-Output "EnableLUA is disabled, which allows any local administrator (RID-500 and others) to perform privileged remote authentication."

  }
  if($EnableLUASetting -eq 1)
  {
      Write-Output "EnableLUA is enabled, which restricts all non-RID-500 administrators from performing privileged remote authentication (things run as medium-integrity). (This is also the default setting)"
  }
} 
Write-Output ""

Write-Output "--Checking LocalAccountTokenFilterPolicy--"
Foreach($GPONode in $LocalAccountTokenFilterPolicyNodes)
{
  "Explicit LocalAccountTokenFilterPolicy directive found in GPO named '" + $GPONode.Node.Name + "' with GUID " + $GPONode.Node.Identifier.Identifier.'#text' | Write-Output

  $RegistryProperty = $GPONode.Node.Computer.ExtensionData.Extension.RegistrySettings.Registry | Where-Object {$_.KeyName -eq "LocalAccountTokenFilterPolicy"}
}
