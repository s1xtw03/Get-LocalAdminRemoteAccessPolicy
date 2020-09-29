<#
.SYNOPSIS
    This script analyzes group policy objects to detect and list all OUs in an AD Domain which permit elevated remote access to local administrator accounts.

.DESCRIPTION
    Having an understanding of which OUs are allowing remote access to local administrators helps identify gaps in organizational security policy. It can also be useful for penetration testing or attack simulation work, where local administrator or LAPS credentials have been compromised.
    Note that this script requires Microsoft RSAT modules if the GPOReport is not provided.
    For information on RSAT, see https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools

.EXAMPLE
    ./Get-RemoteAdminPermittedPermittedOUs.ps1
    If you're on a domain joined machine and authenticated with a domain account, no arguments are needed. 

.EXAMPLE
    ./Get-RemoteAdminPermittedPermittedOUs.ps1 -Domain "thedomain.com"
    Depending on the domain configuration, one may wish to specify a domain to analyze. 

.EXAMPLE
    ./Get-RemoteAdminPermittedPermittedOUs.ps1 -GPOReportFile "C:\Path\To\GPOReport.xml"
    If you have manually obtained the GPO Report and OU List, provide the file paths in this way. 

.PARAMETER Domain
    The name of the domain you wish to analyze.

.PARAMETER GPOReportFile
    The path to a file containing all GPOs for the domain you wish to analyze. 
    Should be generated via: Get-GPOReport -All -Domain "thedomain.com" -ReportType xml

.PARAMETER Verbose
    Print additional output as this script searches group policy objects.

.LINK 
    https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/

.LINK
    https://labs.f-secure.com/blog/enumerating-remote-access-policies-through-gpo/
#>
[CmdletBinding()]
param(
    [string] $Domain,
    [string] $GPOReportFile
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
$AllGPOManagedOUs = Select-Xml -XML $GPOXML -XPath "/report/gpns:GPO/gpns:LinksTo/gpns:SOMPath" -Namespace $XMLNameSpaces | Select-Object -Expand Node | Select-Object -Expand '#text'

$AllGPOManagedOUs = $AllGPOManagedOUs | Where-Object {$_ -match "/"}

$UHOHOUs = @()
$AnyNonDefaultsp = 0

#{"OU Name", [FAT, LUA, LATP]}, set to default
$OUs2Policy = @{}
ForEach ($OU in $AllGPOManagedOUs)
{
  $OUs2Policy[$OU] = @(0, 1, 0)
}

function RemoveChildOUs
{
  Param($OUs)

  $ToBeRemoved = @()
  ForEach ($OOU in $OUs)
  {
    $OUs | % {if ($OOU -ne $_) {if($_ -Match $OOU){$ToBeRemoved += $_}}}
  }

  $Parents = $OUs | % { if ($_ -notin $ToBeRemoved) {$_}}

  return $Parents
}

function FindImplicit
{
  Param($OUs, $Parents)

  $Implicits = ,$()
  ForEach ($OU in $OUs)
  {
    $Match = 0
    ForEach ($Parent in $Parents)
    {
      if ($OU -Match $Parent)
      {
        $Match = 1
      }
    }
    if ($Match -eq 0)
    {
      $Implicits += $OU
    }
  }

  return $Implicits
}

Write-Verbose "--Checking FilterAdministrationToken--"
ForEach($GPONode in $FilterAdministratorTokenNodes)
{
  "Explicit FilterAdministratorToken directive found in GPO named '" + $GPONode.Node.Name + "' with GUID " + $GPONode.Node.Identifier.Identifier.'#text' | Write-Verbose

  $SecurityOption = $GPONode.Node.Computer.ExtensionData.Extension.SecurityOptions | Where-Object {$_.KeyName -eq "$FATKey"}
  $FATSetting = $SecurityOption.SettingNumber

  $OUNodes = $GPONode.Node.LinksTo

  if($FATSetting -eq 0)
  {
    Write-Verbose "FilterAdministrationToken is not restricting remote session privileges, though, cause it's disabled by the policy. (This is the default setting)"
    #If its explicitly disabled, track by marking -1 and assume normal inheritance
    ForEach($OUNode in $OUNodes)
    {
      $OUs2Policy[$OUNode.SOMPath][0] = -1
    }
  }

  if($FATSetting -eq 1)
  {
    $AnyNonDefaultsp = 1
    Write-Verbose "FilterAdministrationToken is enabled, which restricts RID-500 Administrator from performing privileged actions via non-interactive remote sessions."

    ForEach($OUNode in $OUNodes)
    {
      if ($OUs2Policy[$OUNode.SOMPath][0] -ne -1)
      {
        $OUs2Policy[$OUNode.SOMPath][0] = 1
      }
    }
  }
}
Write-Verbose ""

Write-Verbose "--Checking EnableLUA--"
ForEach($GPONode in $EnableLUANodes)
{
  "Explicit EnableLUA directive found in GPO named '" + $GPONode.Node.Name + "' with GUID " + $GPONode.Node.Identifier.Identifier.'#text' | Write-Verbose

  $SecurityOption = $GPONode.Node.Computer.ExtensionData.Extension.SecurityOptions | Where-Object {$_.KeyName -eq "$EnableLUAKey"}
  $EnableLUASetting = $SecurityOption.SettingNumber

  $OUNodes = $GPONode.Node.LinksTo

  if($EnableLUASetting -eq 0)
  {
    $AnyNonDefaultsp = 1
    Write-Verbose "EnableLUA is disabled, which allows any local administrator (RID-500 and others) to perform privileged remote authentication."

    ForEach($OUNode in $OUNodes)
    {
      $OUs2Policy[$OUNode.SOMPath][1] = 0
    }
  }
  if($EnableLUASetting -eq 1)
  {
    #If its explicitly enabled, track by marking -1 and assume normal inheritance
    ForEach($OUNode in $OUNodes)
    {
      $OUs2Policy[$OUNode.SOMPath][1] = -1
    }
    Write-Verbose "EnableLUA is enabled, meaning the system relies on the policy set by FilterAdministrationToken and LocalAccountTokenFilterPolicy. (This is the default setting)"
  }
} 
Write-Verbose ""

Write-Verbose "--Checking LocalAccountTokenFilterPolicy--"
ForEach($GPONode in $LocalAccountTokenFilterPolicyNodes)
{
  "Explicit LocalAccountTokenFilterPolicy directive found in GPO named '" + $GPONode.Node.Name + "' with GUID " + $GPONode.Node.Identifier.Identifier.'#text' | Write-Verbose

  $RegistryProperty = $GPONode.Node.Computer.ExtensionData.Extension.RegistrySettings.Registry.Properties | Where-Object {$_.Name -eq "LocalAccountTokenFilterPolicy"}
  $RegistryValue = $RegistryProperty.Value

  if ($RegistryValue -eq "00000000")
  {
    Write-Verbose "LocalAccountTokenFilterPolicy is disabled, meaning that non-RID-500 administrators remote sessions are properly filtered. (This is the default setting)"
    #If its explicitly disabled, track by marking -1 and assume normal inheritance
    ForEach($OUNode in $OUNodes)
    {
      $OUs2Policy[$OUNode.SOMPath][2] = -1
    }
  }
  if ($RegistryValue -eq "00000001")
  {
    $AnyNonDefaultsp = 1
    Write-Verbose "LocalAccountTokenFilterPolicy is enabled, meaning that non-RID-500 administrators remote sessions are given elevated privileges."

    ForEach($OUNode in $OUNodes)
    {
      $OUs2Policy[$OUNode.SOMPath][2] = 1
    }
  }
}

if($AnyNonDefaultsp -eq 0)
{
  Write-Output "All OUs managed by GPO are using the default policies for remote authentication. This indicates the RID 500 administrator can authenticate remotely and obtain a privileged session, while other local administrators cannot obtain a privileged session. Non-RID-500 administrators can likely still take administrative action via RDP, however."
  Exit
}

Write-Verbose "--Analyzing FilterAdministrationToken--"
$FATEnabled = $AllGPOManagedOUs | Where-Object {$OUs2Policy[$_][0] -eq 1} | Sort-Object | Get-Unique
$FATParents = RemoveChildOUs($FATEnabled)
$FATExplicitlyDisabled = $AllGPOManagedOUs | Where-Object {$OUs2Policy[$_][0] -eq -1} | Sort-Object | Get-Unique
$FATImplicitlyDisabled = $AllGPOManagedOUs | Where-Object {$OUs2Policy[$_][0] -eq 0} | Sort-Object | Get-Unique


if ($FATEnabled.Count -gt 0)
{
  Write-Output "FilterAdministrationToken is enabled for the following OUs and inherited by their children:"
  $FATParents | Write-Output 
  Write-Output ""
}

if ($FATExplicitlyDisabled.Count -gt 0)
{
  Write-Output "FilterAdministrationToken is explicitly disabled for the following OUs, which likely bypasses any inherited restrictions:"
  $FATExplicitlyDisabled | Write-Output 
  Write-Output ""
}

if ($FATImplicitlyDisabled.Count -gt 0)
{
  Write-Output "FilterAdministrationToken is implicitly disabled for the following OUs. OUs which are likely restricted by inheritance have been removed."
  FindImplicit $FATImplicitlyDisabled $FATParents  | Write-Output
  Write-Output ""
}

Write-Verbose "--Analyzing EnableLUA--"
$LUAExplicitlyDisabled = $AllGPOManagedOUs | Where-Object {$OUs2Policy[$_][1] -eq 0} | Sort-Object | Get-Unique

if ($LUAExplicitlyDisabled.Count -gt 0)
{
  Write-Output "EnableLUA is explicitly disabled for the following OU:"
  $LUAExplicitlyDisabled | Write-Output 
  Write-Output ""
}
else {
  Write-Output "EnableLUA is set to the default value for all OUs, which indicates that OUs are following the policy set by FilterAdministrationToken and LocalAccountTokenFilterPolicy."
}

Write-Verbose "--Analyzing LocalAccountTokenFilterPolicy--"
$LATFPEnabled = $AllGPOManagedOUs | Where-Object {$OUs2Policy[$_][2] -eq 1} | Sort-Object | Get-Unique

if ($LATFPEnabled.Count -gt 0)
{
  Write-Output "LocalAccountTokenFilterPolicy is enabled for the following OUs:"
  $LATFPEnabled | Write-Output
  Write-Output ""
}
else {
  Write-Output "LocalAccountTokenFilterPolicy is set to the default value for all OUs."
}
