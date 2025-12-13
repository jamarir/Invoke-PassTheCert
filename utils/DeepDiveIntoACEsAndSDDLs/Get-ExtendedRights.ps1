<#
    .SYNOPSIS

        Returns all Active Directory Extended Rights (Names, DistinguishedNames, and rightsGuids).
    If this script times out, then it might be runable from the DC only

    .EXAMPLE

        .\Get-ExtendedRights.ps1 -Server 192.168.56.202 -Domain 'JAMAD.LOCAL' -Username 'Administrator' -Password 'P@ssw0rd123!'

    .LINK

        https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries (ACEs)

    .LINK

        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb (ObjectAceTypes)

#>

[Cmdletbinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$Server,
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [Parameter(Mandatory = $true)]
    [string]$Username,
    [Parameter(Mandatory = $true)]
    [string]$Password
) 

$c = New-Object System.Management.Automation.PSCredential("$Domain\$Username",(ConvertTo-SecureString "$Password" -AsPlainText -Force));

try {

    # Alternative 1
    Get-ADObject -Server $Server -Credential $c -Properties * -LDAPFilter "(objectClass=controlAccessRight)" -SearchBase "$((Get-ADRootDSE -Server $Server -Credential $c).ConfigurationNamingContext)" |Select-Object Name,DistinguishedName,rightsGuid;

    # Alternative 2
    #Get-ADObject -Server $Server -Credential $c -Properties * -Filter * -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE -Server $Server -Credential $c).ConfigurationNamingContext)" | ? {
    #    $_.objectclass -like 'controlAccessRight'
    #} |Select-Object Name,DistinguishedName,rightsGuid;

    # Alternative 3
    #Get-ADObject -Server $Server -Credential $c -Properties * -LDAPFilter '(objectClass=controlAccessRight)' -SearchBase "$((Get-ADRootDSE -Server $Server -Credential $c).ConfigurationNamingContext)" |Select-Object Name,DistinguishedName,rightsGuid;

} catch { Write-Error "[!] $_" }