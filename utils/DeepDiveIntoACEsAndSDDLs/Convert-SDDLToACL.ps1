

<#

    .Synopsis

        Convert SDDL (Security Descriptor Definition Language) String to ACL Object

    .DESCRIPTION

        Converts one or more SDDL Strings to a human readable format.

    .EXAMPLE

        .\Convert-SDDLToACL.ps1 -SDDLString (Get-Acl C:\Temp.txt).sddl

        Returns the ACL object associated with the provided SDDL string, e.g.:
            PS > .\Convert-SDDLToACL.ps1 -SDDLString (Get-Acl C:\Temp.txt).sddl
                FileSystemRights  : ReadAndExecute
                AccessControlType : Deny
                IdentityReference : Everyone
                IsInherited       : False
                InheritanceFlags  : None
                PropagationFlags  : None

                FileSystemRights  : Modify, Synchronize
                AccessControlType : Allow
                IdentityReference : NT AUTHORITY\Authenticated Users
                IsInherited       : False
                InheritanceFlags  : None
                PropagationFlags  : None

                FileSystemRights  : FullControl
                AccessControlType : Allow
                IdentityReference : PC\Administrator
                IsInherited       : False
                InheritanceFlags  : None
                PropagationFlags  : None

            PS > (Get-Acl C:\Temp.txt).sddl
                O:<Owner_SID>G:<Administrator_SID>D:PAI(D;;CCSWWPLORC;;;WD)(A;;0x1301bf;;;AU)(A;;FA;;;LA)


    .EXAMPLE

        .\Convert-SDDLToACL.ps1 -SDDLString 'O:BAD:(A;;RCSDWDWORPWPCCDCLCSWLODTCR;;;S-1-1-0)'

        Rturns the ACL object associated with the provided SDDL string (here, 'RCSDWDWORPWPCCDCLCSWLODTCR' applies on standard and directory service object access rights ONLY), i.e.
            FileSystemRights  : DeleteSubdirectoriesAndFiles, Modify, ChangePermissions, TakeOwnership
            AccessControlType : Allow
            IdentityReference : Everyone
            IsInherited       : False
            InheritanceFlags  : None
            PropagationFlags  : None


    .EXAMPLE

        .\Convert-SDDLToACL.ps1 -SDDLString 'O:BUD:(A;;FA;;;S-1-1-0)'

        Rturns the ACL object associated with the provided SDDL string (here, 'FA' applies for File access rights ONLY), i.e.
            FileSystemRights  : FullControl
            AccessControlType : Allow
            IdentityReference : Everyone
            IsInherited       : False
            InheritanceFlags  : None
            PropagationFlags  : None

    .NOTES
        Robert Amartinesei

    .LINK 

        https://poshscripter.wordpress.com/2017/04/27/sddl-conversion-with-powershell/

    .LINK

        https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language

    .LINK 
    
        https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings

#>

[Cmdletbinding()]
param (
    #One or more strings of SDDL syntax.
    [Parameter(Mandatory = $false)]
    [string[]]$SDDLString
) 

if (-not $SDDLString) {Get-Help -Examples ".\$($MyInvocation.MyCommand)"; return}

ForEach ($SDDL in $SDDLString) {
    $ACLObject = New-Object -TypeName System.Security.AccessControl.DirectorySecurity;
    $ACLObject.SetSecurityDescriptorSddlForm($SDDL);
    $ACLObject.Access;
}